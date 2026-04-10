"""Steam Web API client for authentication and authenticator operations."""

from __future__ import annotations

import base64
import json
import logging
import time
import uuid
from collections.abc import Callable
from typing import Any

import requests
import rsa

from steam_totp_extract.exceptions import (
    AuthenticationError,
    AuthenticatorError,
    SteamAPIError,
)
from steam_totp_extract.models import AuthenticatorData, SteamSession
from steam_totp_extract.totp import SteamTOTP

logger = logging.getLogger(__name__)

_API_BASE = "https://api.steampowered.com"
_MAX_FINALIZE_RETRIES = 10
_POLL_ATTEMPTS = 30
_POLL_INTERVAL_SECONDS = 2

# Steam API returns untyped JSON; Any is justified for third-party API data.
_JSONDict = dict[str, Any]

_CodeProvider = Callable[[str], str]
"""Callable that accepts a hint ('steam_guard', 'email', 'device_confirm')
and returns the user-supplied code (or empty string for device_confirm)."""


class SteamAPIClient:
    """Low-level HTTP client for Steam Web API calls."""

    def __init__(self) -> None:
        """Initialize with a requests session."""
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "SteamTOTPExtract/0.1"})

    def post(
        self,
        endpoint: str,
        data: dict[str, str] | None = None,
        access_token: str | None = None,
    ) -> _JSONDict:
        """Send a POST request to a Steam API endpoint.

        Args:
            endpoint: API path (e.g. 'ITwoFactorService/AddAuthenticator/v1').
            data: Form-encoded body parameters.
            access_token: OAuth access token appended as query parameter.

        Returns:
            Parsed JSON response.

        Raises:
            SteamAPIError: On HTTP or JSON parsing errors.
        """
        url = f"{_API_BASE}/{endpoint}"
        if access_token:
            url += f"?access_token={access_token}"

        logger.debug("POST %s", endpoint)
        try:
            resp = self._session.post(url, data=data or {}, timeout=30)
            resp.raise_for_status()
            return resp.json()  # type: ignore[no-any-return]
        except requests.RequestException as exc:
            raise SteamAPIError(f"HTTP request failed: {exc}") from exc

    def get(
        self,
        endpoint: str,
        params: dict[str, str] | None = None,
    ) -> _JSONDict:
        """Send a GET request to a Steam API endpoint.

        Args:
            endpoint: API path.
            params: Query string parameters.

        Returns:
            Parsed JSON response.

        Raises:
            SteamAPIError: On HTTP or JSON parsing errors.
        """
        logger.debug("GET %s", endpoint)
        try:
            resp = self._session.get(
                f"{_API_BASE}/{endpoint}", params=params or {}, timeout=30
            )
            resp.raise_for_status()
            return resp.json()  # type: ignore[no-any-return]
        except requests.RequestException as exc:
            raise SteamAPIError(f"HTTP request failed: {exc}") from exc


class SteamAuthenticator:
    """Orchestrates Steam login and authenticator setup/removal operations."""

    def __init__(self, client: SteamAPIClient | None = None) -> None:
        """Initialize with an optional API client.

        Args:
            client: SteamAPIClient instance. Created automatically if omitted.
        """
        self._client = client or SteamAPIClient()

    def login(
        self,
        username: str,
        password: str,
        code_provider: _CodeProvider | None = None,
    ) -> SteamSession:
        """Authenticate with Steam via IAuthenticationService.

        Args:
            username: Steam account name.
            password: Steam account password.
            code_provider: Callable that prompts for a 2FA code given a type hint.
                Defaults to stdin input.

        Returns:
            Authenticated session with access token.

        Raises:
            AuthenticationError: On login failure or timeout.
        """
        if not username:
            raise AuthenticationError("Username must not be empty")
        if not password:
            raise AuthenticationError("Password must not be empty")

        provider = code_provider or _default_code_provider

        pub_key, rsa_timestamp = self._get_rsa_key(username)
        encrypted_pw = self._encrypt_password(password, pub_key)

        session = self._begin_auth_session(username, encrypted_pw, rsa_timestamp)
        client_id = str(session.get("client_id", ""))
        request_id = str(session.get("request_id", ""))
        steamid = str(session.get("steamid", ""))

        if not client_id:
            raise AuthenticationError(
                f"Login failed: {json.dumps(session, indent=2)}",
                response=session,
            )

        self._submit_confirmation(session, client_id, steamid, provider)
        return self._poll_for_tokens(client_id, request_id, steamid, username)

    def remove_authenticator(self, access_token: str, revocation_code: str) -> bool:
        """Remove an existing authenticator using a revocation code.

        Args:
            access_token: OAuth access token from login.
            revocation_code: Revocation code (e.g. 'R12345').

        Returns:
            True if removal was confirmed by Steam.

        Raises:
            AuthenticatorError: On API failure.
        """
        if not revocation_code:
            raise AuthenticatorError("Revocation code must not be empty")

        logger.info("Removing existing authenticator")
        data = {
            "revocation_code": revocation_code,
            "revocation_reason": "1",
            "steamguard_scheme": "1",
        }
        resp = self._client.post(
            "ITwoFactorService/RemoveAuthenticator/v1",
            data,
            access_token=access_token,
        )
        inner: _JSONDict = resp.get("response", {})
        success = bool(inner.get("success", False))

        if not success:
            remaining = inner.get("revocation_attempts_remaining", "?")
            logger.warning("Removal may have failed. Attempts remaining: %s", remaining)
        else:
            logger.info("Existing authenticator removed")

        return success

    def add_authenticator(self, access_token: str, steamid: str) -> AuthenticatorData:
        """Register a new authenticator via ITwoFactorService.

        Args:
            access_token: OAuth access token from login.
            steamid: 64-bit Steam ID.

        Returns:
            AuthenticatorData containing the shared_secret and other secrets.

        Raises:
            AuthenticatorError: On API failure or unexpected status.
        """
        device_id = f"android:{uuid.uuid4()}"
        data = {
            "steamid": steamid,
            "authenticator_type": "1",
            "device_identifier": device_id,
            "sms_phone_id": "1",
            "version": "2",
        }

        logger.info("Adding new authenticator")
        resp = self._client.post(
            "ITwoFactorService/AddAuthenticator/v1", data, access_token=access_token
        )
        inner: _JSONDict = resp.get("response", {})
        status = inner.get("status", -1)

        if status == 2:
            raise AuthenticatorError(
                "No phone number on account. "
                "Add one at https://store.steampowered.com/phone/manage",
                response=inner,
            )
        if status == 29:
            raise AuthenticatorError(
                "Authenticator already present. Remove it first.",
                response=inner,
            )
        if status != 1:
            raise AuthenticatorError(
                f"AddAuthenticator failed with status {status}",
                response=inner,
            )

        logger.info("New authenticator registered")
        return AuthenticatorData(
            shared_secret=str(inner.get("shared_secret", "")),
            serial_number=str(inner.get("serial_number", "")),
            revocation_code=str(inner.get("revocation_code", "")),
            uri=str(inner.get("uri", "")),
            server_time=int(inner.get("server_time", 0)),
            account_name=str(inner.get("account_name", "")),
            token_gid=str(inner.get("token_gid", "")),
            identity_secret=str(inner.get("identity_secret", "")),
            secret_1=str(inner.get("secret_1", "")),
            status=int(status),
            device_id=device_id,
            raw=inner,
        )

    def finalize_authenticator(
        self,
        access_token: str,
        steamid: str,
        shared_secret_b64: str,
        sms_code: str,
    ) -> bool:
        """Finalize authenticator setup with an SMS verification code.

        Args:
            access_token: OAuth access token from login.
            steamid: 64-bit Steam ID.
            shared_secret_b64: Base64-encoded shared_secret from AddAuthenticator.
            sms_code: SMS code sent to the user's phone.

        Returns:
            True on successful finalization.

        Raises:
            AuthenticatorError: On bad SMS code, repeated failure, or API error.
        """
        if not sms_code:
            raise AuthenticatorError("SMS code must not be empty")

        logger.info("Finalizing authenticator setup")
        for attempt in range(1, _MAX_FINALIZE_RETRIES + 1):
            guard_code = SteamTOTP.generate_code(shared_secret_b64)
            server_time = int(time.time())

            data = {
                "steamid": steamid,
                "authenticator_code": guard_code,
                "authenticator_time": str(server_time),
                "activation_code": sms_code,
                "validate_sms_code": "1",
            }
            resp = self._client.post(
                "ITwoFactorService/FinalizeAddAuthenticator/v1",
                data,
                access_token=access_token,
            )
            inner: _JSONDict = resp.get("response", {})
            status = inner.get("status", 0)

            if status == 89:
                raise AuthenticatorError("Bad SMS code", response=inner)
            if status == 88 and attempt < _MAX_FINALIZE_RETRIES:
                logger.debug("Finalization attempt %d: retrying (status 88)", attempt)
                time.sleep(1)
                continue

            if not inner.get("success", False):
                raise AuthenticatorError(
                    f"Finalization failed (attempt {attempt})",
                    response=inner,
                )

            if inner.get("want_more", False):
                continue

            logger.info("Authenticator finalized successfully")
            return True

        raise AuthenticatorError(
            f"Finalization failed after {_MAX_FINALIZE_RETRIES} attempts"
        )

    # -- Private helpers -------------------------------------------------------

    def _get_rsa_key(self, account_name: str) -> tuple[rsa.PublicKey, int]:
        """Fetch RSA public key for password encryption."""
        data = self._client.get(
            "IAuthenticationService/GetPasswordRSAPublicKey/v1",
            {"account_name": account_name},
        )
        resp: _JSONDict = data.get("response", {})
        if not resp.get("publickey_mod"):
            raise AuthenticationError("Failed to get RSA key — check username")

        modulus = int(resp["publickey_mod"], 16)
        exponent = int(resp["publickey_exp"], 16)
        timestamp = int(resp["timestamp"])
        return rsa.PublicKey(modulus, exponent), timestamp

    @staticmethod
    def _encrypt_password(password: str, pub_key: rsa.PublicKey) -> str:
        """RSA-encrypt a password and return as base64."""
        encrypted = rsa.encrypt(password.encode("utf-8"), pub_key)
        return base64.b64encode(encrypted).decode("ascii")

    def _begin_auth_session(
        self, username: str, encrypted_pw: str, rsa_timestamp: int
    ) -> _JSONDict:
        """Start an authentication session as a mobile app."""
        data = {
            "account_name": username,
            "encrypted_password": encrypted_pw,
            "encryption_timestamp": str(rsa_timestamp),
            "remember_login": "true",
            "platform_type": "1",
            "persistence": "1",
            "website_id": "Mobile",
            "device_friendly_name": "SteamTOTPExtract",
        }
        resp = self._client.post(
            "IAuthenticationService/BeginAuthSessionViaCredentials/v1", data
        )
        return resp.get("response", {})

    def _submit_confirmation(
        self,
        session: _JSONDict,
        client_id: str,
        steamid: str,
        provider: _CodeProvider,
    ) -> None:
        """Submit the appropriate 2FA confirmation."""
        allowed: list[_JSONDict] = session.get("allowed_confirmations", [])
        types = {c.get("confirmation_type") for c in allowed}

        if 5 in types:
            code = provider("steam_guard")
            self._client.post(
                "IAuthenticationService/UpdateAuthSessionWithSteamGuardCode/v1",
                {
                    "client_id": client_id,
                    "steamid": steamid,
                    "code": code,
                    "code_type": "5",
                },
            )
        elif 3 in types:
            provider("device_confirm")
        elif 2 in types:
            code = provider("email")
            self._client.post(
                "IAuthenticationService/UpdateAuthSessionWithSteamGuardCode/v1",
                {
                    "client_id": client_id,
                    "steamid": steamid,
                    "code": code,
                    "code_type": "2",
                },
            )
        else:
            raise AuthenticationError(f"Unexpected confirmation types: {types}")

    def _poll_for_tokens(
        self, client_id: str, request_id: str, steamid: str, username: str
    ) -> SteamSession:
        """Poll until the auth session yields tokens."""
        for attempt in range(_POLL_ATTEMPTS):
            logger.debug("Polling auth session (attempt %d)", attempt + 1)
            poll_resp = self._client.post(
                "IAuthenticationService/PollAuthSessionStatus/v1",
                {"client_id": client_id, "request_id": request_id},
            )
            poll: _JSONDict = poll_resp.get("response", {})
            access_token = poll.get("access_token")
            if access_token:
                return SteamSession(
                    access_token=str(access_token),
                    refresh_token=str(poll.get("refresh_token", "")),
                    steamid=steamid,
                    account_name=str(poll.get("account_name", username)),
                )
            time.sleep(_POLL_INTERVAL_SECONDS)

        raise AuthenticationError("Login timed out waiting for session approval")


def _default_code_provider(hint: str) -> str:
    """Prompt on stdin for a 2FA code."""
    prompts = {
        "steam_guard": "  Enter current Steam Guard code from your phone: ",
        "email": "  Enter the code sent to your email: ",
        "device_confirm": (
            "  Confirm the login on your Steam mobile app, then press Enter..."
        ),
    }
    return input(prompts.get(hint, f"  Enter code ({hint}): ")).strip()
