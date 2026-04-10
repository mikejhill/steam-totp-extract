"""Interactive workflow for extracting Steam Guard TOTP secrets."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from pathlib import Path

from steam_totp_extract.exceptions import AppError, AuthenticatorError
from steam_totp_extract.models import AuthenticatorData, ExtractionResult, SteamSession
from steam_totp_extract.steam_api import SteamAuthenticator
from steam_totp_extract.totp import SteamTOTP

logger = logging.getLogger(__name__)

_SMSCodeProvider = Callable[[], str]


class ExtractionWorkflow:
    """Orchestrates the full TOTP extraction process.

    Steps: login → remove old auth → add new auth → finalize via SMS → output.
    """

    def __init__(
        self,
        authenticator: SteamAuthenticator | None = None,
        output_dir: Path | None = None,
    ) -> None:
        """Initialize the workflow.

        Args:
            authenticator: SteamAuthenticator instance; created if not provided.
            output_dir: Directory for saving authenticator backups. Defaults to cwd.
        """
        self._auth = authenticator or SteamAuthenticator()
        self._output_dir = output_dir or Path.cwd()

    def run(
        self,
        username: str,
        password: str,
        revocation_code: str,
        sms_code_provider: _SMSCodeProvider | None = None,
    ) -> ExtractionResult:
        """Execute the full extraction workflow.

        Args:
            username: Steam account name.
            password: Steam account password.
            revocation_code: Existing authenticator revocation code (e.g. 'R12345').
            sms_code_provider: Callable returning the SMS code. Defaults to stdin.

        Returns:
            ExtractionResult with all secrets and paths.

        Raises:
            AppError: On any unrecoverable failure during the workflow.
        """
        if not username:
            raise AppError("Username is required")
        if not password:
            raise AppError("Password is required")
        if not revocation_code:
            raise AppError("Revocation code is required")

        sms_provider = sms_code_provider or _default_sms_provider

        session = self._login(username, password)
        self._remove_old_authenticator(session.access_token, revocation_code)
        auth_data = self._add_new_authenticator(session.access_token, session.steamid)
        sms_code = sms_provider()
        self._finalize(session.access_token, session.steamid, auth_data, sms_code)

        backup_path = self._save_backup(auth_data, session.steamid)
        return self._build_result(auth_data, session, backup_path)

    # -- Private steps ---------------------------------------------------------

    def _login(self, username: str, password: str) -> SteamSession:
        """Perform Steam login."""
        logger.info("Logging in as %s", username)
        return self._auth.login(username, password)

    def _remove_old_authenticator(
        self, access_token: str, revocation_code: str
    ) -> None:
        """Remove the existing authenticator."""
        logger.info("Removing existing authenticator")
        try:
            self._auth.remove_authenticator(access_token, revocation_code)
        except AuthenticatorError:
            logger.warning("Removal returned error; proceeding anyway")

    def _add_new_authenticator(
        self, access_token: str, steamid: str
    ) -> AuthenticatorData:
        """Register a new authenticator."""
        logger.info("Adding new authenticator")
        return self._auth.add_authenticator(access_token, steamid)

    def _finalize(
        self,
        access_token: str,
        steamid: str,
        auth_data: AuthenticatorData,
        sms_code: str,
    ) -> None:
        """Finalize with SMS verification."""
        logger.info("Finalizing with SMS code")
        self._auth.finalize_authenticator(
            access_token, steamid, auth_data.shared_secret, sms_code
        )

    def _save_backup(self, auth_data: AuthenticatorData, steamid: str) -> Path:
        """Save a JSON backup of the authenticator data."""
        backup_content = dict(auth_data.raw)
        backup_content["device_id"] = auth_data.device_id
        filename = f"steam_guard_{steamid}.json"
        path = self._output_dir / filename
        path.write_text(json.dumps(backup_content, indent=2), encoding="utf-8")
        logger.info("Saved backup to %s", path)
        return path

    @staticmethod
    def _build_result(
        auth_data: AuthenticatorData,
        session: SteamSession,
        backup_path: Path,
    ) -> ExtractionResult:
        """Assemble the final extraction result."""
        b32 = SteamTOTP.shared_secret_to_base32(auth_data.shared_secret)
        current_code = SteamTOTP.generate_code(auth_data.shared_secret)
        return ExtractionResult(
            account_name=session.account_name,
            steamid=session.steamid,
            revocation_code=auth_data.revocation_code,
            shared_secret_b64=auth_data.shared_secret,
            shared_secret_b32=b32,
            identity_secret=auth_data.identity_secret,
            steam_uri=f"steam://{b32}",
            current_code=current_code,
            backup_path=str(backup_path),
        )


def _default_sms_provider() -> str:
    """Prompt on stdin for the SMS code."""
    return input("  Enter the SMS code sent to your phone: ").strip()
