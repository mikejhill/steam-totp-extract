"""Tests for steam_totp_extract.steam_api module."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests

from steam_totp_extract.exceptions import (
    AuthenticationError,
    AuthenticatorError,
    SteamAPIError,
)
from steam_totp_extract.steam_api import SteamAPIClient, SteamAuthenticator

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_client_mock(response_json: dict[str, Any]) -> SteamAPIClient:
    """Build a SteamAPIClient whose session returns a canned JSON response."""
    mock_resp = MagicMock()
    mock_resp.json.return_value = response_json
    mock_resp.raise_for_status.return_value = None

    mock_session = MagicMock()
    mock_session.post.return_value = mock_resp
    mock_session.get.return_value = mock_resp

    client = SteamAPIClient()
    object.__setattr__(client, "_session", mock_session)
    return client


def _api_client_returning(*responses: dict[str, Any]) -> SteamAPIClient:
    """Build a SteamAPIClient that returns successive canned responses."""
    mock_resps = []
    for resp_json in responses:
        mock_resp = MagicMock()
        mock_resp.json.return_value = resp_json
        mock_resp.raise_for_status.return_value = None
        mock_resps.append(mock_resp)

    mock_session = MagicMock()
    mock_session.post.side_effect = mock_resps
    mock_session.get.side_effect = mock_resps

    client = SteamAPIClient()
    object.__setattr__(client, "_session", mock_session)
    return client


# ===========================================================================
# SteamAPIClient tests
# ===========================================================================


class TestSteamAPIClientPost:
    """Tests for SteamAPIClient.post."""

    def test_post_returns_parsed_json(self) -> None:
        """Successful POST returns parsed JSON dict."""
        expected = {"response": {"status": 1}}
        client = _make_client_mock(expected)

        result = client.post("ITwoFactorService/AddAuthenticator/v1")

        assert result == expected, f"Expected {expected!r}, got {result!r}"

    def test_post_appends_access_token_to_url(self) -> None:
        """Access token is appended as query parameter."""
        client = _make_client_mock({"response": {}})
        client.post("some/endpoint", access_token="my_token")

        mock_session: MagicMock = client._session  # ty: ignore[invalid-assignment]
        call_args = mock_session.post.call_args
        url = call_args[0][0]
        assert "?access_token=my_token" in url, (
            f"Expected access_token in URL, got {url!r}"
        )

    def test_post_raises_steam_api_error_on_http_failure(self) -> None:
        """HTTP errors are wrapped in SteamAPIError."""
        mock_session = MagicMock()
        mock_session.post.side_effect = requests.ConnectionError("timeout")
        client = SteamAPIClient()
        object.__setattr__(client, "_session", mock_session)

        with pytest.raises(SteamAPIError, match="HTTP request failed"):
            client.post("some/endpoint")


class TestSteamAPIClientGet:
    """Tests for SteamAPIClient.get."""

    def test_get_returns_parsed_json(self) -> None:
        """Successful GET returns parsed JSON dict."""
        expected = {"response": {"publickey_mod": "abc"}}
        client = _make_client_mock(expected)

        result = client.get("IAuthenticationService/GetPasswordRSAPublicKey/v1")

        assert result == expected, f"Expected {expected!r}, got {result!r}"

    def test_get_raises_steam_api_error_on_http_failure(self) -> None:
        """HTTP errors are wrapped in SteamAPIError."""
        mock_session = MagicMock()
        mock_session.get.side_effect = requests.ConnectionError("dns fail")
        client = SteamAPIClient()
        object.__setattr__(client, "_session", mock_session)

        with pytest.raises(SteamAPIError, match="HTTP request failed"):
            client.get("some/endpoint")


# ===========================================================================
# SteamAuthenticator tests
# ===========================================================================


class TestSteamAuthenticatorLogin:
    """Tests for SteamAuthenticator.login."""

    def test_raises_on_empty_username(self) -> None:
        """Empty username raises AuthenticationError."""
        auth = SteamAuthenticator()
        with pytest.raises(AuthenticationError, match="Username must not be empty"):
            auth.login("", "password")

    def test_raises_on_empty_password(self) -> None:
        """Empty password raises AuthenticationError."""
        auth = SteamAuthenticator()
        with pytest.raises(AuthenticationError, match="Password must not be empty"):
            auth.login("user", "")

    def test_raises_on_missing_client_id(self) -> None:
        """Missing client_id in auth response raises AuthenticationError."""
        rsa_resp = {
            "response": {
                "publickey_mod": "00b" + "0" * 510,
                "publickey_exp": "010001",
                "timestamp": "12345",
            }
        }
        begin_resp = {"response": {}}

        # Build client with RSA key response for GET, empty response for POST
        mock_get_resp = MagicMock()
        mock_get_resp.json.return_value = rsa_resp
        mock_get_resp.raise_for_status.return_value = None

        mock_post_resp = MagicMock()
        mock_post_resp.json.return_value = begin_resp
        mock_post_resp.raise_for_status.return_value = None

        mock_session = MagicMock()
        mock_session.get.return_value = mock_get_resp
        mock_session.post.return_value = mock_post_resp

        client = SteamAPIClient()
        object.__setattr__(client, "_session", mock_session)

        auth = SteamAuthenticator(client=client)
        with pytest.raises(AuthenticationError, match="Login failed"):
            auth.login("user", "password")


class TestSteamAuthenticatorRemoveAuthenticator:
    """Tests for SteamAuthenticator.remove_authenticator."""

    def test_remove_success(self) -> None:
        """Successful removal returns True."""
        client = _make_client_mock({"response": {"success": True}})
        auth = SteamAuthenticator(client=client)

        result = auth.remove_authenticator("token", "R12345")

        assert result is True, "Expected True for successful removal"

    def test_remove_failure_returns_false(self) -> None:
        """Failed removal returns False."""
        client = _make_client_mock(
            {"response": {"success": False, "revocation_attempts_remaining": 3}}
        )
        auth = SteamAuthenticator(client=client)

        result = auth.remove_authenticator("token", "R12345")

        assert result is False, "Expected False for failed removal"

    def test_remove_raises_on_empty_revocation_code(self) -> None:
        """Empty revocation code raises AuthenticatorError."""
        auth = SteamAuthenticator()
        with pytest.raises(
            AuthenticatorError, match="Revocation code must not be empty"
        ):
            auth.remove_authenticator("token", "")


class TestSteamAuthenticatorAddAuthenticator:
    """Tests for SteamAuthenticator.add_authenticator."""

    def test_add_success_returns_authenticator_data(self) -> None:
        """Successful add returns AuthenticatorData with correct fields."""
        inner = {
            "status": 1,
            "shared_secret": "dGVzdA==",
            "serial_number": "999",
            "revocation_code": "R55555",
            "uri": "otpauth://totp/Steam:user",
            "server_time": 1700000000,
            "account_name": "user",
            "token_gid": "gid123",
            "identity_secret": "id_secret",
            "secret_1": "s1",
        }
        client = _make_client_mock({"response": inner})
        auth = SteamAuthenticator(client=client)

        result = auth.add_authenticator("token", "76561198000000000")

        assert result.shared_secret == "dGVzdA==", (
            f"Expected shared_secret='dGVzdA==', got {result.shared_secret!r}"
        )
        assert result.revocation_code == "R55555", (
            f"Expected revocation_code='R55555', got {result.revocation_code!r}"
        )
        assert result.device_id.startswith("android:"), (
            f"Expected device_id starting with 'android:', got {result.device_id!r}"
        )

    def test_add_status_2_raises_no_phone_error(self) -> None:
        """Status 2 raises AuthenticatorError about missing phone number."""
        client = _make_client_mock({"response": {"status": 2}})
        auth = SteamAuthenticator(client=client)

        with pytest.raises(AuthenticatorError, match="No phone number"):
            auth.add_authenticator("token", "steamid")

    def test_add_status_29_raises_already_present_error(self) -> None:
        """Status 29 raises AuthenticatorError about existing authenticator."""
        client = _make_client_mock({"response": {"status": 29}})
        auth = SteamAuthenticator(client=client)

        with pytest.raises(AuthenticatorError, match="already present"):
            auth.add_authenticator("token", "steamid")

    def test_add_unknown_status_raises_error(self) -> None:
        """Unknown status raises AuthenticatorError with the status code."""
        client = _make_client_mock({"response": {"status": 99}})
        auth = SteamAuthenticator(client=client)

        with pytest.raises(AuthenticatorError, match="status 99"):
            auth.add_authenticator("token", "steamid")


class TestSteamAuthenticatorFinalizeAuthenticator:
    """Tests for SteamAuthenticator.finalize_authenticator."""

    def test_finalize_success(self) -> None:
        """Successful finalization returns True."""
        client = _make_client_mock(
            {"response": {"status": 1, "success": True, "want_more": False}}
        )
        auth = SteamAuthenticator(client=client)

        result = auth.finalize_authenticator(
            "token", "steamid", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "12345"
        )

        assert result is True, "Expected True for successful finalization"

    def test_finalize_bad_sms_code_raises_error(self) -> None:
        """Status 89 (bad SMS) raises AuthenticatorError."""
        client = _make_client_mock({"response": {"status": 89}})
        auth = SteamAuthenticator(client=client)

        with pytest.raises(AuthenticatorError, match="Bad SMS code"):
            auth.finalize_authenticator(
                "token", "steamid", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "wrong"
            )

    def test_finalize_empty_sms_raises_error(self) -> None:
        """Empty SMS code raises AuthenticatorError."""
        auth = SteamAuthenticator()

        with pytest.raises(AuthenticatorError, match="SMS code must not be empty"):
            auth.finalize_authenticator(
                "token", "steamid", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", ""
            )

    @patch("steam_totp_extract.steam_api.time.sleep")
    def test_finalize_retries_on_status_88(self, mock_sleep: MagicMock) -> None:
        """Status 88 triggers a retry, then succeeds on next attempt."""
        retry_resp = MagicMock()
        retry_resp.json.return_value = {"response": {"status": 88}}
        retry_resp.raise_for_status.return_value = None

        success_resp = MagicMock()
        success_resp.json.return_value = {
            "response": {"status": 1, "success": True, "want_more": False}
        }
        success_resp.raise_for_status.return_value = None

        mock_session = MagicMock()
        mock_session.post.side_effect = [retry_resp, success_resp]
        client = SteamAPIClient()
        object.__setattr__(client, "_session", mock_session)

        auth = SteamAuthenticator(client=client)
        result = auth.finalize_authenticator(
            "token", "steamid", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "12345"
        )

        assert result is True, "Expected True after retry succeeded"
        mock_sleep.assert_called_once_with(1)

    @patch("steam_totp_extract.steam_api.time.sleep")
    @patch("steam_totp_extract.steam_api._MAX_FINALIZE_RETRIES", 2)
    def test_finalize_max_retries_exceeded(self, mock_sleep: MagicMock) -> None:
        """Exceeding max retries raises AuthenticatorError."""
        _ = mock_sleep  # Required by @patch decorator
        # want_more=True causes loop to continue; after all retries, raises
        want_more_resp = MagicMock()
        want_more_resp.json.return_value = {
            "response": {"status": 1, "success": True, "want_more": True}
        }
        want_more_resp.raise_for_status.return_value = None

        mock_session = MagicMock()
        mock_session.post.side_effect = [want_more_resp] * 3
        client = SteamAPIClient()
        object.__setattr__(client, "_session", mock_session)

        auth = SteamAuthenticator(client=client)
        with pytest.raises(AuthenticatorError, match="failed after 2 attempts"):
            auth.finalize_authenticator(
                "token", "steamid", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "12345"
            )

    def test_finalize_failure_raises_error(self) -> None:
        """Non-retryable failure raises AuthenticatorError."""
        client = _make_client_mock({"response": {"status": 0, "success": False}})
        auth = SteamAuthenticator(client=client)

        with pytest.raises(AuthenticatorError, match="Finalization failed"):
            auth.finalize_authenticator(
                "token", "steamid", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "12345"
            )


class TestSteamAuthenticatorGetRSAKey:
    """Tests for SteamAuthenticator._get_rsa_key (via login path)."""

    def test_raises_on_missing_publickey_mod(self) -> None:
        """Missing publickey_mod raises AuthenticationError."""
        mock_get_resp = MagicMock()
        mock_get_resp.json.return_value = {"response": {}}
        mock_get_resp.raise_for_status.return_value = None

        mock_session = MagicMock()
        mock_session.get.return_value = mock_get_resp

        client = SteamAPIClient()
        object.__setattr__(client, "_session", mock_session)

        auth = SteamAuthenticator(client=client)
        with pytest.raises(AuthenticationError, match="Failed to get RSA key"):
            auth._get_rsa_key("baduser")


class TestSteamAuthenticatorSubmitConfirmation:
    """Tests for SteamAuthenticator._submit_confirmation (via login path)."""

    def test_raises_on_unknown_confirmation_type(self) -> None:
        """Unknown confirmation type raises AuthenticationError."""
        client = _make_client_mock({"response": {}})
        auth = SteamAuthenticator(client=client)

        with pytest.raises(AuthenticationError, match="Unexpected confirmation types"):
            auth._submit_confirmation(
                session={"allowed_confirmations": [{"confirmation_type": 99}]},
                client_id="123",
                steamid="456",
                provider=lambda hint: "code",  # noqa: ARG005
            )
