"""Shared test fixtures for steam-totp-extract."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from steam_totp_extract.models import AuthenticatorData, SteamSession


@pytest.fixture
def sample_shared_secret() -> str:
    """A known base64-encoded shared_secret (21 zero bytes)."""
    return "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="


@pytest.fixture
def sample_shared_secret_b32() -> str:
    """Base32-encoded form of the sample shared secret (no padding)."""
    return "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def make_session(**overrides: str) -> SteamSession:
    """Build a SteamSession with sensible defaults.

    Override only the fields relevant to the test scenario.
    """
    defaults: dict[str, str] = {
        "access_token": "test_access_token",
        "refresh_token": "test_refresh_token",
        "steamid": "76561198000000000",
        "account_name": "testuser",
    }
    defaults.update(overrides)
    return SteamSession(**defaults)


def make_auth_data(**overrides: object) -> AuthenticatorData:
    """Build an AuthenticatorData with sensible defaults.

    Override only the fields relevant to the test scenario.
    """
    defaults: dict[str, object] = {
        "shared_secret": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "serial_number": "1234567890",
        "revocation_code": "R99999",
        "uri": "otpauth://totp/Steam:testuser",
        "server_time": 1_700_000_000,
        "account_name": "testuser",
        "token_gid": "test_gid",
        "identity_secret": "test_identity_secret",
        "secret_1": "test_secret_1",
        "status": 1,
        "device_id": "android:test-uuid",
        "raw": {
            "shared_secret": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "revocation_code": "R99999",
        },
    }
    defaults.update(overrides)
    return AuthenticatorData(**defaults)


def make_mock_authenticator(
    session: SteamSession | None = None,
    auth_data: AuthenticatorData | None = None,
) -> MagicMock:
    """Build a fully-configured mock SteamAuthenticator.

    Returns a MagicMock with login, remove, add, and finalize pre-wired.
    """
    mock = MagicMock()
    mock.login.return_value = session or make_session()
    mock.remove_authenticator.return_value = True
    mock.add_authenticator.return_value = auth_data or make_auth_data()
    mock.finalize_authenticator.return_value = True
    return mock
