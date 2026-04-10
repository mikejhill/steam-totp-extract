"""Tests for steam_totp_extract.models module."""

from __future__ import annotations

import pytest

from steam_totp_extract.models import AuthenticatorData, ExtractionResult, SteamSession


class TestSteamSession:
    """Tests for SteamSession dataclass."""

    def test_stores_all_fields(self) -> None:
        """SteamSession stores all provided fields."""
        session = SteamSession(
            access_token="tok",
            refresh_token="ref",
            steamid="123",
            account_name="user",
        )
        assert session.access_token == "tok", (
            f"Expected access_token='tok', got {session.access_token!r}"
        )
        assert session.refresh_token == "ref", (
            f"Expected refresh_token='ref', got {session.refresh_token!r}"
        )
        assert session.steamid == "123", (
            f"Expected steamid='123', got {session.steamid!r}"
        )
        assert session.account_name == "user", (
            f"Expected account_name='user', got {session.account_name!r}"
        )

    def test_frozen_prevents_mutation(self) -> None:
        """SteamSession is immutable (frozen dataclass)."""
        session = SteamSession("t", "r", "1", "u")
        with pytest.raises(AttributeError):
            setattr(session, "access_token", "new")  # noqa: B010


class TestAuthenticatorData:
    """Tests for AuthenticatorData dataclass."""

    def test_stores_essential_fields(self) -> None:
        """AuthenticatorData stores all essential authenticator fields."""
        data = AuthenticatorData(
            shared_secret="s",
            serial_number="123",
            revocation_code="R12345",
            uri="otpauth://",
            server_time=1000,
            account_name="user",
            token_gid="gid",
            identity_secret="id_s",
            secret_1="s1",
            status=1,
            device_id="android:uuid",
        )
        assert data.shared_secret == "s", (
            f"Expected shared_secret='s', got {data.shared_secret!r}"
        )
        assert data.revocation_code == "R12345", (
            f"Expected revocation_code='R12345', got {data.revocation_code!r}"
        )
        assert data.status == 1, f"Expected status=1, got {data.status!r}"
        assert data.device_id == "android:uuid", (
            f"Expected device_id='android:uuid', got {data.device_id!r}"
        )

    def test_raw_defaults_to_empty_dict(self) -> None:
        """AuthenticatorData.raw defaults to empty dict when not provided."""
        data = AuthenticatorData(
            shared_secret="",
            serial_number="",
            revocation_code="",
            uri="",
            server_time=0,
            account_name="",
            token_gid="",
            identity_secret="",
            secret_1="",
            status=0,
            device_id="",
        )
        assert data.raw == {}, f"Expected empty dict, got {data.raw!r}"

    def test_raw_stores_provided_dict(self) -> None:
        """AuthenticatorData.raw stores the provided dict."""
        raw = {"shared_secret": "test", "status": 1}
        data = AuthenticatorData(
            shared_secret="test",
            serial_number="",
            revocation_code="",
            uri="",
            server_time=0,
            account_name="",
            token_gid="",
            identity_secret="",
            secret_1="",
            status=1,
            device_id="",
            raw=raw,
        )
        assert data.raw == raw, f"Expected {raw!r}, got {data.raw!r}"


class TestExtractionResult:
    """Tests for ExtractionResult dataclass."""

    def test_stores_all_output_fields(self) -> None:
        """ExtractionResult stores all extraction output fields."""
        result = ExtractionResult(
            account_name="user",
            steamid="123",
            revocation_code="R12345",
            shared_secret_b64="b64",
            shared_secret_b32="b32",
            identity_secret="id",
            steam_uri="steam://B32",
            current_code="X2Y3Z",
            backup_path="/tmp/test.json",
        )
        assert result.steam_uri == "steam://B32", (
            f"Expected steam_uri='steam://B32', got {result.steam_uri!r}"
        )
        assert result.current_code == "X2Y3Z", (
            f"Expected current_code='X2Y3Z', got {result.current_code!r}"
        )
        assert result.backup_path == "/tmp/test.json", (
            f"Expected backup_path='/tmp/test.json', got {result.backup_path!r}"
        )
