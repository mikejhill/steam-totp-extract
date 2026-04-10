"""Tests for steam_totp_extract.exceptions module."""

from __future__ import annotations

import pytest

from steam_totp_extract.exceptions import (
    AppError,
    AuthenticationError,
    AuthenticatorError,
    SteamAPIError,
)


class TestExceptionHierarchy:
    """Tests for the exception class hierarchy."""

    @pytest.mark.parametrize(
        "exc_class",
        [SteamAPIError, AuthenticationError, AuthenticatorError],
        ids=["SteamAPIError", "AuthenticationError", "AuthenticatorError"],
    )
    def test_catchable_as_app_error(self, exc_class: type[AppError]) -> None:
        """All domain exceptions are catchable as AppError."""
        with pytest.raises(AppError):
            raise exc_class("test error")


class TestSteamAPIError:
    """Tests for SteamAPIError fields."""

    def test_message_accessible_via_str(self) -> None:
        """Error message is accessible via str()."""
        exc = SteamAPIError("something failed")
        assert str(exc) == "something failed", (
            f"Expected message 'something failed', got {str(exc)!r}"
        )

    def test_response_defaults_to_none(self) -> None:
        """Response defaults to None when not provided."""
        exc = SteamAPIError("fail")
        assert exc.response is None, f"Expected response=None, got {exc.response!r}"

    def test_response_stored_when_provided(self) -> None:
        """Response dict is stored when provided."""
        resp = {"status": 29, "error": "already present"}
        exc = SteamAPIError("fail", response=resp)
        assert exc.response == resp, f"Expected response {resp!r}, got {exc.response!r}"


class TestAuthenticationError:
    """Tests for AuthenticationError."""

    def test_inherits_response_field(self) -> None:
        """AuthenticationError supports the response keyword from SteamAPIError."""
        resp = {"client_id": ""}
        exc = AuthenticationError("login failed", response=resp)
        assert exc.response == resp, f"Expected response {resp!r}, got {exc.response!r}"


class TestAuthenticatorError:
    """Tests for AuthenticatorError."""

    def test_inherits_response_field(self) -> None:
        """AuthenticatorError supports the response keyword from SteamAPIError."""
        resp = {"status": 2}
        exc = AuthenticatorError("no phone", response=resp)
        assert exc.response == resp, f"Expected response {resp!r}, got {exc.response!r}"
