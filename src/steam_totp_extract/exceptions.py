"""Project-specific exception hierarchy."""

from __future__ import annotations

from typing import Any


class AppError(Exception):
    """Base exception for the application."""


class SteamAPIError(AppError):
    """Raised when a Steam API call fails."""

    def __init__(
        self,
        message: str,
        # Steam API returns untyped JSON; Any is justified for third-party data.
        response: dict[str, Any] | None = None,
    ) -> None:
        """Initialize with a message and optional API response.

        Args:
            message: Human-readable description of the failure.
            response: Raw Steam API response body, if available.
        """
        super().__init__(message)
        self.response = response


class AuthenticationError(SteamAPIError):
    """Raised when Steam login fails."""


class AuthenticatorError(SteamAPIError):
    """Raised when authenticator add/remove/finalize fails."""
