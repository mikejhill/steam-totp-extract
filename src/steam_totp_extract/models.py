"""Data models for Steam authenticator operations."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class SteamSession:
    """Authenticated Steam session credentials."""

    access_token: str
    refresh_token: str
    steamid: str
    account_name: str


@dataclass(frozen=True)
class AuthenticatorData:
    """Authenticator secrets returned by AddAuthenticator.

    Contains all sensitive fields needed for TOTP generation and recovery.
    """

    shared_secret: str
    serial_number: str
    revocation_code: str
    uri: str
    server_time: int
    account_name: str
    token_gid: str
    identity_secret: str
    secret_1: str
    status: int
    device_id: str
    # Steam API returns untyped JSON; Any is justified for third-party data.
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ExtractionResult:
    """Final output of the extraction process."""

    account_name: str
    steamid: str
    revocation_code: str
    shared_secret_b64: str
    shared_secret_b32: str
    identity_secret: str
    steam_uri: str
    current_code: str
    backup_path: str
