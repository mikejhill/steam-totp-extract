"""Steam Guard TOTP code generation.

Port of SteamAuth/SteamGuardAccount.cs GenerateSteamGuardCodeForTime().
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

_STEAM_GUARD_CHARS = b"23456789BCDFGHJKMNPQRTVWXY"


class SteamTOTP:
    """Generates Steam Guard TOTP codes and converts secrets between encodings."""

    @staticmethod
    def generate_code(shared_secret_b64: str, time_offset: int = 0) -> str:
        """Generate a 5-character Steam Guard code.

        Args:
            shared_secret_b64: Base64-encoded shared_secret from Steam.
            time_offset: Seconds to add to current time (for clock correction).

        Returns:
            Five-character alphanumeric Steam Guard code.

        Raises:
            ValueError: If the shared_secret is empty or invalid base64.
        """
        if not shared_secret_b64:
            raise ValueError("shared_secret must not be empty")

        secret = base64.b64decode(shared_secret_b64)
        time_val = int(time.time()) + time_offset
        time_val //= 30

        time_bytes = struct.pack(">Q", time_val)
        mac = hmac.new(secret, time_bytes, hashlib.sha1).digest()

        offset = mac[19] & 0x0F
        code_int = (
            (mac[offset] & 0x7F) << 24
            | (mac[offset + 1] & 0xFF) << 16
            | (mac[offset + 2] & 0xFF) << 8
            | (mac[offset + 3] & 0xFF)
        )

        code_chars: list[int] = []
        for _ in range(5):
            code_chars.append(_STEAM_GUARD_CHARS[code_int % len(_STEAM_GUARD_CHARS)])
            code_int //= len(_STEAM_GUARD_CHARS)

        return bytes(code_chars).decode("ascii")

    @staticmethod
    def generate_code_for_time(shared_secret_b64: str, timestamp: int) -> str:
        """Generate a Steam Guard code for a specific Unix timestamp.

        Args:
            shared_secret_b64: Base64-encoded shared_secret from Steam.
            timestamp: Unix timestamp to generate a code for.

        Returns:
            Five-character alphanumeric Steam Guard code.

        Raises:
            ValueError: If the shared_secret is empty or invalid base64.
        """
        if not shared_secret_b64:
            raise ValueError("shared_secret must not be empty")

        secret = base64.b64decode(shared_secret_b64)
        time_val = timestamp // 30

        time_bytes = struct.pack(">Q", time_val)
        mac = hmac.new(secret, time_bytes, hashlib.sha1).digest()

        offset = mac[19] & 0x0F
        code_int = (
            (mac[offset] & 0x7F) << 24
            | (mac[offset + 1] & 0xFF) << 16
            | (mac[offset + 2] & 0xFF) << 8
            | (mac[offset + 3] & 0xFF)
        )

        code_chars: list[int] = []
        for _ in range(5):
            code_chars.append(_STEAM_GUARD_CHARS[code_int % len(_STEAM_GUARD_CHARS)])
            code_int //= len(_STEAM_GUARD_CHARS)

        return bytes(code_chars).decode("ascii")

    @staticmethod
    def shared_secret_to_base32(shared_secret_b64: str) -> str:
        """Convert a base64-encoded shared_secret to base32 for Bitwarden.

        Args:
            shared_secret_b64: Base64-encoded shared_secret from Steam.

        Returns:
            Base32-encoded string with padding stripped.

        Raises:
            ValueError: If the shared_secret is empty or invalid base64.
        """
        if not shared_secret_b64:
            raise ValueError("shared_secret must not be empty")

        raw = base64.b64decode(shared_secret_b64)
        return base64.b32encode(raw).decode("ascii").rstrip("=")
