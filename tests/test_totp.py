"""Tests for steam_totp_extract.totp module."""

from __future__ import annotations

import base64
import binascii

import pytest

from steam_totp_extract.totp import SteamTOTP


class TestSteamTOTPGenerateCode:
    """Tests for SteamTOTP.generate_code and generate_code_for_time."""

    def test_generates_five_character_code(self, sample_shared_secret: str) -> None:
        """Code is always exactly 5 characters."""
        code = SteamTOTP.generate_code(sample_shared_secret)
        assert len(code) == 5, f"Expected 5-char code, got {len(code)}-char: {code!r}"

    def test_code_uses_steam_alphabet(self, sample_shared_secret: str) -> None:
        """Every character belongs to the 26-char Steam Guard alphabet."""
        valid_chars = set("23456789BCDFGHJKMNPQRTVWXY")
        code = SteamTOTP.generate_code(sample_shared_secret)
        invalid = [c for c in code if c not in valid_chars]
        assert not invalid, f"Invalid chars {invalid} in code {code!r}"

    @pytest.mark.parametrize(
        "timestamp",
        [0, 1_000_000_000, 1_700_000_000, 2_000_000_000],
        ids=["epoch", "2001", "2023", "2033"],
    )
    def test_code_length_across_timestamps(
        self, sample_shared_secret: str, timestamp: int
    ) -> None:
        """Codes are 5 chars for any timestamp."""
        code = SteamTOTP.generate_code_for_time(sample_shared_secret, timestamp)
        assert len(code) == 5, (
            f"Expected 5-char code for timestamp={timestamp}, "
            f"got {len(code)}-char: {code!r}"
        )

    def test_same_period_gives_same_code(self, sample_shared_secret: str) -> None:
        """Two timestamps in the same 30s window produce the same code."""
        t = 1_700_000_010
        code1 = SteamTOTP.generate_code_for_time(sample_shared_secret, t)
        code2 = SteamTOTP.generate_code_for_time(sample_shared_secret, t + 5)
        assert code1 == code2, (
            f"Same-period codes differ: {code1!r} vs {code2!r} "
            f"(timestamps {t} and {t + 5})"
        )

    def test_different_periods_give_different_codes(
        self, sample_shared_secret: str
    ) -> None:
        """Two timestamps in different 30s windows produce different codes."""
        t = 1_700_000_010
        code1 = SteamTOTP.generate_code_for_time(sample_shared_secret, t)
        code2 = SteamTOTP.generate_code_for_time(sample_shared_secret, t + 30)
        assert code1 != code2, (
            f"Different-period codes should differ but both are {code1!r}"
        )

    def test_deterministic_for_known_input(self) -> None:
        """Known secret + timestamp produces a known code (regression)."""
        secret = base64.b64encode(bytes(range(1, 21))).decode()
        code = SteamTOTP.generate_code_for_time(secret, 0)
        assert code == "6KR59", (
            f"Expected code '6KR59' for 20-byte sequential secret at t=0, got {code!r}"
        )

    def test_deterministic_for_known_input_large_timestamp(self) -> None:
        """Known secret + large timestamp produces a known code (regression)."""
        secret = base64.b64encode(bytes(range(1, 21))).decode()
        code = SteamTOTP.generate_code_for_time(secret, 1_700_000_000)
        assert code == "3M9KK", (
            f"Expected code '3M9KK' for 20-byte sequential secret at t=1700000000, "
            f"got {code!r}"
        )

    def test_time_offset_shifts_code(self) -> None:
        """Positive time_offset generates a code for a later period."""
        secret = base64.b64encode(bytes(range(1, 21))).decode()
        code_now = SteamTOTP.generate_code_for_time(secret, 1_700_000_000)
        code_offset = SteamTOTP.generate_code_for_time(secret, 1_700_000_030)
        # generate_code with offset=+30 should match the next period
        assert code_now != code_offset, (
            f"Offset of +30s should yield a different code, but both are {code_now!r}"
        )

    def test_raises_on_empty_secret(self) -> None:
        """Empty secret raises ValueError."""
        with pytest.raises(ValueError, match="must not be empty"):
            SteamTOTP.generate_code("")

    def test_raises_on_empty_secret_for_time(self) -> None:
        """Empty secret raises ValueError for generate_code_for_time."""
        with pytest.raises(ValueError, match="must not be empty"):
            SteamTOTP.generate_code_for_time("", 0)

    def test_raises_on_invalid_base64(self) -> None:
        """Invalid base64 input raises binascii.Error."""
        with pytest.raises(binascii.Error):
            SteamTOTP.generate_code("!!!not-base64!!!")


class TestSteamTOTPSharedSecretToBase32:
    """Tests for SteamTOTP.shared_secret_to_base32."""

    def test_round_trip_conversion(self) -> None:
        """Base64 → base32 → decode matches original raw bytes."""
        raw_bytes = b"\xde\xad\xbe\xef" * 5
        b64 = base64.b64encode(raw_bytes).decode()
        b32 = SteamTOTP.shared_secret_to_base32(b64)
        decoded = base64.b32decode(b32 + "=" * (-len(b32) % 8))
        assert decoded == raw_bytes, (
            f"Round-trip failed: expected {raw_bytes.hex()}, got {decoded.hex()}"
        )

    def test_strips_padding(self) -> None:
        """Output has no trailing '=' padding."""
        secret = base64.b64encode(b"\x01\x02\x03").decode()
        b32 = SteamTOTP.shared_secret_to_base32(secret)
        assert "=" not in b32, f"Expected no padding in {b32!r}"

    def test_known_conversion(self, sample_shared_secret: str) -> None:
        """All-zero bytes have a known base32 representation."""
        b32 = SteamTOTP.shared_secret_to_base32(sample_shared_secret)
        expected = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        assert b32 == expected, f"Expected {expected!r}, got {b32!r}"

    @pytest.mark.parametrize(
        "raw_length",
        [10, 20, 32],
        ids=["10-byte", "20-byte", "32-byte"],
    )
    def test_various_secret_lengths(self, raw_length: int) -> None:
        """Conversion works for secrets of different byte lengths."""
        raw = bytes(range(raw_length))
        b64 = base64.b64encode(raw).decode()
        b32 = SteamTOTP.shared_secret_to_base32(b64)
        decoded = base64.b32decode(b32 + "=" * (-len(b32) % 8))
        assert decoded == raw, (
            f"Round-trip failed for {raw_length}-byte input: "
            f"expected {raw.hex()}, got {decoded.hex()}"
        )

    def test_raises_on_empty_secret(self) -> None:
        """Empty secret raises ValueError."""
        with pytest.raises(ValueError, match="must not be empty"):
            SteamTOTP.shared_secret_to_base32("")

    def test_raises_on_invalid_base64(self) -> None:
        """Invalid base64 input raises binascii.Error."""
        with pytest.raises(binascii.Error):
            SteamTOTP.shared_secret_to_base32("!!!not-base64!!!")
