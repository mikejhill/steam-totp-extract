"""Tests for steam_totp_extract.cli module."""

from __future__ import annotations

from pathlib import Path

import pytest

from steam_totp_extract.cli import parse_args


class TestParseArgs:
    """Tests for parse_args function."""

    def test_defaults(self) -> None:
        """Default arguments use cwd and INFO log level."""
        args = parse_args([])
        assert isinstance(args.output_dir, Path)
        assert args.log_level == 20  # logging.INFO

    def test_custom_output_dir(self, tmp_path: Path) -> None:
        """--output-dir sets the output directory."""
        args = parse_args(["--output-dir", str(tmp_path)])
        assert args.output_dir == tmp_path

    def test_invalid_output_dir(self, tmp_path: Path) -> None:
        """Non-existent --output-dir causes a SystemExit."""
        bad_path = tmp_path / "nonexistent"
        with pytest.raises(SystemExit):
            parse_args(["--output-dir", str(bad_path)])

    @pytest.mark.parametrize(
        ("level_str", "expected_int"),
        [
            ("DEBUG", 10),
            ("INFO", 20),
            ("WARNING", 30),
            ("ERROR", 40),
        ],
    )
    def test_log_level_choices(self, level_str: str, expected_int: int) -> None:
        """--log-level accepts all valid choices."""
        args = parse_args(["--log-level", level_str])
        assert args.log_level == expected_int

    def test_invalid_log_level(self) -> None:
        """Invalid --log-level causes a SystemExit."""
        with pytest.raises(SystemExit):
            parse_args(["--log-level", "TRACE"])
