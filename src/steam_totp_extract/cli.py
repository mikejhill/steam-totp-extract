"""Command-line argument parsing for steam-totp-extract."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse and validate command-line arguments.

    Args:
        argv: Argument list. Uses sys.argv when None.

    Returns:
        Parsed arguments namespace.
    """
    parser = argparse.ArgumentParser(
        prog="steam-totp-extract",
        description=(
            "Extract Steam Guard TOTP secret for Bitwarden import. "
            "Walks through Steam login, authenticator removal, "
            "and re-registration to obtain the shared_secret."
        ),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path.cwd(),
        help="Directory for authenticator backup (default: %(default)s)",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging verbosity (default: %(default)s)",
    )

    args = parser.parse_args(argv)

    if not args.output_dir.is_dir():
        parser.error(f"Output directory does not exist: {args.output_dir}")

    args.log_level = getattr(logging, args.log_level)
    return args
