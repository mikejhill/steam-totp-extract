"""Application entry point for steam-totp-extract."""

from __future__ import annotations

import getpass
import logging
import sys

from steam_totp_extract.cli import parse_args
from steam_totp_extract.exceptions import AppError
from steam_totp_extract.models import ExtractionResult
from steam_totp_extract.workflow import ExtractionWorkflow

logger = logging.getLogger(__name__)


def _display_result(result: ExtractionResult) -> None:
    """Print the extraction result in a user-friendly format."""
    print(
        "\n"
        "═══════════════════════════════════════════════\n"
        "  STEAM GUARD TOTP EXTRACTION COMPLETE\n"
        "═══════════════════════════════════════════════\n"
        f"  Account:          {result.account_name}\n"
        f"  SteamID:          {result.steamid}\n"
        f"  Revocation Code:  {result.revocation_code}  ← SAVE THIS!\n"
        "\n"
        f"  shared_secret (base64): {result.shared_secret_b64}\n"
        f"  shared_secret (base32): {result.shared_secret_b32}\n"
        "\n"
        "  ┌─ FOR BITWARDEN ────────────────────────────\n"
        "  │ Paste this into the 'Authenticator Key\n"
        "  │ (TOTP)' field of your Steam login entry:\n"
        "  │\n"
        f"  │   {result.steam_uri}\n"
        "  └────────────────────────────────────────────\n"
        "\n"
        f"  Current code:  {result.current_code}  (verify in Bitwarden)\n"
        "\n"
        f"  Backup saved:  {result.backup_path}\n"
        "═══════════════════════════════════════════════"
    )


def _prompt_credentials() -> tuple[str, str, str]:
    """Interactively collect Steam credentials from the user."""
    print("\n  Steam Guard TOTP Extractor")
    print("  ─────────────────────────\n")
    username = input("  Steam username: ").strip()
    password = getpass.getpass("  Steam password: ")
    revocation_code = input("  Current revocation code (e.g. R12345): ").strip()
    return username, password, revocation_code


def main() -> None:
    """Parse arguments, configure logging, and run the extraction workflow."""
    args = parse_args()
    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    username, password, revocation_code = _prompt_credentials()

    workflow = ExtractionWorkflow(output_dir=args.output_dir)
    try:
        result = workflow.run(username, password, revocation_code)
        _display_result(result)
    except AppError as exc:
        logger.error("%s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
