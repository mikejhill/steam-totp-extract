"""Tests for steam_totp_extract.__main__ module."""

from __future__ import annotations

import io
from unittest.mock import MagicMock, patch

import pytest

from steam_totp_extract.__main__ import _display_result, _prompt_credentials, main
from steam_totp_extract.exceptions import AuthenticationError
from steam_totp_extract.models import ExtractionResult


def _make_result(**overrides: str) -> ExtractionResult:
    """Build an ExtractionResult with sensible defaults."""
    defaults: dict[str, str] = {
        "account_name": "testuser",
        "steamid": "76561198000000000",
        "revocation_code": "R12345",
        "shared_secret_b64": "dGVzdA==",
        "shared_secret_b32": "ORSXG5A",
        "identity_secret": "id_secret",
        "steam_uri": "steam://ORSXG5A",
        "current_code": "X2Y3Z",
        "backup_path": "/tmp/steam_guard_76561198000000000.json",
    }
    defaults.update(overrides)
    return ExtractionResult(**defaults)


class TestDisplayResult:
    """Tests for _display_result output formatting."""

    def test_output_contains_account_name(self) -> None:
        """Display output includes the account name."""
        result = _make_result(account_name="mysteamuser")
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            _display_result(result)
        output = buf.getvalue()
        assert "mysteamuser" in output, (
            f"Expected 'mysteamuser' in output, got:\n{output}"
        )

    def test_output_contains_steam_uri(self) -> None:
        """Display output includes the steam:// URI for Bitwarden."""
        result = _make_result(steam_uri="steam://TESTBASE32")
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            _display_result(result)
        output = buf.getvalue()
        assert "steam://TESTBASE32" in output, (
            f"Expected 'steam://TESTBASE32' in output, got:\n{output}"
        )

    def test_output_contains_revocation_code(self) -> None:
        """Display output includes the revocation code with SAVE THIS hint."""
        result = _make_result(revocation_code="R99999")
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            _display_result(result)
        output = buf.getvalue()
        assert "R99999" in output, f"Expected 'R99999' in output, got:\n{output}"
        assert "SAVE THIS" in output, (
            f"Expected 'SAVE THIS' warning in output, got:\n{output}"
        )

    def test_output_contains_current_code(self) -> None:
        """Display output includes the current TOTP code for verification."""
        result = _make_result(current_code="ABCDE")
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            _display_result(result)
        output = buf.getvalue()
        assert "ABCDE" in output, f"Expected 'ABCDE' in output, got:\n{output}"

    def test_output_contains_bitwarden_instructions(self) -> None:
        """Display output includes Bitwarden paste instructions."""
        result = _make_result()
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            _display_result(result)
        output = buf.getvalue()
        assert "Authenticator Key" in output, (
            f"Expected 'Authenticator Key' in output, got:\n{output}"
        )
        assert "BITWARDEN" in output, f"Expected 'BITWARDEN' in output, got:\n{output}"

    def test_output_contains_backup_path(self) -> None:
        """Display output includes the backup file path."""
        result = _make_result(backup_path="/my/custom/path/backup.json")
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            _display_result(result)
        output = buf.getvalue()
        assert "/my/custom/path/backup.json" in output, (
            f"Expected backup path in output, got:\n{output}"
        )

    def test_output_contains_both_secret_formats(self) -> None:
        """Display output includes both base64 and base32 shared_secret."""
        result = _make_result(
            shared_secret_b64="b64value", shared_secret_b32="b32value"
        )
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            _display_result(result)
        output = buf.getvalue()
        assert "b64value" in output, f"Expected base64 secret in output, got:\n{output}"
        assert "b32value" in output, f"Expected base32 secret in output, got:\n{output}"


class TestPromptCredentials:
    """Tests for _prompt_credentials interactive input."""

    @patch("steam_totp_extract.__main__.getpass.getpass", return_value="secret_pw")
    @patch("builtins.input", side_effect=["myuser", "R12345"])
    def test_returns_username_password_revocation(
        self,
        mock_input: MagicMock,
        mock_getpass: MagicMock,
    ) -> None:
        """Returns tuple of (username, password, revocation_code)."""
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            username, password, revcode = _prompt_credentials()

        assert username == "myuser", f"Expected username='myuser', got {username!r}"
        assert password == "secret_pw", (
            f"Expected password='secret_pw', got {password!r}"
        )
        assert revcode == "R12345", (
            f"Expected revocation_code='R12345', got {revcode!r}"
        )
        assert mock_input.call_count == 2, (
            f"Expected 2 input() calls, got {mock_input.call_count}"
        )
        mock_getpass.assert_called_once()

    @patch("steam_totp_extract.__main__.getpass.getpass", return_value="pw")
    @patch("builtins.input", side_effect=["  spacey_user  ", "  R99999  "])
    def test_strips_whitespace_from_inputs(
        self,
        mock_input: MagicMock,
        mock_getpass: MagicMock,
    ) -> None:
        """Username and revocation code are stripped of whitespace."""
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            username, _password, revcode = _prompt_credentials()

        assert username == "spacey_user", (
            f"Expected stripped username='spacey_user', got {username!r}"
        )
        assert revcode == "R99999", (
            f"Expected stripped revcode='R99999', got {revcode!r}"
        )
        assert mock_input.call_count == 2, (
            f"Expected 2 input() calls, got {mock_input.call_count}"
        )
        assert mock_getpass.call_count == 1, (
            f"Expected 1 getpass() call, got {mock_getpass.call_count}"
        )


class TestMain:
    """Tests for main() entry point."""

    @patch("steam_totp_extract.__main__._display_result")
    @patch("steam_totp_extract.__main__.ExtractionWorkflow")
    @patch("steam_totp_extract.__main__._prompt_credentials")
    @patch("steam_totp_extract.__main__.parse_args")
    def test_successful_run_displays_result(
        self,
        mock_args: MagicMock,
        mock_creds: MagicMock,
        mock_workflow_cls: MagicMock,
        mock_display: MagicMock,
    ) -> None:
        """Successful workflow run calls _display_result with the result."""
        mock_args.return_value = MagicMock(log_level="WARNING", output_dir=".")
        mock_creds.return_value = ("user", "pass", "R12345")
        mock_result = _make_result()
        mock_workflow_cls.return_value.run.return_value = mock_result

        main()

        mock_display.assert_called_once_with(mock_result)

    @patch("steam_totp_extract.__main__.ExtractionWorkflow")
    @patch("steam_totp_extract.__main__._prompt_credentials")
    @patch("steam_totp_extract.__main__.parse_args")
    def test_app_error_exits_with_code_1(
        self,
        mock_args: MagicMock,
        mock_creds: MagicMock,
        mock_workflow_cls: MagicMock,
    ) -> None:
        """AppError during workflow run causes sys.exit(1)."""
        mock_args.return_value = MagicMock(log_level="WARNING", output_dir=".")
        mock_creds.return_value = ("user", "pass", "R12345")
        mock_workflow_cls.return_value.run.side_effect = AuthenticationError(
            "Login failed"
        )

        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 1, (
            f"Expected exit code 1, got {exc_info.value.code}"
        )
