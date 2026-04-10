"""Tests for steam_totp_extract.workflow module."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from steam_totp_extract.exceptions import AppError, AuthenticatorError
from steam_totp_extract.workflow import ExtractionWorkflow

from .conftest import make_auth_data, make_mock_authenticator


class TestExtractionWorkflow:
    """Tests for ExtractionWorkflow."""

    def test_run_produces_result_with_correct_fields(self, tmp_path: Path) -> None:
        """Successful run returns ExtractionResult with account data and steam URI."""
        mock_auth = make_mock_authenticator()
        workflow = ExtractionWorkflow(authenticator=mock_auth, output_dir=tmp_path)

        result = workflow.run(
            username="testuser",
            password="pass",
            revocation_code="R12345",
            sms_code_provider=lambda: "12345",
        )

        assert result.account_name == "testuser", (
            f"Expected account_name='testuser', got {result.account_name!r}"
        )
        assert result.steamid == "76561198000000000", (
            f"Expected steamid='76561198000000000', got {result.steamid!r}"
        )
        assert result.steam_uri.startswith("steam://"), (
            f"Expected steam URI to start with 'steam://', got {result.steam_uri!r}"
        )
        assert len(result.current_code) == 5, (
            f"Expected 5-char code, got {result.current_code!r}"
        )

    def test_saves_backup_as_json(self, tmp_path: Path) -> None:
        """Run saves a .json backup with shared_secret to the output directory."""
        mock_auth = make_mock_authenticator()
        workflow = ExtractionWorkflow(authenticator=mock_auth, output_dir=tmp_path)
        result = workflow.run("testuser", "pass", "R12345", lambda: "12345")

        backup = Path(result.backup_path)
        assert backup.exists(), f"Backup file not found: {backup}"
        assert backup.suffix == ".json", (
            f"Expected .json extension, got {backup.suffix!r}"
        )
        content = json.loads(backup.read_text())
        assert "shared_secret" in content, (
            f"Backup JSON missing 'shared_secret' key. Keys: {list(content.keys())}"
        )

    def test_backup_filename_includes_steamid(self, tmp_path: Path) -> None:
        """Backup file is named steam_guard_{steamid}.json."""
        mock_auth = make_mock_authenticator()
        workflow = ExtractionWorkflow(authenticator=mock_auth, output_dir=tmp_path)
        result = workflow.run("testuser", "pass", "R12345", lambda: "12345")

        backup = Path(result.backup_path)
        assert backup.name == "steam_guard_76561198000000000.json", (
            f"Expected filename 'steam_guard_76561198000000000.json', "
            f"got {backup.name!r}"
        )

    def test_backup_includes_device_id(self, tmp_path: Path) -> None:
        """Backup JSON includes the device_id field."""
        mock_auth = make_mock_authenticator()
        workflow = ExtractionWorkflow(authenticator=mock_auth, output_dir=tmp_path)
        result = workflow.run("testuser", "pass", "R12345", lambda: "12345")

        content = json.loads(Path(result.backup_path).read_text())
        assert "device_id" in content, (
            f"Backup JSON missing 'device_id'. Keys: {list(content.keys())}"
        )
        assert content["device_id"] == "android:test-uuid", (
            f"Expected device_id='android:test-uuid', got {content['device_id']!r}"
        )

    def test_continues_on_authenticator_removal_failure(self, tmp_path: Path) -> None:
        """Workflow proceeds if remove_authenticator raises AuthenticatorError."""
        mock_auth = make_mock_authenticator()
        mock_auth.remove_authenticator.side_effect = AuthenticatorError(
            "removal failed"
        )
        workflow = ExtractionWorkflow(authenticator=mock_auth, output_dir=tmp_path)

        result = workflow.run("testuser", "pass", "R12345", lambda: "12345")

        assert result.account_name == "testuser", (
            "Workflow should succeed even if removal fails"
        )
        mock_auth.add_authenticator.assert_called_once()

    def test_uses_revocation_code_from_auth_data(self, tmp_path: Path) -> None:
        """Result uses the new revocation_code from AddAuthenticator, not the input."""
        auth_data = make_auth_data(revocation_code="R55555")
        mock_auth = make_mock_authenticator(auth_data=auth_data)
        workflow = ExtractionWorkflow(authenticator=mock_auth, output_dir=tmp_path)

        result = workflow.run("testuser", "pass", "R12345", lambda: "12345")

        assert result.revocation_code == "R55555", (
            f"Expected new revocation_code='R55555', got {result.revocation_code!r}"
        )

    def test_raises_on_empty_username(self, tmp_path: Path) -> None:
        """Empty username raises AppError."""
        workflow = ExtractionWorkflow(output_dir=tmp_path)
        with pytest.raises(AppError, match="Username"):
            workflow.run("", "pass", "R12345")

    def test_raises_on_empty_password(self, tmp_path: Path) -> None:
        """Empty password raises AppError."""
        workflow = ExtractionWorkflow(output_dir=tmp_path)
        with pytest.raises(AppError, match="Password"):
            workflow.run("user", "", "R12345")

    def test_raises_on_empty_revocation_code(self, tmp_path: Path) -> None:
        """Empty revocation code raises AppError."""
        workflow = ExtractionWorkflow(output_dir=tmp_path)
        with pytest.raises(AppError, match="Revocation"):
            workflow.run("user", "pass", "")
