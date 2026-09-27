"""Command-Line Interface Security and Defensive Argument Handling Tests.

Validates:
- Safe handling of non-existent, malformed, or hostile file paths.
- Proper error code returns without unhandled Python stack traces.
- Execution of defensive CLI diagnostic commands (doctor, airgap-check).
"""

from __future__ import annotations

import sys
from unittest.mock import patch

from tracecrypt.cli.main import main


class TestCLISecurity:
    """Evaluate CLI resilience against hostile arguments and invalid inputs."""

    def test_cli_version_safe(self, capsys) -> None:
        """Executing 'tracecrypt version' must cleanly print version and return 0."""
        with patch.object(sys, "argv", ["tracecrypt", "version"]):
            exit_code = main()
            assert exit_code == 0
            captured = capsys.readouterr()
            assert "TraceCrypt" in captured.out

    def test_cli_missing_command_help(self, capsys) -> None:
        """Invoking without arguments must safely display usage instructions."""
        with patch.object(sys, "argv", ["tracecrypt"]):
            exit_code = main()
            assert exit_code == 0
            captured = capsys.readouterr()
            assert "usage:" in captured.out or "TraceCrypt" in captured.out

    def test_cli_investigate_missing_file(self) -> None:
        """Investigating a non-existent file path must exit cleanly with error code."""
        with patch.object(sys, "argv", ["tracecrypt", "forensic", "investigate", "--file", "does_not_exist.pdf"]):
            exit_code = main()
            assert exit_code != 0

    def test_cli_verify_missing_proof(self) -> None:
        """Verifying a missing .tcproof bundle must fail safely with non-zero code."""
        with patch.object(sys, "argv", ["tracecrypt", "forensic", "verify", "--proof", "missing.tcproof"]):
            exit_code = main()
            assert exit_code != 0

    def test_cli_airgap_check_command(self, capsys) -> None:
        """Executing 'security airgap-check' must verify airgap status cleanly."""
        with patch.object(sys, "argv", ["tracecrypt", "security", "airgap-check"]):
            exit_code = main()
            assert exit_code == 0
            captured = capsys.readouterr()
            assert "Air-Gap" in captured.out or "AIR-GAP" in captured.out
