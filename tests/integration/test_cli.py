"""Integration tests for the TraceCrypt CLI."""

import pytest

from tracecrypt.cli.main import main


@pytest.mark.integration
def test_cli_help(capsys: pytest.CaptureFixture[str]):
    exit_code = main(["--help"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "TraceCrypt: Offline Forensic Document Attribution Platform" in captured.out


@pytest.mark.integration
def test_cli_version(capsys: pytest.CaptureFixture[str]):
    exit_code = main(["version"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "TraceCrypt v1.0.0" in captured.out or "TraceCrypt v0.1.0" in captured.out
    assert "FIPS 203" in captured.out
    assert "FIPS 204" in captured.out


@pytest.mark.integration
def test_cli_doctor(capsys: pytest.CaptureFixture[str]):
    exit_code = main(["doctor"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Running TraceCrypt System Doctor" in captured.out
    assert "ALL CHECKS PASSED" in captured.out


@pytest.mark.integration
def test_cli_config_validate(capsys: pytest.CaptureFixture[str]):
    exit_code = main(["config", "validate"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "VALID (Security Invariants Upheld)" in captured.out


@pytest.mark.integration
def test_cli_security_airgap(capsys: pytest.CaptureFixture[str]):
    exit_code = main(["security", "airgap-check"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Air-Gap Status: COMPLIANT" in captured.out
