"""Integration tests for document packaging, validation, and CLI commands."""

from __future__ import annotations

from pathlib import Path
import pytest

from tracecrypt.cli.main import main
from tracecrypt.config.settings import (
    AirGapConfig,
    AppMode,
    CryptoConfig,
    LedgerConfig,
    LoggingConfig,
    Settings,
    reset_settings,
    StorageConfig,
)


@pytest.fixture
def cli_isolated_env(tmp_path: Path):
    """Provide isolated configuration for document CLI execution."""
    data_dir = tmp_path / "data"
    settings = Settings(
        mode=AppMode.TEST,
        airgap=AirGapConfig(enforce_airgap=False, allow_dns=True),
        storage=StorageConfig(
            base_dir=data_dir,
            keys_dir=data_dir / "keys",
            documents_dir=data_dir / "documents",
            ledger_dir=data_dir / "ledger",
            reports_dir=data_dir / "reports",
            sqlite_db_path=data_dir / "test_local.db",
        ),
        ledger=LedgerConfig(),
        crypto=CryptoConfig(),
        logging=LoggingConfig(redact_secrets=True),
    )
    reset_settings(settings)
    yield settings
    reset_settings(None)


def test_cli_document_hash_and_inspect(cli_isolated_env, tmp_path: Path, capsys) -> None:
    """Verify document hash and inspect commands on source files."""
    doc_path = tmp_path / "sample.pdf"
    doc_path.write_bytes(b"%PDF-1.7\nSample content for hashing test\n")

    # 1. document hash
    ret = main(["document", "hash", str(doc_path)])
    out = capsys.readouterr().out
    assert ret == 0
    assert "Algorithm: SHA3-256" in out
    assert "Digest:" in out

    # 2. document inspect (source file)
    ret = main(["document", "inspect", str(doc_path)])
    out = capsys.readouterr().out
    assert ret == 0
    assert "Source Document Inspection" in out
    assert "application/pdf" in out
    assert str(doc_path.name) in out


def test_cli_document_packaging_and_validation(cli_isolated_env, tmp_path: Path, capsys) -> None:
    """End-to-end CLI workflow: CA init -> identity gen -> document package -> inspect -> validate -> decrypt."""
    # 1. Initialize Root CA
    ca_pass = "MasterCAPassphrase123!"
    ret = main(["ca", "init", "--ca-id", "ca-root-cli", "--passphrase", ca_pass])
    assert ret == 0
    capsys.readouterr()

    # 2. Generate identity for Alice
    alice_id = "rcp-a1b2c3d4e5f60718293a4b5c6d7e8f90"
    alice_pass = "AliceSecurePass123!"
    ret = main([
        "identity", "generate",
        "--owner-id", alice_id,
        "--passphrase", alice_pass,
        "--ca-passphrase", ca_pass,
    ])
    assert ret == 0
    capsys.readouterr()

    # 3. Create document to package
    doc_file = tmp_path / "confidential_brief.pdf"
    doc_file.write_bytes(b"%PDF-1.7\nRESTRICTED BRIEFING CONTENT\n" + b"A" * 512)
    pkg_file = tmp_path / "confidential_brief.pdf.tcdist"

    # 4. Package document for Alice
    ret = main([
        "document", "package",
        "--input", str(doc_file),
        "--output", str(pkg_file),
        "--recipient", alice_id,
    ])
    out = capsys.readouterr().out
    assert ret == 0
    assert "[SUCCESS] Created TraceCrypt Distribution Package" in out
    assert pkg_file.exists()

    # 5. Inspect package
    ret = main(["document", "inspect", str(pkg_file)])
    out = capsys.readouterr().out
    assert ret == 0
    assert "TraceCrypt Distribution Package (.tcdist)" in out
    assert alice_id in out
    assert "AES-256-GCM" in out
    assert "ML-KEM-768" in out

    # 6. List recipients
    ret = main(["document", "recipients", str(pkg_file)])
    out = capsys.readouterr().out
    assert ret == 0
    assert alice_id in out
    assert "Total Envelopes:  1" in out

    # 7. Validate package
    ret = main(["document", "validate", str(pkg_file)])
    out = capsys.readouterr().out
    assert ret == 0
    assert "[PASS] Package is cryptographically valid and untampered." in out

    # 8. Decrypt without --dev-mode (must fail with security notice)
    ret = main([
        "document", "decrypt", str(pkg_file),
        "--recipient-id", alice_id,
        "--passphrase", alice_pass,
    ])
    out = capsys.readouterr().out
    assert ret == 1
    assert "ERROR: Direct CLI decryption without forensic pipeline is restricted" in out

    # 9. Decrypt with --dev-mode (allowed test path)
    out_dec = tmp_path / "decrypted.pdf"
    ret = main([
        "document", "decrypt", str(pkg_file),
        "--recipient-id", alice_id,
        "--passphrase", alice_pass,
        "--output", str(out_dec),
        "--dev-mode",
    ])
    out = capsys.readouterr().out
    assert ret == 0
    assert "[WARNING] RUNNING IN RESTRICTED DEVELOPMENT/TEST MODE" in out
    assert "[SUCCESS] Cryptographic decryption and SHA3-256 verification SUCCEEDED." in out
    assert out_dec.read_bytes() == doc_file.read_bytes()

    # 10. Decrypt with incorrect passphrase fails
    ret = main([
        "document", "decrypt", str(pkg_file),
        "--recipient-id", alice_id,
        "--passphrase", "WrongPassphrase123!",
        "--dev-mode",
    ])
    out = capsys.readouterr().out
    assert ret == 1
    assert "Decryption failed:" in out
