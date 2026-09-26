"""Integration tests for identity and CA CLI subcommands."""

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
    StorageConfig,
    reset_settings,
)


@pytest.fixture
def cli_isolated_env(tmp_path: Path):
    """Provide isolated configuration for CLI execution."""
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


def test_cli_ca_init_and_status(cli_isolated_env, capsys) -> None:
    """Verify Root CA initialization and status inspection via CLI."""
    # 1. Check status before init
    ret_uninit = main(["ca", "status"])
    out_uninit = capsys.readouterr().out
    assert ret_uninit == 0
    assert "UNINITIALIZED" in out_uninit

    # 2. Init CA
    ret_init = main(["ca", "init", "--ca-id", "ca-root-cli", "--passphrase", "MasterPass123!"])
    out_init = capsys.readouterr().out
    assert ret_init == 0
    assert "Root CA Initialized Successfully" in out_init

    # 3. Check status after init
    ret_active = main(["ca", "status"])
    out_active = capsys.readouterr().out
    assert ret_active == 0
    assert "ca-root-cli" in out_active
    assert "ACTIVE" in out_active


def test_cli_identity_generate_list_inspect_verify(cli_isolated_env, capsys) -> None:
    """Verify full recipient generation, list, inspect, and verify flow via CLI."""
    # Initialize CA
    main(["ca", "init", "--ca-id", "ca-root-test", "--passphrase", "MasterPass123!"])
    capsys.readouterr()

    # Generate recipient identity
    ret_gen = main([
        "identity", "generate",
        "--recipient-id", "rcp-cli-alice",
        "--organization", "Cyber Directorate",
        "--role", "Forensic Officer",
        "--passphrase", "AlicePassword456!",
        "--ca-passphrase", "MasterPass123!",
    ])
    out_gen = capsys.readouterr().out
    assert ret_gen == 0
    assert "Identity Generated & Certified Successfully" in out_gen
    assert "rcp-cli-alice" in out_gen

    # List identities
    ret_list = main(["identity", "list"])
    out_list = capsys.readouterr().out
    assert ret_list == 0
    assert "rcp-cli-alice" in out_list

    # Inspect recipient
    ret_insp = main(["identity", "inspect", "--recipient-id", "rcp-cli-alice"])
    out_insp = capsys.readouterr().out
    assert ret_insp == 0
    assert "rcp-cli-alice" in out_insp
    assert "Cyber Directorate" in out_insp

    # Verify certificate file
    keys_dir = cli_isolated_env.storage.keys_dir
    dsa_cert_file = keys_dir / "rcp-cli-alice_dsa_cert.json"
    assert dsa_cert_file.exists()

    ret_ver = main(["identity", "verify", "--cert-file", str(dsa_cert_file)])
    out_ver = capsys.readouterr().out
    assert ret_ver == 0
    assert "CERTIFICATE IS VALID" in out_ver


def test_cli_key_fingerprint(cli_isolated_env, capsys) -> None:
    """Verify public key fingerprint inspection via CLI."""
    main(["ca", "init", "--ca-id", "ca-root-test", "--passphrase", "MasterPass123!"])
    capsys.readouterr()

    keys_dir = cli_isolated_env.storage.keys_dir
    ca_pub_file = keys_dir / "ca_root_pub.bin"
    assert ca_pub_file.exists()

    ret = main(["key", "fingerprint", "--key-file", str(ca_pub_file)])
    out = capsys.readouterr().out
    assert ret == 0
    assert "mldsa65:sha3-256:" in out
