"""Integration tests for identity and CA FastAPI endpoints."""

from __future__ import annotations

import json
from pathlib import Path
import pytest
from starlette.testclient import TestClient

from tracecrypt.api.app import create_app
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
from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
from tracecrypt.crypto.types import KeyMetadata, KeyPurpose, KeyStatus
from tracecrypt.identity.ca import OfflineRootCA
from tracecrypt.storage.sqlite_store import SQLiteStorageManager
from tracecrypt.utils.timestamps import utc_now_micros


@pytest.fixture
def api_isolated_env(tmp_path: Path):
    """Provide isolated configuration and storage for API testing."""
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    keys_dir = data_dir / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)

    settings = Settings(
        mode=AppMode.TEST,
        airgap=AirGapConfig(enforce_airgap=False, allow_dns=True),
        storage=StorageConfig(
            base_dir=data_dir,
            keys_dir=keys_dir,
            documents_dir=data_dir / "documents",
            ledger_dir=data_dir / "ledger",
            reports_dir=data_dir / "reports",
            sqlite_db_path=data_dir / "api_test.db",
        ),
        ledger=LedgerConfig(),
        crypto=CryptoConfig(),
        logging=LoggingConfig(redact_secrets=True),
    )
    reset_settings(settings)
    yield settings
    reset_settings(None)


def test_api_ca_status_uninitialized(api_isolated_env) -> None:
    """Verify /ca/status returns uninitialized before CA ceremony."""
    app = create_app()
    client = TestClient(app)

    response = client.get("/ca/status")
    assert response.status_code == 200
    data = response.json()
    assert data["initialized"] is False
    assert data["status"] == "UNINITIALIZED"


def test_api_ca_and_identity_endpoints(api_isolated_env) -> None:
    """Verify full suite of identity endpoints on initialized system."""
    settings = api_isolated_env
    store = SQLiteStorageManager(settings.storage.sqlite_db_path)
    store.initialize()

    # 1. Initialize and save CA
    ca = OfflineRootCA.initialize(ca_id="ca-root-api-test")
    ca_pass = "Capassword123!"
    ca_cert = ca.issue_signing_certificate(
        subject_id="ca-root-api-test",
        public_key=ca.public_key,
        organization="TraceCrypt Authority",
        role="Root CA",
        validity_days=3650,
    )
    ca_cert_file = settings.storage.keys_dir / "ca_root_cert.json"
    ca_cert_file.write_text(ca_cert.to_canonical_json(), encoding="utf-8")
    ca_keystore = settings.storage.keys_dir / "ca_root.json"
    ca.save_to_keystore(ca_keystore, ca_pass)

    # 2. Issue and persist a recipient certificate and key metadata
    dsa_pk, _ = generate_mldsa_keypair()
    rcp_cert = ca.issue_signing_certificate(
        subject_id="rcp-api-charlie",
        public_key=dsa_pk,
        organization="Cyber Intelligence",
        role="Agent",
        validity_days=30,
        device_id="dev-sec-01",
    )
    store.save_certificate(rcp_cert)

    meta = KeyMetadata(
        key_id="key-charlie-dsa-1",
        owner_id="rcp-api-charlie",
        purpose=KeyPurpose.DIGITAL_SIGNATURE,
        algorithm="ML-DSA-65",
        parameter_set="ML-DSA-65",
        created_at=utc_now_micros(),
        status=KeyStatus.ACTIVE,
        version=1,
        fingerprint=dsa_pk.fingerprint,
    )
    store.save_key_metadata(meta, str(settings.storage.keys_dir / "charlie_dsa.json"))

    # Test API
    app = create_app()
    client = TestClient(app)

    # Check /ca/status
    res_ca = client.get("/ca/status")
    assert res_ca.status_code == 200
    assert res_ca.json()["initialized"] is True
    assert res_ca.json()["ca_id"] == "ca-root-api-test"

    # Check /identity/status
    res_status = client.get("/identity/status")
    assert res_status.status_code == 200
    data_status = res_status.json()
    assert data_status["total_enrolled_subjects"] == 1
    assert data_status["total_certificates"] == 1
    assert data_status["total_tracked_keys"] == 1

    # Check /identity/recipients
    res_rcps = client.get("/identity/recipients")
    assert res_rcps.status_code == 200
    assert "rcp-api-charlie" in res_rcps.json()["recipients"]

    # Check /identity/recipients/{id}
    res_rcp = client.get("/identity/recipients/rcp-api-charlie")
    assert res_rcp.status_code == 200
    rcp_data = res_rcp.json()
    assert rcp_data["recipient_id"] == "rcp-api-charlie"
    assert len(rcp_data["certificates"]) == 1
    assert rcp_data["certificates"][0]["serial_number"] == rcp_cert.serial_number

    # Check /identity/keys/{id}
    res_key = client.get("/identity/keys/key-charlie-dsa-1")
    assert res_key.status_code == 200
    key_data = res_key.json()
    assert key_data["key_id"] == "key-charlie-dsa-1"
    assert key_data["purpose"] == "DIGITAL_SIGNATURE"
    # Ensure no private key or keystore path in response
    assert "private" not in key_data
    assert "keystore_path" not in key_data

    # Check /identity/verify
    res_verify = client.post(
        "/identity/verify",
        json={"certificate": json.loads(rcp_cert.to_canonical_json())},
    )
    assert res_verify.status_code == 200
    assert res_verify.json()["valid"] is True
    assert res_verify.json()["serial_number"] == rcp_cert.serial_number


def test_api_admin_token_authorization(api_isolated_env, monkeypatch) -> None:
    """Verify that setting TRACECRYPT_ADMIN_TOKEN requires authorization."""
    monkeypatch.setenv("TRACECRYPT_ADMIN_TOKEN", "SuperSecretToken-999")
    app = create_app()
    client = TestClient(app)

    # Missing token -> 401
    res_unauth = client.get("/identity/status")
    assert res_unauth.status_code == 401

    # Invalid token -> 401
    res_bad = client.get("/identity/status", headers={"Authorization": "Bearer wrong"})
    assert res_bad.status_code == 401

    # Valid token via Bearer -> 200
    res_bearer = client.get(
        "/identity/status",
        headers={"Authorization": "Bearer SuperSecretToken-999"},
    )
    assert res_bearer.status_code == 200

    # Valid token via X-TraceCrypt-Admin-Token header -> 200
    res_custom = client.get(
        "/identity/status",
        headers={"X-TraceCrypt-Admin-Token": "SuperSecretToken-999"},
    )
    assert res_custom.status_code == 200
