"""Integration tests for document packaging, inspection, and validation API endpoints."""

from __future__ import annotations

import base64
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
    reset_settings,
    StorageConfig,
)
from tracecrypt.crypto.pqc_kem import generate_mlkem_keypair
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.crypto.types import KeyMetadata, KeyPurpose, KeyStatus
from tracecrypt.identity.ca import OfflineRootCA
from tracecrypt.identity.keystore import KeystoreManager
from tracecrypt.storage.sqlite_store import SQLiteStorageManager
from tracecrypt.utils.identifiers import RecipientID
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


@pytest.fixture
def setup_pki(api_isolated_env):
    """Initialize Root CA and enroll a test recipient."""
    settings = api_isolated_env
    store = SQLiteStorageManager(settings.storage.sqlite_db_path)
    store.initialize()

    ca = OfflineRootCA.initialize(ca_id="ca-root-api-test")
    ca_pass = "Capassword123!"
    ca_cert = ca.issue_signing_certificate(
        subject_id="ca-root-api-test",
        public_key=ca.public_key,
        organization="TraceCrypt Authority",
        role="ROOT_CA",
    )
    # Save root cert to keys dir for node validation
    root_cert_file = settings.storage.keys_dir / "ca_root_cert.json"
    root_cert_file.write_text(ca_cert.to_canonical_json(), encoding="utf-8")
    ca.save_to_keystore(settings.storage.keys_dir / "ca_root.json", ca_pass)

    # Enroll Alice
    alice_id = str(SecureRandom.generate_typed_id(RecipientID))
    alice_pk, alice_sk = generate_mlkem_keypair()
    alice_cert = ca.issue_kem_certificate(
        subject_id=alice_id,
        public_key=alice_pk,
        organization="Test Operations",
        role="RECIPIENT",
        validity_days=30,
    )
    store.save_certificate(alice_cert)

    # Save Alice's keystore
    now = utc_now_micros()
    meta = KeyMetadata(
        key_id=f"key-{alice_id}-kem",
        owner_id=alice_id,
        purpose=KeyPurpose.KEY_ENCAPSULATION,
        algorithm="ML-KEM-768",
        parameter_set="ML-KEM-768",
        created_at=now,
        status=KeyStatus.ACTIVE,
        version=1,
        fingerprint=alice_pk.fingerprint,
    )
    passphrase = "AliceSecurePass123!"
    container = KeystoreManager.encrypt_private_key(alice_sk, passphrase, meta)
    keystore_path = settings.storage.keys_dir / f"{alice_id}_kem_keystore.json"
    KeystoreManager.save_container(container, keystore_path)
    store.save_key_metadata(meta, str(keystore_path))

    return {
        "ca": ca,
        "store": store,
        "alice_id": alice_id,
        "alice_cert": alice_cert,
        "alice_sk": alice_sk,
        "container_json": container.model_dump_json(),
        "passphrase": passphrase,
    }


def test_api_package_and_metadata_flow(setup_pki) -> None:
    """Verify document packaging and metadata retrieval via FastAPI endpoints."""
    app = create_app()
    client = TestClient(app)
    alice_id = setup_pki["alice_id"]

    sample_doc = b"%PDF-1.7\nSENSITIVE FINANCIAL AUDIT 2026\n" + b"B" * 1024
    doc_b64 = base64.b64encode(sample_doc).decode("ascii")

    # 1. POST /documents/package
    pkg_payload = {
        "document_bytes_b64": doc_b64,
        "filename": "audit.pdf",
        "mime_type": "application/pdf",
        "recipient_ids": [alice_id],
    }
    resp = client.post("/documents/package", json=pkg_payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "distribution_id" in data
    assert "document_id" in data
    assert data["filename"] == "audit.pdf"
    assert data["source_size_bytes"] == len(sample_doc)
    assert data["recipient_count"] == 1
    assert "package_bytes_b64" in data
    assert "aes_key" not in data
    assert "cek" not in data
    assert "shared_secret" not in data

    doc_id = data["document_id"]
    pkg_b64 = data["package_bytes_b64"]

    # 2. GET /documents/{document_id}
    meta_resp = client.get(f"/documents/{doc_id}")
    assert meta_resp.status_code == 200
    meta_data = meta_resp.json()
    assert meta_data["document_id"] == doc_id
    assert meta_data["title"] == "audit.pdf"
    assert meta_data["file_size_bytes"] == len(sample_doc)
    assert "aes_key" not in meta_data

    # 3. GET /documents/nonexistent returns 404
    not_found = client.get("/documents/doc-00000000000000000000000000000000")
    assert not_found.status_code == 404

    # 4. POST /documents/validate
    val_resp = client.post("/documents/validate", json={"package_bytes_b64": pkg_b64})
    assert val_resp.status_code == 200
    val_data = val_resp.json()
    assert val_data["valid"] is True
    assert val_data["distribution_id"] == data["distribution_id"]
    assert val_data["recipient_count"] == 1
    assert val_data["errors"] == []

    # 5. POST /documents/validate with corrupted package
    corrupted_bytes = bytearray(base64.b64decode(pkg_b64))
    corrupted_bytes[20] ^= 0xFF
    corrupted_b64 = base64.b64encode(corrupted_bytes).decode("ascii")
    bad_val_resp = client.post("/documents/validate", json={"package_bytes_b64": corrupted_b64})
    assert bad_val_resp.status_code == 200
    bad_val_data = bad_val_resp.json()
    assert bad_val_data["valid"] is False
    assert len(bad_val_data["errors"]) > 0


def test_api_decrypt_validate_endpoint(setup_pki) -> None:
    """Verify decryption feasibility testing endpoint."""
    app = create_app()
    client = TestClient(app)
    alice_id = setup_pki["alice_id"]

    sample_doc = b"%PDF-1.7\nOPERATIONAL SCHEDULING DISPATCH\n"
    doc_b64 = base64.b64encode(sample_doc).decode("ascii")

    # Package for Alice
    pkg_resp = client.post(
        "/documents/package",
        json={
            "document_bytes_b64": doc_b64,
            "filename": "dispatch.pdf",
            "recipient_ids": [alice_id],
        },
    )
    assert pkg_resp.status_code == 200
    pkg_b64 = pkg_resp.json()["package_bytes_b64"]

    # 1. Validate decryption for authorized Alice (without private key provided)
    auth_resp = client.post(
        "/documents/decrypt/validate",
        json={"package_bytes_b64": pkg_b64, "recipient_id": alice_id},
    )
    assert auth_resp.status_code == 200
    auth_data = auth_resp.json()
    assert auth_data["can_decrypt"] is True
    assert auth_data["envelope_found"] is True
    assert auth_data["certificate_valid"] is True

    # 2. Validate decryption for unauthorized recipient
    eve_id = "rcp-99999999999999999999999999999999"
    unauth_resp = client.post(
        "/documents/decrypt/validate",
        json={"package_bytes_b64": pkg_b64, "recipient_id": eve_id},
    )
    assert unauth_resp.status_code == 200
    unauth_data = unauth_resp.json()
    assert unauth_data["can_decrypt"] is False
    assert unauth_data["envelope_found"] is False

    # 3. Test cryptographic check with keystore and correct passphrase
    crypto_resp = client.post(
        "/documents/decrypt/validate",
        json={
            "package_bytes_b64": pkg_b64,
            "recipient_id": alice_id,
            "keystore_json": setup_pki["container_json"],
            "passphrase": setup_pki["passphrase"],
        },
    )
    assert crypto_resp.status_code == 200
    crypto_data = crypto_resp.json()
    assert crypto_data["can_decrypt"] is True
    assert crypto_data["cryptographic_check_passed"] is True
    # Ensure plaintext is never returned
    assert "plaintext" not in crypto_data
    assert "content" not in crypto_data

    # 4. Test cryptographic check with wrong passphrase fails
    bad_pass_resp = client.post(
        "/documents/decrypt/validate",
        json={
            "package_bytes_b64": pkg_b64,
            "recipient_id": alice_id,
            "keystore_json": setup_pki["container_json"],
            "passphrase": "WrongPassphrase999!",
        },
    )
    assert bad_pass_resp.status_code == 200
    bad_pass_data = bad_pass_resp.json()
    assert bad_pass_data["can_decrypt"] is False
    assert bad_pass_data["cryptographic_check_passed"] is False
