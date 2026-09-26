"""Unit tests for the OfflineRootCA and Root CA trust ceremony."""

from __future__ import annotations

from pathlib import Path
import pytest

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
from tracecrypt.crypto.pqc_kem import generate_mlkem_keypair
from tracecrypt.crypto.types import KeyPurpose, MLDSAPublicKey
from tracecrypt.errors import CryptographicError, SecurityError
from tracecrypt.identity.ca import OfflineRootCA
from tracecrypt.identity.certificate import CertificateValidator


def test_ca_initialization() -> None:
    """Verify Root CA initialization creates valid ML-DSA-65 keys and fingerprint."""
    ca = OfflineRootCA.initialize(ca_id="ca-root-ceremony-1")

    assert ca.ca_id == "ca-root-ceremony-1"
    assert isinstance(ca.public_key, MLDSAPublicKey)
    assert len(ca.public_key.raw_bytes) == MLDSAPublicKey.EXPECTED_LENGTH
    assert ca.fingerprint.startswith("mldsa65:sha3-256:")


def test_ca_issue_signing_and_kem_certificates() -> None:
    """Verify that Root CA can issue both signing and KEM identity certificates."""
    ca = OfflineRootCA.initialize(ca_id="ca-root-ceremony-2")

    dsa_pk, _ = generate_mldsa_keypair()
    dsa_cert = ca.issue_signing_certificate(
        subject_id="usr-analyst-1",
        public_key=dsa_pk,
        organization="Strategic Analysis Wing",
        role="Investigator",
    )
    assert dsa_cert.key_purpose == KeyPurpose.DIGITAL_SIGNATURE
    CertificateValidator.validate(dsa_cert, ca.public_key)

    kem_pk, _ = generate_mlkem_keypair()
    kem_cert = ca.issue_kem_certificate(
        subject_id="rcp-recipient-1",
        public_key=kem_pk,
        organization="Strategic Analysis Wing",
        role="Recipient",
    )
    assert kem_cert.key_purpose == KeyPurpose.KEY_ENCAPSULATION
    CertificateValidator.validate(kem_cert, ca.public_key)


def test_ca_keystore_save_and_load(tmp_path: Path) -> None:
    """Verify Root CA persistence to Argon2id/AES-GCM keystore and subsequent reload."""
    ca = OfflineRootCA.initialize(ca_id="ca-root-persist")
    passphrase = "UltraSecureOfflineRootPassphrase2026!"
    keystore_file = tmp_path / "ca_root.json"

    ca.save_to_keystore(keystore_file, passphrase)
    assert keystore_file.exists()

    loaded_ca = OfflineRootCA.load_from_keystore(
        keystore_path=keystore_file,
        passphrase=passphrase,
        public_key_bytes=ca.public_key.raw_bytes,
    )

    assert loaded_ca.ca_id == ca.ca_id
    assert loaded_ca.fingerprint == ca.fingerprint

    # Verify that the reloaded CA can issue certificates that validate
    dsa_pk, _ = generate_mldsa_keypair()
    cert = loaded_ca.issue_signing_certificate(
        subject_id="usr-reloaded",
        public_key=dsa_pk,
        organization="AirGap Division",
        role="Operator",
    )
    CertificateValidator.validate(cert, loaded_ca.public_key)


def test_ca_keystore_wrong_password_fails_closed(tmp_path: Path) -> None:
    """Verify that loading Root CA with wrong password fails closed."""
    ca = OfflineRootCA.initialize(ca_id="ca-root-wrong-pw")
    keystore_file = tmp_path / "ca_root.json"
    ca.save_to_keystore(keystore_file, "CorrectPassphrase")

    with pytest.raises((SecurityError, CryptographicError), match="Keystore decryption failed"):
        OfflineRootCA.load_from_keystore(
            keystore_path=keystore_file,
            passphrase="IncorrectPassphrase",
            public_key_bytes=ca.public_key.raw_bytes,
        )
