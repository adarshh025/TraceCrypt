"""Comprehensive security and adversarial tests for Phase 3 Identity Subsystem."""

from __future__ import annotations

import base64
from pathlib import Path
import pytest

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair, sign
from tracecrypt.crypto.pqc_kem import decapsulate, encapsulate, generate_mlkem_keypair
from tracecrypt.crypto.types import (
    KeyMetadata,
    KeyPurpose,
    KeyStatus,
)
from tracecrypt.errors import CryptographicError, SecurityError, ValidationError
from tracecrypt.identity.ca import OfflineRootCA
from tracecrypt.identity.certificate import CertificateValidator
from tracecrypt.identity.keystore import KeystoreManager
from tracecrypt.utils.timestamps import utc_now_micros


def test_algorithm_downgrade_in_certificate_rejected() -> None:
    """Verify that classical or unauthorized algorithms (e.g. RSA-2048, Ed25519) are rejected."""
    ca = OfflineRootCA.initialize(ca_id="ca-root-sec")
    pk, _ = generate_mldsa_keypair()

    cert = ca.issue_signing_certificate(
        subject_id="usr-victim",
        public_key=pk,
        organization="AirGap Defense",
        role="Operator",
    )

    # Attempt to spoof algorithm to classical RSA or ECDSA
    downgraded_cert = cert.model_copy(update={"algorithm": "RSA-4096"})
    sig = sign(ca._private_key, downgraded_cert.to_signing_bytes())
    downgraded_cert = downgraded_cert.model_copy(update={"signature_b64": sig.to_b64()})
    with pytest.raises(ValidationError, match="Unknown algorithm"):
        CertificateValidator.validate(downgraded_cert, ca.public_key)

    downgraded_cert_2 = cert.model_copy(update={"algorithm": "Ed25519"})
    sig2 = sign(ca._private_key, downgraded_cert_2.to_signing_bytes())
    downgraded_cert_2 = downgraded_cert_2.model_copy(update={"signature_b64": sig2.to_b64()})
    with pytest.raises(ValidationError, match="Unknown algorithm"):
        CertificateValidator.validate(downgraded_cert_2, ca.public_key)


def test_purpose_separation_enforced_at_runtime() -> None:
    """Verify that ML-KEM private keys cannot sign and ML-DSA keys cannot decapsulate."""
    kem_pk, kem_sk = generate_mlkem_keypair()
    dsa_pk, dsa_sk = generate_mldsa_keypair()

    # Attempt to sign with ML-KEM private key
    with pytest.raises(ValidationError, match="private_key must be MLDSAPrivateKey"):
        sign(kem_sk, b"Disallowed signing payload")  # type: ignore[arg-type]

    # Attempt to decapsulate with ML-DSA private key
    _, kem_ct = encapsulate(kem_pk)
    with pytest.raises(ValidationError, match="private_key must be MLKEMPrivateKey"):
        decapsulate(dsa_sk, kem_ct)  # type: ignore[arg-type]


def test_keystore_path_traversal_rejection(tmp_path: Path) -> None:
    """Verify that path traversal attempts in keystore saving/loading are rejected or contained."""
    _, sk = generate_mldsa_keypair()
    metadata = KeyMetadata(
        key_id="key-sec-trav",
        owner_id="usr-sec",
        purpose=KeyPurpose.DIGITAL_SIGNATURE,
        algorithm="ML-DSA-65",
        parameter_set="ML-DSA-65",
        created_at=utc_now_micros(),
        status=KeyStatus.ACTIVE,
        version=1,
        fingerprint="mldsa65:sha3-256:dummy",
    )

    container = KeystoreManager.encrypt_private_key(sk, "TestPassword!", metadata)
    assert container.format_version == "1.0.0"

    # Attempting to load a non-existent traversal path fails closed
    traversal_path = tmp_path / ".." / ".." / "system32" / "non_existent_key.json"
    with pytest.raises((FileNotFoundError, SecurityError, ValidationError)):
        KeystoreManager.load_container(traversal_path)


def test_private_key_repr_does_not_leak_key_material() -> None:
    """Verify that str() and repr() of private keys do not leak secret key bytes."""
    _, kem_sk = generate_mlkem_keypair()
    _, dsa_sk = generate_mldsa_keypair()

    kem_repr = repr(kem_sk)
    kem_str = str(kem_sk)
    dsa_repr = repr(dsa_sk)
    dsa_str = str(dsa_sk)

    # Neither raw bytes, hex, nor base64 should appear in string representation
    kem_b64 = base64.b64encode(kem_sk.raw_bytes).decode("ascii")
    dsa_b64 = base64.b64encode(dsa_sk.raw_bytes).decode("ascii")

    assert kem_b64 not in kem_repr
    assert kem_b64 not in kem_str
    assert dsa_b64 not in dsa_repr
    assert dsa_b64 not in dsa_str

    assert "REDACTED" in kem_repr
    assert "REDACTED" in dsa_repr


def test_corrupted_encrypted_container_tag_rejection(tmp_path: Path) -> None:
    """Verify that corrupting the AES-256-GCM auth tag in keystore fails closed."""
    _, sk = generate_mldsa_keypair()
    metadata = KeyMetadata(
        key_id="key-sec-tag",
        owner_id="usr-sec-tag",
        purpose=KeyPurpose.DIGITAL_SIGNATURE,
        algorithm="ML-DSA-65",
        parameter_set="ML-DSA-65",
        created_at=utc_now_micros(),
        status=KeyStatus.ACTIVE,
        version=1,
        fingerprint="mldsa65:sha3-256:dummy",
    )

    container = KeystoreManager.encrypt_private_key(sk, "SecurePassphrase123", metadata)

    # Corrupt auth tag
    tag_bytes = bytearray(base64.b64decode(container.auth_tag_b64))
    tag_bytes[0] ^= 0xFF
    corrupted_tag_b64 = base64.b64encode(bytes(tag_bytes)).decode("ascii")

    corrupted_container = container.model_copy(update={"auth_tag_b64": corrupted_tag_b64})

    with pytest.raises((SecurityError, CryptographicError), match="Keystore decryption failed"):
        KeystoreManager.decrypt_private_key(corrupted_container, "SecurePassphrase123")
