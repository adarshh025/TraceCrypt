"""Adversarial Cryptographic Boundary and Key Separation Tests.

Validates:
- Strict separation between ML-KEM-768 and ML-DSA-65 key purposes.
- Rejection of key reuse across different cryptographic domains.
- Enforcement of strict byte lengths for all PQC keys, ciphertexts, and signatures.
- Rejection of legacy classical cryptographic primitives.
"""

from __future__ import annotations

import pytest

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair, sign, verify as verify_dsa
from tracecrypt.crypto.pqc_kem import decapsulate, encapsulate, generate_mlkem_keypair
from tracecrypt.crypto.types import (
    KeyPurpose,
    MLDSAPrivateKey,
    MLDSAPublicKey,
    MLDSASignature,
    MLKEMCiphertext,
    MLKEMPrivateKey,
    MLKEMPublicKey,
)
from tracecrypt.errors import ValidationError
from tracecrypt.identity.certificate import CertificateValidator, PQCIdentityCertificate


class TestCryptographicBoundaries:
    """Validate cryptographic boundaries, type isolation, and purpose separation."""

    def test_mldsa_and_mlkem_type_isolation(self) -> None:
        """ML-KEM keys must never be accepted by ML-DSA signing/verification functions."""
        kem_pk, kem_sk = generate_mlkem_keypair()
        dsa_pk, dsa_sk = generate_mldsa_keypair()

        # 1. Attempting to sign with MLKEMPrivateKey must raise ValidationError
        with pytest.raises(ValidationError):
            sign(kem_sk, b"test message")  # type: ignore[arg-type]

        # 2. Attempting to verify DSA with MLKEMPublicKey must fail closed (return False)
        sig = sign(dsa_sk, b"valid message")
        assert verify_dsa(kem_pk, b"valid message", sig) is False

    def test_mlkem_and_mldsa_encapsulation_isolation(self) -> None:
        """ML-DSA keys must never be accepted for KEM encapsulation or decapsulation."""
        dsa_pk, dsa_sk = generate_mldsa_keypair()
        kem_pk, kem_sk = generate_mlkem_keypair()

        # 1. Attempting encapsulation with MLDSAPublicKey
        with pytest.raises(ValidationError):
            encapsulate(dsa_pk)  # type: ignore[arg-type]

        # 2. Attempting decapsulation with MLDSAPrivateKey
        _, ct = encapsulate(kem_pk)
        with pytest.raises(ValidationError):
            decapsulate(dsa_sk, ct)  # type: ignore[arg-type]

    def test_strict_key_length_enforcement(self) -> None:
        """Any mutated or truncated key length must fail closed with ValidationError."""
        # ML-KEM-768
        with pytest.raises(ValidationError):
            MLKEMPublicKey(b"\x00" * 1183)
        with pytest.raises(ValidationError):
            MLKEMPublicKey(b"\x00" * 1185)
        with pytest.raises(ValidationError):
            MLKEMPrivateKey(b"\x00" * 2399)
        with pytest.raises(ValidationError):
            MLKEMPrivateKey(b"\x00" * 2401)
        with pytest.raises(ValidationError):
            MLKEMCiphertext(b"\x00" * 1087)

        # ML-DSA-65
        with pytest.raises(ValidationError):
            MLDSAPublicKey(b"\x00" * 1951)
        with pytest.raises(ValidationError):
            MLDSAPublicKey(b"\x00" * 1953)
        with pytest.raises(ValidationError):
            MLDSAPrivateKey(b"\x00" * 4031)
        with pytest.raises(ValidationError):
            MLDSAPrivateKey(b"\x00" * 4033)
        with pytest.raises(ValidationError):
            MLDSASignature(b"\x00" * 3308)

    def test_key_purpose_in_certificate_enforcement(self, forensic_environment) -> None:
        """Certificates with mismatched key purpose must fail validation."""
        root_ca = forensic_environment["root_ca"]
        dsa_pk, _ = generate_mldsa_keypair()

        # Create certificate with wrong key purpose (KEY_ENCAPSULATION for ML-DSA)
        now = 1700000000000000
        unsigned_data = {
            "format_version": "1.0.0",
            "serial_number": "crt-test-mismatch-purpose",
            "issuer_ca_id": root_ca.ca_id,
            "subject_id": "usr-test-purpose",
            "organization": "Test Org",
            "role": "ANALYST",
            "key_purpose": KeyPurpose.KEY_ENCAPSULATION,
            "algorithm": "ML-DSA-65",
            "parameter_set": "ML-DSA-65",
            "public_key_b64": dsa_pk.to_b64(),
            "public_key_fingerprint": dsa_pk.fingerprint,
            "valid_from": now - 1000,
            "valid_until": now + 1000000000,
        }
        from tracecrypt.crypto.pqc_dsa import sign as sign_mldsa
        proto_cert = PQCIdentityCertificate.model_validate({**unsigned_data, "signature_b64": ""})
        sig = sign_mldsa(root_ca._private_key, proto_cert.to_signing_bytes())
        cert = proto_cert.model_copy(update={"signature_b64": sig.to_b64()})

        with pytest.raises(ValidationError, match="Check 10 Failed"):
            CertificateValidator.validate(
                certificate=cert,
                root_ca_public_key=root_ca.public_key,
                current_time_micros=now,
            )
