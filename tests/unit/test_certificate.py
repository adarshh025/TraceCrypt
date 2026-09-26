"""Unit and security tests for PQC Identity Certificates and 12-point offline validation."""

from __future__ import annotations

import base64
import pytest

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair, sign as sign_mldsa
from tracecrypt.crypto.pqc_kem import generate_mlkem_keypair
from tracecrypt.crypto.types import KeyPurpose
from tracecrypt.errors import SecurityError, ValidationError
from tracecrypt.identity.ca import OfflineRootCA
from tracecrypt.identity.certificate import CertificateValidator


class DummyRevocationProvider:
    """Mock revocation provider for testing offline revocation checks."""

    def __init__(self, revoked_serials: set[str] | None = None) -> None:
        self.revoked_serials = revoked_serials or set()

    def is_serial_revoked(self, serial_number: str) -> bool:
        return serial_number in self.revoked_serials


def test_valid_signing_certificate_offline_validation() -> None:
    """Verify that a valid ML-DSA-65 certificate passes all 12 validation checks."""
    ca = OfflineRootCA.initialize(ca_id="ca-root-test-1")
    pk, _ = generate_mldsa_keypair()

    cert = ca.issue_signing_certificate(
        subject_id="usr-alice",
        public_key=pk,
        organization="Defense Intelligence Agency",
        role="Forensic Examiner",
        validity_days=30,
        device_id="dev-ws-001",
    )

    # 12-point validation against CA's pinned public key
    CertificateValidator.validate(cert, ca.public_key)
    assert cert.subject_id == "usr-alice"
    assert cert.key_purpose == KeyPurpose.DIGITAL_SIGNATURE
    assert cert.algorithm == "ML-DSA-65"


def test_valid_kem_certificate_offline_validation() -> None:
    """Verify that a valid ML-KEM-768 certificate passes all 12 validation checks."""
    ca = OfflineRootCA.initialize(ca_id="ca-root-test-2")
    kem_pk, _ = generate_mlkem_keypair()

    cert = ca.issue_kem_certificate(
        subject_id="rcp-bob",
        public_key=kem_pk,
        organization="Joint Staff",
        role="Recipient",
        validity_days=90,
    )

    CertificateValidator.validate(cert, ca.public_key)
    assert cert.subject_id == "rcp-bob"
    assert cert.key_purpose == KeyPurpose.KEY_ENCAPSULATION
    assert cert.algorithm == "ML-KEM-768"


def test_forged_root_ca_signature_rejected() -> None:
    """Check 3: Verify that forged or altered issuer signature is caught."""
    ca = OfflineRootCA.initialize(ca_id="ca-root-legit")
    ca_attacker = OfflineRootCA.initialize(ca_id="ca-root-rogue")
    pk, _ = generate_mldsa_keypair()

    cert = ca_attacker.issue_signing_certificate(
        subject_id="usr-forger",
        public_key=pk,
        organization="Adversary Org",
        role="Attacker",
    )

    # Validating against legit CA must fail
    with pytest.raises(SecurityError, match="Invalid Root CA digital signature"):
        CertificateValidator.validate(cert, ca.public_key)


def test_tampered_public_key_fingerprint_mismatch() -> None:
    """Check 5: Verify that altering public key bytes triggers fingerprint check failure."""
    ca = OfflineRootCA.initialize(ca_id="ca-root-fp-test")
    pk, _ = generate_mldsa_keypair()

    cert = ca.issue_signing_certificate(
        subject_id="usr-test",
        public_key=pk,
        organization="AirGap Unit",
        role="Analyst",
    )

    # Tamper with public key b64 (length preserved) but keep old fingerprint
    raw_pk = bytearray(base64.b64decode(cert.public_key_b64))
    raw_pk[20] ^= 0xFF
    tampered_b64 = base64.b64encode(bytes(raw_pk)).decode("ascii")

    tampered_cert = cert.model_copy(update={"public_key_b64": tampered_b64})
    # Re-sign so signature Check 3 passes, letting Check 5 execute
    sig = sign_mldsa(ca._private_key, tampered_cert.to_signing_bytes())
    tampered_cert = tampered_cert.model_copy(update={"signature_b64": sig.to_b64()})

    with pytest.raises(SecurityError, match="Check 5 Failed"):
        CertificateValidator.validate(tampered_cert, ca.public_key)


def test_purpose_mismatch_rejected() -> None:
    """Check 10: Verify that ML-DSA key claiming KEM purpose is rejected."""
    ca = OfflineRootCA.initialize(ca_id="ca-root-purpose")
    pk, _ = generate_mldsa_keypair()

    cert = ca.issue_signing_certificate(
        subject_id="usr-confused",
        public_key=pk,
        organization="AirGap Unit",
        role="Analyst",
    )

    # Force key_purpose to KEY_ENCAPSULATION for ML-DSA
    tampered_cert = cert.model_copy(update={"key_purpose": KeyPurpose.KEY_ENCAPSULATION})
    # Re-sign so signature Check 3 passes, letting Check 10 execute
    sig = sign_mldsa(ca._private_key, tampered_cert.to_signing_bytes())
    tampered_cert = tampered_cert.model_copy(update={"signature_b64": sig.to_b64()})

    with pytest.raises(ValidationError, match="Check 10 Failed"):
        CertificateValidator.validate(tampered_cert, ca.public_key)


def test_expired_certificate_rejected() -> None:
    """Check 8: Verify that an expired certificate fails validation."""
    ca = OfflineRootCA.initialize(ca_id="ca-root-time")
    pk, _ = generate_mldsa_keypair()

    cert = ca.issue_signing_certificate(
        subject_id="usr-time",
        public_key=pk,
        organization="AirGap Unit",
        role="Analyst",
        validity_days=1,
    )

    future_time = cert.valid_until + 10_000_000  # 10s after expiration

    with pytest.raises(SecurityError, match="Certificate has expired"):
        CertificateValidator.validate(cert, ca.public_key, current_time_micros=future_time)


def test_revoked_certificate_rejected() -> None:
    """Check 11: Verify that a revoked certificate fails validation."""
    ca = OfflineRootCA.initialize(ca_id="ca-root-rev")
    pk, _ = generate_mldsa_keypair()

    cert = ca.issue_signing_certificate(
        subject_id="usr-revoked",
        public_key=pk,
        organization="AirGap Unit",
        role="Analyst",
    )

    rev_provider = DummyRevocationProvider(revoked_serials={cert.serial_number})

    with pytest.raises(SecurityError, match="has been REVOKED"):
        CertificateValidator.validate(cert, ca.public_key, revocation_provider=rev_provider)
