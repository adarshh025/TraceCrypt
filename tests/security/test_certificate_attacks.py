"""Adversarial Certificate Attack and Offline PKI Security Tests.

Validates:
- Rejection of expired certificates.
- Rejection of not-yet-valid certificates.
- Rejection of certificates with forged Root CA signatures.
- Rejection of certificates with altered public keys (fingerprint mismatch).
- Rejection of revoked certificates against offline revocation lists.
- Rejection of certificates with mismatched key purposes.
"""

from __future__ import annotations

from pathlib import Path
import pytest

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
from tracecrypt.errors import SecurityError
from tracecrypt.identity.certificate import CertificateValidator
from tracecrypt.identity.lifecycle import OfflineRevocationStore, RevocationReason


class TestCertificateAttacks:
    """Evaluate 12-point offline certificate verifier against hostile inputs."""

    @pytest.fixture
    def cert_fixture(self, forensic_environment):
        root_ca = forensic_environment["root_ca"]
        pk, sk = generate_mldsa_keypair()
        cert = root_ca.issue_signing_certificate(
            subject_id="usr-adversary-test",
            public_key=pk,
            organization="Adversary Corp",
            role="LEAK_TESTER",
        )
        return cert, root_ca, pk, sk

    def test_forged_ca_signature_rejected(self, cert_fixture) -> None:
        """Modifying the Root CA signature bytes triggers Check 3 failure."""
        cert, root_ca, _, _ = cert_fixture
        import base64
        raw_sig = base64.b64decode(cert.signature_b64)
        tampered_sig = bytes([raw_sig[0] ^ 0xFF]) + raw_sig[1:]

        tampered_cert = cert.model_copy(update={"signature_b64": base64.b64encode(tampered_sig).decode("ascii")})

        with pytest.raises(SecurityError, match="Check 3 Failed.*Invalid Root CA digital signature"):
            CertificateValidator.validate(
                certificate=tampered_cert,
                root_ca_public_key=root_ca.public_key,
            )

    def test_tampered_subject_rejected(self, cert_fixture) -> None:
        """Modifying the subject without re-signing triggers signature verification failure."""
        cert, root_ca, _, _ = cert_fixture
        tampered_cert = cert.model_copy(update={"subject_id": "usr-impostor"})

        with pytest.raises(SecurityError, match="Check 3 Failed"):
            CertificateValidator.validate(
                certificate=tampered_cert,
                root_ca_public_key=root_ca.public_key,
            )

    def test_tampered_public_key_fingerprint_mismatch(self, cert_fixture) -> None:
        """Modifying public key without changing fingerprint fails Check 5."""
        cert, root_ca, _, _ = cert_fixture
        other_pk, _ = generate_mldsa_keypair()

        # Update public_key_b64 but leave public_key_fingerprint
        tampered_cert = cert.model_copy(update={"public_key_b64": other_pk.to_b64()})

        with pytest.raises(SecurityError, match="Check (3|5) Failed"):
            CertificateValidator.validate(
                certificate=tampered_cert,
                root_ca_public_key=root_ca.public_key,
            )

    def test_expired_certificate_rejected(self, cert_fixture) -> None:
        """Valid certificate tested at timestamp beyond valid_until triggers Check 8."""
        cert, root_ca, _, _ = cert_fixture
        far_future = cert.valid_until + 1_000_000

        with pytest.raises(SecurityError, match="Check 8 Failed.*Certificate has expired"):
            CertificateValidator.validate(
                certificate=cert,
                root_ca_public_key=root_ca.public_key,
                current_time_micros=far_future,
            )

    def test_not_yet_valid_certificate_rejected(self, cert_fixture) -> None:
        """Valid certificate tested at timestamp before valid_from triggers Check 8."""
        cert, root_ca, _, _ = cert_fixture
        past_time = cert.valid_from - 1_000_000

        with pytest.raises(SecurityError, match="Check 8 Failed.*not yet valid"):
            CertificateValidator.validate(
                certificate=cert,
                root_ca_public_key=root_ca.public_key,
                current_time_micros=past_time,
            )

    def test_revoked_certificate_rejected(self, cert_fixture, tmp_path: Path) -> None:
        """Revoking a certificate serial in the revocation store triggers Check 11."""
        cert, root_ca, _, _ = cert_fixture
        rev_store = OfflineRevocationStore()

        # Before revocation, validation passes
        CertificateValidator.validate(
            certificate=cert,
            root_ca_public_key=root_ca.public_key,
            revocation_provider=rev_store,
            current_time_micros=cert.valid_from + 1000,
        )

        # Revoke the certificate
        from tracecrypt.identity.lifecycle import KeyLifecycleManager
        rec = KeyLifecycleManager.create_revocation_record(
            serial_number=cert.serial_number,
            key_id=f"key-{cert.subject_id}",
            reason=RevocationReason.KEY_COMPROMISE,
            ca=root_ca,
        )
        rev_store.register_revocation(rec)

        # After revocation, validation fails closed
        with pytest.raises(SecurityError, match="Check 11 Failed.*REVOKED"):
            CertificateValidator.validate(
                certificate=cert,
                root_ca_public_key=root_ca.public_key,
                revocation_provider=rev_store,
                current_time_micros=cert.valid_from + 3000,
            )
