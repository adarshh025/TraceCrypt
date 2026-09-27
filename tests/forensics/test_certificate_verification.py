"""Unit tests for offline recipient certificate validation and revocation checks."""

from __future__ import annotations

import pytest

from tracecrypt.crypto.random import SecureRandom
from tracecrypt.errors import SecurityError
from tracecrypt.event.schema import DecryptionEvent, PQCAlgorithms
from tracecrypt.event.signer import DecryptionEventSigner
from tracecrypt.forensics.verifier import ForensicCryptographicVerifier
from tracecrypt.identity.lifecycle import KeyLifecycleManager, RevocationReason
from tracecrypt.utils.identifiers import (
    DistributionID,
    DocumentID,
    EventID,
    RecipientID,
    SessionID,
    WatermarkID,
)
from tracecrypt.utils.timestamps import utc_now_micros


class TestCertificateVerification:
    """Validate 11-point offline certificate validation and revocation enforcement."""

    def test_valid_recipient_certificate(self, forensic_environment) -> None:
        env = forensic_environment
        helper = env["helper"]
        dsa_sk = env["dsa_sk"]
        dsa_cert = env["dsa_cert"]
        root_ca = env["root_ca"]
        rev_store = env["revocation_store"]

        event = DecryptionEvent(
            event_version="1.0.0",
            schema_version="1.0.0",
            protocol_version="1.0.0",
            software_version="1.0.0",
            event_type="DECRYPTION_ATTRIBUTION",
            event_id=EventID.generate(),
            document_id=DocumentID.generate(),
            distribution_id=DistributionID.generate(),
            document_hash="sha3-256:4444444444444444444444444444444444444444444444444444444444444444",
            recipient_id=RecipientID(dsa_cert.subject_id),
            recipient_certificate_id=dsa_cert.serial_number,
            session_id=SessionID.generate(),
            watermark_id=WatermarkID.generate(),
            watermark_version=1,
            anti_replay_nonce=SecureRandom.random_nonce_128(),
            timestamp=utc_now_micros(),
            pqc_algorithms=PQCAlgorithms(),
        )

        _, tx = helper.commit_event(event, dsa_sk, dsa_cert, height=1)

        ident = ForensicCryptographicVerifier.verify_recipient_identity_and_signature(
            tx=tx,
            root_ca_public_key=root_ca.public_key,
            revocation_provider=rev_store,
        )

        assert ident.certificate_valid is True
        assert ident.not_revoked is True
        assert ident.key_purpose_valid is True
        assert ident.signature_verified is True
        assert len(ident.errors) == 0

    def test_revoked_certificate_fails(self, forensic_environment) -> None:
        env = forensic_environment
        helper = env["helper"]
        dsa_sk = env["dsa_sk"]
        dsa_cert = env["dsa_cert"]
        root_ca = env["root_ca"]
        rev_store = env["revocation_store"]

        event = DecryptionEvent(
            event_version="1.0.0",
            schema_version="1.0.0",
            protocol_version="1.0.0",
            software_version="1.0.0",
            event_type="DECRYPTION_ATTRIBUTION",
            event_id=EventID.generate(),
            document_id=DocumentID.generate(),
            distribution_id=DistributionID.generate(),
            document_hash="sha3-256:4444444444444444444444444444444444444444444444444444444444444444",
            recipient_id=RecipientID(dsa_cert.subject_id),
            recipient_certificate_id=dsa_cert.serial_number,
            session_id=SessionID.generate(),
            watermark_id=WatermarkID.generate(),
            watermark_version=1,
            anti_replay_nonce=SecureRandom.random_nonce_128(),
            timestamp=utc_now_micros(),
            pqc_algorithms=PQCAlgorithms(),
        )

        _, tx = helper.commit_event(event, dsa_sk, dsa_cert, height=1)

        # Create signed revocation record and register in revocation store
        rev_rec = KeyLifecycleManager.create_revocation_record(
            serial_number=dsa_cert.serial_number,
            key_id="key-alice-signing",
            reason=RevocationReason.KEY_COMPROMISE,
            ca=root_ca,
        )
        rev_store.register_revocation(rev_rec)

        ident = ForensicCryptographicVerifier.verify_recipient_identity_and_signature(
            tx=tx,
            root_ca_public_key=root_ca.public_key,
            revocation_provider=rev_store,
        )

        assert ident.certificate_valid is False
        assert any("revoked" in e.lower() for e in ident.errors)

    def test_wrong_key_purpose_fails(self, forensic_environment) -> None:
        """KEM encryption certificate cannot be used for digital signing."""
        env = forensic_environment
        helper = env["helper"]
        dsa_sk = env["dsa_sk"]
        dsa_cert = env["dsa_cert"]
        kem_cert = env["kem_cert"]
        root_ca = env["root_ca"]
        rev_store = env["revocation_store"]

        event = DecryptionEvent(
            event_version="1.0.0",
            schema_version="1.0.0",
            protocol_version="1.0.0",
            software_version="1.0.0",
            event_type="DECRYPTION_ATTRIBUTION",
            event_id=EventID.generate(),
            document_id=DocumentID.generate(),
            distribution_id=DistributionID.generate(),
            document_hash="sha3-256:4444444444444444444444444444444444444444444444444444444444444444",
            recipient_id=RecipientID(dsa_cert.subject_id),
            recipient_certificate_id=dsa_cert.serial_number,
            session_id=SessionID.generate(),
            watermark_id=WatermarkID.generate(),
            watermark_version=1,
            anti_replay_nonce=SecureRandom.random_nonce_128(),
            timestamp=utc_now_micros(),
            pqc_algorithms=PQCAlgorithms(),
        )

        # 1. Signer layer rejects signing directly with KEM cert
        with pytest.raises(SecurityError):
            DecryptionEventSigner.sign_event(event, dsa_sk, kem_cert)

        # 2. Forensic verifier rejects a transaction swapped with KEM cert
        _, valid_tx = helper.commit_event(event, dsa_sk, dsa_cert, height=1)
        tampered_tx = valid_tx.model_copy(update={"recipient_certificate": kem_cert})

        ident = ForensicCryptographicVerifier.verify_recipient_identity_and_signature(
            tx=tampered_tx,
            root_ca_public_key=root_ca.public_key,
            revocation_provider=rev_store,
        )

        assert ident.key_purpose_valid is False
        assert ident.certificate_valid is False
        assert any("key purpose" in e.lower() for e in ident.errors)
