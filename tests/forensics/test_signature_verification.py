"""Unit tests for RFC 8785 canonicalization and ML-DSA-65 digital signature verification."""

from __future__ import annotations

import base64

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair, sign_mldsa
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.event.canonicalizer import canonicalize
from tracecrypt.event.schema import DecryptionEvent, PQCAlgorithms
from tracecrypt.forensics.verifier import ForensicCryptographicVerifier
from tracecrypt.utils.identifiers import (
    DistributionID,
    DocumentID,
    EventID,
    RecipientID,
    SessionID,
    WatermarkID,
)
from tracecrypt.utils.timestamps import utc_now_micros


class TestSignatureVerification:
    """Validate RFC 8785 canonical event verification and NIST FIPS 204 ML-DSA-65 signatures."""

    def test_valid_signature_verification(self, forensic_environment) -> None:
        env = forensic_environment
        helper = env["helper"]
        dsa_sk = env["dsa_sk"]
        dsa_cert = env["dsa_cert"]

        event = DecryptionEvent(
            event_version="1.0.0",
            schema_version="1.0.0",
            protocol_version="1.0.0",
            software_version="1.0.0",
            event_type="DECRYPTION_ATTRIBUTION",
            event_id=EventID.generate(),
            document_id=DocumentID.generate(),
            distribution_id=DistributionID.generate(),
            document_hash="sha3-256:5555555555555555555555555555555555555555555555555555555555555555",
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
            root_ca_public_key=None,
            revocation_provider=None,
        )

        assert ident.signature_verified is True
        assert ident.canonical_event_digest == tx.signed_event.event_digest

    def test_forged_mldsa_signature_fails(self, forensic_environment) -> None:
        """Attack G: Signature from different ML-DSA keypair fails verification."""
        env = forensic_environment
        helper = env["helper"]
        dsa_sk = env["dsa_sk"]
        dsa_cert = env["dsa_cert"]

        event = DecryptionEvent(
            event_version="1.0.0",
            schema_version="1.0.0",
            protocol_version="1.0.0",
            software_version="1.0.0",
            event_type="DECRYPTION_ATTRIBUTION",
            event_id=EventID.generate(),
            document_id=DocumentID.generate(),
            distribution_id=DistributionID.generate(),
            document_hash="sha3-256:5555555555555555555555555555555555555555555555555555555555555555",
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

        # Forge signature using an unauthorized key
        _, rogue_sk = generate_mldsa_keypair()
        canonical_bytes = canonicalize(event.to_canonical_dict())
        forged_sig = sign_mldsa(rogue_sk, canonical_bytes)

        tampered_signed_evt = tx.signed_event.model_copy(
            update={"signature": base64.b64encode(forged_sig.raw_bytes).decode("ascii")}
        )
        tampered_tx = tx.model_copy(update={"signed_event": tampered_signed_evt})

        ident = ForensicCryptographicVerifier.verify_recipient_identity_and_signature(
            tx=tampered_tx,
            root_ca_public_key=None,
            revocation_provider=None,
        )

        assert ident.signature_verified is False
        assert any("signature mathematical verification failed" in e.lower() for e in ident.errors)

    def test_tampered_event_fields_break_signature(self, forensic_environment) -> None:
        """Modifying event data (e.g. document_hash) breaks digest and fails signature."""
        env = forensic_environment
        helper = env["helper"]
        dsa_sk = env["dsa_sk"]
        dsa_cert = env["dsa_cert"]

        event = DecryptionEvent(
            event_version="1.0.0",
            schema_version="1.0.0",
            protocol_version="1.0.0",
            software_version="1.0.0",
            event_type="DECRYPTION_ATTRIBUTION",
            event_id=EventID.generate(),
            document_id=DocumentID.generate(),
            distribution_id=DistributionID.generate(),
            document_hash="sha3-256:5555555555555555555555555555555555555555555555555555555555555555",
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

        # Tamper with document_hash inside event
        tampered_event = event.model_copy(
            update={"document_hash": "sha3-256:9999999999999999999999999999999999999999999999999999999999999999"}
        )
        tampered_signed_evt = tx.signed_event.model_copy(update={"event": tampered_event})
        tampered_tx = tx.model_copy(update={"signed_event": tampered_signed_evt})

        ident = ForensicCryptographicVerifier.verify_recipient_identity_and_signature(
            tx=tampered_tx,
            root_ca_public_key=None,
            revocation_provider=None,
        )

        assert ident.signature_verified is False
        assert any("mismatch" in e.lower() for e in ident.errors)
