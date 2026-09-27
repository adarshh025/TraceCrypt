"""Unit tests for cryptographic document binding verification and document mismatch detection."""

from __future__ import annotations

from tracecrypt.crypto.random import SecureRandom
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
from tracecrypt.watermark.types import WatermarkPayload


class TestDocumentBinding:
    """Validate 40-bit document binding commitments and DOCUMENT_MISMATCH isolation."""

    def test_valid_document_binding(self, forensic_environment) -> None:
        env = forensic_environment
        helper = env["helper"]
        dsa_sk = env["dsa_sk"]
        dsa_cert = env["dsa_cert"]

        wmid = WatermarkID.generate()
        sid = SessionID.generate()
        doc_hash = "sha3-256:6666666666666666666666666666666666666666666666666666666666666666"

        payload = WatermarkPayload.create(
            watermark_id=wmid,
            session_id=sid,
            document_hash=doc_hash,
        )

        event = DecryptionEvent(
            event_version="1.0.0",
            schema_version="1.0.0",
            protocol_version="1.0.0",
            software_version="1.0.0",
            event_type="DECRYPTION_ATTRIBUTION",
            event_id=EventID.generate(),
            document_id=DocumentID.generate(),
            distribution_id=DistributionID.generate(),
            document_hash=doc_hash,
            recipient_id=RecipientID(dsa_cert.subject_id),
            recipient_certificate_id=dsa_cert.serial_number,
            session_id=sid,
            watermark_id=wmid,
            watermark_version=1,
            anti_replay_nonce=SecureRandom.random_nonce_128(),
            timestamp=utc_now_micros(),
            pqc_algorithms=PQCAlgorithms(),
        )

        _, tx = helper.commit_event(event, dsa_sk, dsa_cert, height=1)

        binding = ForensicCryptographicVerifier.verify_document_binding(
            watermark_payload=payload,
            tx=tx,
            expected_document_hash=doc_hash,
        )

        assert binding.binding_verified is True
        assert binding.document_hash_matched is True
        assert binding.watermark_binding_matched is True
        assert len(binding.errors) == 0

    def test_wrong_document_binding_fails(self, forensic_environment) -> None:
        """Attack H: Watermark embedded in Doc B, but event commits to Doc A -> DOCUMENT_MISMATCH."""
        env = forensic_environment
        helper = env["helper"]
        dsa_sk = env["dsa_sk"]
        dsa_cert = env["dsa_cert"]

        wmid = WatermarkID.generate()
        sid = SessionID.generate()
        doc_a_hash = "sha3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        doc_b_hash = "sha3-256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

        # Watermark was created with Doc B binding
        payload = WatermarkPayload.create(
            watermark_id=wmid,
            session_id=sid,
            document_hash=doc_b_hash,
        )

        # But ledger event records Doc A
        event = DecryptionEvent(
            event_version="1.0.0",
            schema_version="1.0.0",
            protocol_version="1.0.0",
            software_version="1.0.0",
            event_type="DECRYPTION_ATTRIBUTION",
            event_id=EventID.generate(),
            document_id=DocumentID.generate(),
            distribution_id=DistributionID.generate(),
            document_hash=doc_a_hash,  # Doc A!
            recipient_id=RecipientID(dsa_cert.subject_id),
            recipient_certificate_id=dsa_cert.serial_number,
            session_id=sid,
            watermark_id=wmid,
            watermark_version=1,
            anti_replay_nonce=SecureRandom.random_nonce_128(),
            timestamp=utc_now_micros(),
            pqc_algorithms=PQCAlgorithms(),
        )

        _, tx = helper.commit_event(event, dsa_sk, dsa_cert, height=1)

        binding = ForensicCryptographicVerifier.verify_document_binding(
            watermark_payload=payload,
            tx=tx,
            expected_document_hash=None,
        )

        assert binding.binding_verified is False
        assert binding.watermark_binding_matched is False
        assert any("binding" in e.lower() for e in binding.errors)
