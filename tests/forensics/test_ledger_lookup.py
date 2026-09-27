"""Unit tests for ledger lookup by cryptographic WatermarkID and identifiers."""

from __future__ import annotations

from tracecrypt.crypto.random import SecureRandom
from tracecrypt.event.schema import DecryptionEvent, PQCAlgorithms
from tracecrypt.utils.identifiers import (
    DistributionID,
    DocumentID,
    EventID,
    RecipientID,
    SessionID,
    WatermarkID,
)
from tracecrypt.utils.timestamps import utc_now_micros


class TestLedgerLookup:
    """Validate deterministic ledger lookup by cryptographic WatermarkID."""

    def test_lookup_existing_watermark_transaction(self, forensic_environment) -> None:
        env = forensic_environment
        storage = env["storage"]
        helper = env["helper"]
        dsa_sk = env["dsa_sk"]
        dsa_cert = env["dsa_cert"]

        wmid = WatermarkID.generate()
        sid = SessionID.generate()
        eid = EventID.generate()
        did = DocumentID.generate()
        doc_hash = "sha3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

        event = DecryptionEvent(
            event_version="1.0.0",
            schema_version="1.0.0",
            protocol_version="1.0.0",
            software_version="1.0.0",
            event_type="DECRYPTION_ATTRIBUTION",
            event_id=eid,
            document_id=did,
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

        block, tx = helper.commit_event(event, dsa_sk, dsa_cert, height=1)

        # Lookup by WatermarkID
        result = storage.get_transaction_with_block_by_watermark(str(wmid))
        assert result is not None
        found_tx, found_block, found_index = result

        assert found_index == 0
        assert found_tx.transaction_id == tx.transaction_id
        assert found_tx.signed_event.event.watermark_id == wmid
        assert found_tx.signed_event.event.session_id == sid
        assert found_block.header.height == 1
        assert found_block.header.block_hash == block.header.block_hash

    def test_lookup_missing_watermark_returns_none(self, forensic_environment) -> None:
        env = forensic_environment
        storage = env["storage"]

        missing_wmid = WatermarkID.generate()
        result = storage.get_transaction_with_block_by_watermark(str(missing_wmid))
        assert result is None
