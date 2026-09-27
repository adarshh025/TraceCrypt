"""Unit tests for direct ledger database tampering detection."""

from __future__ import annotations

import sqlite3

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


class TestLedgerTampering:
    """Validate that direct SQLite database tampering is detected and fails closed with LEDGER_INVALID."""

    def test_direct_sqlite_transaction_tamper(self, forensic_environment) -> None:
        env = forensic_environment
        storage = env["storage"]
        helper = env["helper"]
        dsa_sk = env["dsa_sk"]
        dsa_cert = env["dsa_cert"]
        val_set = env["val_set"]

        event = DecryptionEvent(
            event_version="1.0.0",
            schema_version="1.0.0",
            protocol_version="1.0.0",
            software_version="1.0.0",
            event_type="DECRYPTION_ATTRIBUTION",
            event_id=EventID.generate(),
            document_id=DocumentID.generate(),
            distribution_id=DistributionID.generate(),
            document_hash="sha3-256:9999999999999999999999999999999999999999999999999999999999999999",
            recipient_id=RecipientID(dsa_cert.subject_id),
            recipient_certificate_id=dsa_cert.serial_number,
            session_id=SessionID.generate(),
            watermark_id=WatermarkID.generate(),
            watermark_version=1,
            anti_replay_nonce=SecureRandom.random_nonce_128(),
            timestamp=utc_now_micros(),
            pqc_algorithms=PQCAlgorithms(),
        )
        block, tx = helper.commit_event(event, dsa_sk, dsa_cert, height=1)

        # Direct database modification: alter transaction JSON in transactions table
        conn = sqlite3.connect(str(storage.db_path))
        try:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE transactions SET canonical_json = "
                "REPLACE(canonical_json, 'DECRYPTION_ATTRIBUTION', 'TAMPERED') "
                "WHERE transaction_id = ?;",
                (str(tx.transaction_id),),
            )
            conn.commit()
        finally:
            conn.close()

        # Re-fetch from storage
        tampered_res = storage.get_transaction_with_block(str(tx.transaction_id))
        assert tampered_res is not None
        tampered_tx, stored_block, _ = tampered_res

        # Independent verifier MUST detect that tampered transaction breaks Merkle inclusion proof
        details = ForensicCryptographicVerifier.verify_ledger_proof(
            tx=tampered_tx,
            block=stored_block,
            previous_block=None,
            validator_set=val_set,
        )

        assert details.merkle_proof_valid is False
        assert len(details.errors) > 0

    def test_direct_sqlite_block_header_tamper(self, forensic_environment) -> None:
        env = forensic_environment
        storage = env["storage"]
        helper = env["helper"]
        dsa_sk = env["dsa_sk"]
        dsa_cert = env["dsa_cert"]
        val_set = env["val_set"]

        event = DecryptionEvent(
            event_version="1.0.0",
            schema_version="1.0.0",
            protocol_version="1.0.0",
            software_version="1.0.0",
            event_type="DECRYPTION_ATTRIBUTION",
            event_id=EventID.generate(),
            document_id=DocumentID.generate(),
            distribution_id=DistributionID.generate(),
            document_hash="sha3-256:9999999999999999999999999999999999999999999999999999999999999999",
            recipient_id=RecipientID(dsa_cert.subject_id),
            recipient_certificate_id=dsa_cert.serial_number,
            session_id=SessionID.generate(),
            watermark_id=WatermarkID.generate(),
            watermark_version=1,
            anti_replay_nonce=SecureRandom.random_nonce_128(),
            timestamp=utc_now_micros(),
            pqc_algorithms=PQCAlgorithms(),
        )
        block, tx = helper.commit_event(event, dsa_sk, dsa_cert, height=1)

        # Alter header_json in blocks table
        conn = sqlite3.connect(str(storage.db_path))
        try:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE blocks SET header_json = REPLACE(header_json, 'tracecrypt-forensic-chain', 'forged-chain') "
                "WHERE height = 1;"
            )
            conn.commit()
        finally:
            conn.close()

        tampered_res = storage.get_transaction_with_block(str(tx.transaction_id))
        assert tampered_res is not None
        stored_tx, tampered_block, _ = tampered_res

        details = ForensicCryptographicVerifier.verify_ledger_proof(
            tx=stored_tx,
            block=tampered_block,
            previous_block=None,
            validator_set=val_set,
        )

        assert details.block_valid is False
        assert any("hash self-consistency failed" in e for e in details.errors)
