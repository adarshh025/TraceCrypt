"""Unit tests for block header verification, chain linkage, and tamper detection."""

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


class TestBlockVerification:
    """Validate block header integrity and chain linkage verification."""

    def test_block_hash_self_consistency(self, forensic_environment) -> None:
        env = forensic_environment
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
            document_hash="sha3-256:2222222222222222222222222222222222222222222222222222222222222222",
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

        details = ForensicCryptographicVerifier.verify_ledger_proof(
            tx=tx,
            block=block,
            previous_block=None,
            validator_set=val_set,
        )

        assert details.block_valid is True

    def test_tampered_block_hash_fails(self, forensic_environment) -> None:
        """Attack D: Tampered block hash must be caught by verifier."""
        env = forensic_environment
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
            document_hash="sha3-256:2222222222222222222222222222222222222222222222222222222222222222",
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

        # Tamper with header timestamp without recomputing block_hash
        tampered_header = block.header.model_copy(update={"timestamp": block.header.timestamp + 1000})
        tampered_block = block.model_copy(update={"header": tampered_header})

        details = ForensicCryptographicVerifier.verify_ledger_proof(
            tx=tx,
            block=tampered_block,
            previous_block=None,
            validator_set=val_set,
        )

        assert details.block_valid is False
        assert any("hash self-consistency failed" in e for e in details.errors)

    def test_chain_linkage_verification(self, forensic_environment) -> None:
        env = forensic_environment
        helper = env["helper"]
        dsa_sk = env["dsa_sk"]
        dsa_cert = env["dsa_cert"]
        val_set = env["val_set"]

        def make_evt():
            return DecryptionEvent(
                event_version="1.0.0",
                schema_version="1.0.0",
                protocol_version="1.0.0",
                software_version="1.0.0",
                event_type="DECRYPTION_ATTRIBUTION",
                event_id=EventID.generate(),
                document_id=DocumentID.generate(),
                distribution_id=DistributionID.generate(),
                document_hash="sha3-256:2222222222222222222222222222222222222222222222222222222222222222",
                recipient_id=RecipientID(dsa_cert.subject_id),
                recipient_certificate_id=dsa_cert.serial_number,
                session_id=SessionID.generate(),
                watermark_id=WatermarkID.generate(),
                watermark_version=1,
                anti_replay_nonce=SecureRandom.random_nonce_128(),
                timestamp=utc_now_micros(),
                pqc_algorithms=PQCAlgorithms(),
            )

        block1, tx1 = helper.commit_event(make_evt(), dsa_sk, dsa_cert, height=1)
        block2, tx2 = helper.commit_event(make_evt(), dsa_sk, dsa_cert, height=2, prev_hash=block1.header.block_hash)

        # Valid linkage
        d2 = ForensicCryptographicVerifier.verify_ledger_proof(
            tx=tx2,
            block=block2,
            previous_block=block1,
            validator_set=val_set,
        )
        assert d2.chain_linkage_valid is True

        # Broken linkage: pass wrong previous block
        bad_hash = "sha3-256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        wrong_prev = block1.model_copy(
            update={"header": block1.header.model_copy(update={"block_hash": bad_hash})}
        )
        d2_bad = ForensicCryptographicVerifier.verify_ledger_proof(
            tx=tx2,
            block=block2,
            previous_block=wrong_prev,
            validator_set=val_set,
        )
        assert d2_bad.chain_linkage_valid is False
        assert any("Chain break" in e for e in d2_bad.errors)
