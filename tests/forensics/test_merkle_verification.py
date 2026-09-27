"""Unit tests for Merkle inclusion proof verification and tamper detection."""

from __future__ import annotations

from tracecrypt.crypto.random import SecureRandom
from tracecrypt.event.schema import DecryptionEvent, PQCAlgorithms
from tracecrypt.forensics.verifier import ForensicCryptographicVerifier
from tracecrypt.ledger.merkle import MerkleTree
from tracecrypt.utils.identifiers import (
    DistributionID,
    DocumentID,
    EventID,
    RecipientID,
    SessionID,
    WatermarkID,
)
from tracecrypt.utils.timestamps import utc_now_micros


class TestMerkleVerification:
    """Validate independent mathematical Merkle inclusion proof verification."""

    def test_valid_merkle_proof_verification(self, forensic_environment) -> None:
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
            document_hash="sha3-256:1111111111111111111111111111111111111111111111111111111111111111",
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

        assert details.merkle_proof_valid is True
        assert details.block_valid is True
        assert details.commit_certificate_valid is True
        assert len(details.errors) == 0

    def test_tampered_merkle_root_fails(self, forensic_environment) -> None:
        """Attack E: Tampered block Merkle root must fail verification."""
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
            document_hash="sha3-256:1111111111111111111111111111111111111111111111111111111111111111",
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

        # Forge header transaction_root
        tampered_header = block.header.model_copy(
            update={"transaction_root": "sha3-256:0000000000000000000000000000000000000000000000000000000000000000"}
        )
        tampered_block = block.model_copy(update={"header": tampered_header})

        details = ForensicCryptographicVerifier.verify_ledger_proof(
            tx=tx,
            block=tampered_block,
            previous_block=None,
            validator_set=val_set,
        )

        assert details.merkle_proof_valid is False
        assert any("Merkle" in e for e in details.errors)

    def test_direct_merkle_inclusion_tamper(self) -> None:
        tx_bytes_1 = b"transaction_1"
        tx_bytes_2 = b"transaction_2"
        tx_bytes_3 = b"transaction_3"
        leaf_list = [tx_bytes_1, tx_bytes_2, tx_bytes_3]

        root = MerkleTree.build_merkle_root(leaf_list)
        proof = MerkleTree.generate_merkle_proof(0, leaf_list)

        # Valid proof succeeds
        leaf_0 = MerkleTree.compute_leaf_hash(tx_bytes_1)
        assert MerkleTree.verify_merkle_proof(leaf_0, proof, root) is True

        # Tampered leaf fails
        tampered_leaf = MerkleTree.compute_leaf_hash(b"tampered_bytes")
        assert MerkleTree.verify_merkle_proof(tampered_leaf, proof, root) is False
