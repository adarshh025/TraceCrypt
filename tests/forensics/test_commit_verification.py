"""Unit tests for BFT CommitCertificate and validator quorum verification."""

from __future__ import annotations

from typing import List

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.event.schema import DecryptionEvent, PQCAlgorithms
from tracecrypt.forensics.verifier import ForensicCryptographicVerifier
from tracecrypt.ledger.messages import VoteMessage, VoteType
from tracecrypt.utils.identifiers import (
    DistributionID,
    DocumentID,
    EventID,
    RecipientID,
    SessionID,
    ValidatorID,
    WatermarkID,
)
from tracecrypt.utils.timestamps import utc_now_micros


class TestCommitVerification:
    """Validate 4-validator BFT quorum (2f+1=3) commit certificate verification."""

    def test_valid_quorum_commit_certificate(self, forensic_environment) -> None:
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
            document_hash="sha3-256:3333333333333333333333333333333333333333333333333333333333333333",
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

        assert details.commit_certificate_valid is True
        assert details.quorum_satisfied is True
        assert len(details.verified_validators) >= 3

    def test_insufficient_votes_fails_quorum(self, forensic_environment) -> None:
        """Attack F1: Commit certificate with only 2 votes (below quorum of 3) must fail."""
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
            document_hash="sha3-256:3333333333333333333333333333333333333333333333333333333333333333",
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

        # Drop 1 vote from certificate, leaving only 2
        two_votes = block.commit_certificate.votes[:2]
        bad_cert = block.commit_certificate.model_copy(update={"votes": two_votes})
        tampered_block = block.model_copy(update={"commit_certificate": bad_cert})

        details = ForensicCryptographicVerifier.verify_ledger_proof(
            tx=tx,
            block=tampered_block,
            previous_block=None,
            validator_set=val_set,
        )

        assert details.commit_certificate_valid is False
        assert details.quorum_satisfied is False
        assert any("quorum not satisfied" in e for e in details.errors)

    def test_forged_validator_signature_fails(self, forensic_environment) -> None:
        """Attack F2: Forged or unauthorized validator signature fails commit verification."""
        env = forensic_environment
        helper = env["helper"]
        dsa_sk = env["dsa_sk"]
        dsa_cert = env["dsa_cert"]
        val_set = env["val_set"]
        state = env["state"]

        event = DecryptionEvent(
            event_version="1.0.0",
            schema_version="1.0.0",
            protocol_version="1.0.0",
            software_version="1.0.0",
            event_type="DECRYPTION_ATTRIBUTION",
            event_id=EventID.generate(),
            document_id=DocumentID.generate(),
            distribution_id=DistributionID.generate(),
            document_hash="sha3-256:3333333333333333333333333333333333333333333333333333333333333333",
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

        # Add vote from rogue unknown validator
        _, rogue_sk = generate_mldsa_keypair()
        rogue_vid = ValidatorID.generate()
        rogue_vote = VoteMessage.create_and_sign(
            chain_id=state.chain_id,
            height=1,
            round=0,
            vote_type=VoteType.PRECOMMIT,
            block_hash=block.header.block_hash,
            validator_id=rogue_vid,
            signing_key=rogue_sk,
            timestamp=utc_now_micros(),
        )

        rogue_votes: List[VoteMessage] = [block.commit_certificate.votes[0], rogue_vote]
        bad_cert = block.commit_certificate.model_copy(update={"votes": rogue_votes})
        tampered_block = block.model_copy(update={"commit_certificate": bad_cert})

        details = ForensicCryptographicVerifier.verify_ledger_proof(
            tx=tx,
            block=tampered_block,
            previous_block=None,
            validator_set=val_set,
        )

        assert details.commit_certificate_valid is False
        assert any("unauthorized validator" in e for e in details.errors)
