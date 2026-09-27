"""Byzantine Fault Tolerant (BFT) Adversarial Consensus Tests.

Validates:
- Byzantine validator equivocation detection (double voting).
- Generation and recording of cryptographic ByzantineEvidence.
- Mathematical quorum threshold calculation: floor(2*w/3) + 1.
- Prevention of dual commitment for conflicting block proposals.
- Safety maintenance with f=1 malicious validator in N=4 network.
"""

from __future__ import annotations

import pytest

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
from tracecrypt.errors import ByzantineFaultDetected
from tracecrypt.ledger.consensus import ConsensusEngine
from tracecrypt.ledger.mempool import Mempool
from tracecrypt.ledger.messages import (
    CommitCertificate,
    VoteMessage,
    VoteType,
)
from tracecrypt.ledger.state import LedgerState
from tracecrypt.ledger.validator import NodeRole, ValidatorInfo, ValidatorSet
from tracecrypt.utils.identifiers import ValidatorID
from tracecrypt.utils.timestamps import utc_now_micros


def _build_test_validator_set(count: int = 4):
    keys = []
    validators = []
    for i in range(count):
        vid = ValidatorID.generate()
        pk, sk = generate_mldsa_keypair()
        keys.append((vid, pk, sk))
        vinfo = ValidatorInfo(
            validator_id=vid,
            public_key_b64=pk.to_b64(),
            certificate_id=f"crt-{i+1}",
            certificate_fingerprint=f"fp-{i+1}",
            voting_power=1,
            role=NodeRole.VALIDATOR,
        )
        validators.append(vinfo)
    return ValidatorSet(validators=validators), keys


class TestBFTByzantineConsensus:
    """Evaluate BFT consensus resilience against active Byzantine adversaries."""

    def test_quorum_threshold_mathematical_formula(self) -> None:
        """Verify centralized quorum formula floor(2*w/3) + 1 for various cluster sizes."""
        # N=4, w=4 -> floor(8/3) + 1 = 2 + 1 = 3
        vset_4, _ = _build_test_validator_set(4)
        assert vset_4.total_voting_power == 4
        assert vset_4.max_byzantine_faults == 1
        assert vset_4.quorum_threshold == 3
        assert vset_4.has_quorum(2) is False
        assert vset_4.has_quorum(3) is True

        # N=7, w=7 -> floor(14/3) + 1 = 4 + 1 = 5
        vset_7, _ = _build_test_validator_set(7)
        assert vset_7.total_voting_power == 7
        assert vset_7.max_byzantine_faults == 2
        assert vset_7.quorum_threshold == 5
        assert vset_7.has_quorum(4) is False
        assert vset_7.has_quorum(5) is True

    def test_byzantine_equivocation_detection(self) -> None:
        """Detect and generate cryptographic evidence when a validator double-votes."""
        vset, keys = _build_test_validator_set(4)
        val_1_id, val_1_pk, val_1_sk = keys[0]
        val_2_id, val_2_pk, val_2_sk = keys[1]

        state = LedgerState("chain-test-bft")
        mempool = Mempool()
        engine = ConsensusEngine(
            validator_id=val_1_id,
            private_key=val_1_sk,
            validator_set=vset,
            chain_id="chain-test-bft",
            state=state,
            mempool=mempool,
        )

        # Honest vote from Validator 2 for Block A
        vote_a = VoteMessage.create_and_sign(
            chain_id="chain-test-bft",
            height=1,
            round=0,
            vote_type=VoteType.PREVOTE,
            block_hash="sha3-256:" + "aa" * 32,
            validator_id=val_2_id,
            signing_key=val_2_sk,
            timestamp=utc_now_micros(),
        )
        assert engine.add_vote(vote_a) is True

        # Byzantine vote from Validator 2 for conflicting Block B in the same round/height
        vote_b = VoteMessage.create_and_sign(
            chain_id="chain-test-bft",
            height=1,
            round=0,
            vote_type=VoteType.PREVOTE,
            block_hash="sha3-256:" + "bb" * 32,
            validator_id=val_2_id,
            signing_key=val_2_sk,
            timestamp=utc_now_micros() + 10,
        )

        with pytest.raises(ByzantineFaultDetected, match="equivocated at height"):
            engine.add_vote(vote_b)

        # Verify evidence recorded
        assert len(engine.evidence_log) == 1
        ev = list(engine.evidence_log.values())[0]
        assert ev.validator_id == val_2_id
        assert ev.verify(vset) is True

    def test_commit_certificate_requires_quorum(self) -> None:
        """CommitCertificate with fewer than 2f+1 signatures must fail verification."""
        vset, keys = _build_test_validator_set(4)
        block_hash = "sha3-256:" + "11" * 32

        # Only 2 votes when 3 are required
        votes = []
        for i in range(2):
            vid, _, sk = keys[i]
            v = VoteMessage.create_and_sign(
                chain_id="chain-test-bft",
                height=1,
                round=0,
                vote_type=VoteType.PRECOMMIT,
                block_hash=block_hash,
                validator_id=vid,
                signing_key=sk,
                timestamp=utc_now_micros(),
            )
            votes.append(v)

        cert = CommitCertificate(
            chain_id="chain-test-bft",
            height=1,
            round=0,
            block_hash=block_hash,
            votes=votes,
            validator_set_hash=vset.compute_hash(),
        )

        assert cert.verify_certificate(vset, block_hash) is False
