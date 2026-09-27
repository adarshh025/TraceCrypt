"""Adversarial Consensus Message Authentication and Replay Tests.

Validates:
- Rejection of replayed Proposal, Prevote, and Precommit across heights and rounds.
- Rejection of consensus messages signed by unauthorized or unknown validator keys.
- Detection of modified payloads or tampered signatures in consensus messages.
"""

from __future__ import annotations

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
from tracecrypt.ledger.consensus import ConsensusEngine
from tracecrypt.ledger.mempool import Mempool
from tracecrypt.ledger.messages import (
    ProposalMessage,
    VoteMessage,
    VoteType,
)
from tracecrypt.ledger.state import LedgerState
from tracecrypt.ledger.validator import NodeRole, ValidatorInfo, ValidatorSet
from tracecrypt.utils.identifiers import ValidatorID
from tracecrypt.utils.timestamps import utc_now_micros


def _build_test_validator_set():
    keys = []
    validators = []
    for i in range(4):
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


class TestConsensusReplay:
    """Evaluate consensus engine resilience against message replays and tampering."""

    def test_vote_replay_across_rounds_rejected(self) -> None:
        """A vote signed for round 0 must not be accepted when consensus advances to round 1."""
        vset, keys = _build_test_validator_set()
        val_0_id, _, val_0_sk = keys[0]
        val_1_id, _, val_1_sk = keys[1]

        engine = ConsensusEngine(
            validator_id=val_0_id,
            private_key=val_0_sk,
            validator_set=vset,
            chain_id="chain-test-replay",
            state=LedgerState("chain-test-replay"),
            mempool=Mempool(),
        )

        # Engine is at height 1, round 0
        vote_round_0 = VoteMessage.create_and_sign(
            chain_id="chain-test-replay",
            height=1,
            round=0,
            vote_type=VoteType.PREVOTE,
            block_hash="sha3-256:" + "01" * 32,
            validator_id=val_1_id,
            signing_key=val_1_sk,
            timestamp=utc_now_micros(),
        )
        assert engine.add_vote(vote_round_0) is True

        # Advance engine to round 1
        engine.advance_round()

        # Replaying round 0 vote in round 1 must return False (stale/mismatched)
        assert engine.add_vote(vote_round_0) is False

    def test_vote_from_unknown_validator_rejected(self) -> None:
        """Vote signed by a key not present in active validator set must be rejected."""
        vset, keys = _build_test_validator_set()
        val_0_id, _, val_0_sk = keys[0]
        rogue_pk, rogue_sk = generate_mldsa_keypair()
        rogue_vid = ValidatorID.generate()

        engine = ConsensusEngine(
            validator_id=val_0_id,
            private_key=val_0_sk,
            validator_set=vset,
            chain_id="chain-test-replay",
            state=LedgerState("chain-test-replay"),
            mempool=Mempool(),
        )

        rogue_vote = VoteMessage.create_and_sign(
            chain_id="chain-test-replay",
            height=1,
            round=0,
            vote_type=VoteType.PREVOTE,
            block_hash="sha3-256:" + "02" * 32,
            validator_id=rogue_vid,
            signing_key=rogue_sk,
            timestamp=utc_now_micros(),
        )
        assert engine.add_vote(rogue_vote) is False

    def test_tampered_signature_on_proposal_rejected(self) -> None:
        """Modifying proposal contents must invalidate the cryptographic signature."""
        vset, keys = _build_test_validator_set()
        proposer_id, proposer_pk, proposer_sk = keys[0]

        proposal = ProposalMessage.create_and_sign(
            chain_id="chain-test-replay",
            height=1,
            round=0,
            block_hash="sha3-256:" + "aa" * 32,
            proposer_id=proposer_id,
            signing_key=proposer_sk,
            timestamp=utc_now_micros(),
        )
        assert proposal.verify_signature(proposer_pk) is True

        # Tamper with block_hash without updating signature
        tampered_proposal = ProposalMessage(
            chain_id=proposal.chain_id,
            height=proposal.height,
            round=proposal.round,
            block_hash="sha3-256:" + "ff" * 32,
            proposer_id=proposal.proposer_id,
            timestamp=proposal.timestamp,
            signature=proposal.signature,
        )
        assert tampered_proposal.verify_signature(proposer_pk) is False
