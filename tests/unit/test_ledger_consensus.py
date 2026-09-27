"""Unit tests for Tendermint-inspired BFT Consensus Engine."""

import pytest

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
from tracecrypt.errors import (
    ByzantineFaultDetected,
    ConsensusError,
)
from tracecrypt.identity.ca import OfflineRootCA
from tracecrypt.ledger.consensus import ConsensusEngine
from tracecrypt.ledger.mempool import Mempool
from tracecrypt.ledger.messages import (
    VoteMessage,
    VoteType,
)
from tracecrypt.ledger.state import LedgerState
from tracecrypt.ledger.validator import ValidatorInfo, ValidatorSet
from tracecrypt.utils.identifiers import ValidatorID
from tracecrypt.utils.timestamps import utc_now_micros


def setup_cluster_context(num_validators: int = 4):
    ca = OfflineRootCA.initialize("ca-consensus-unit")
    keys = {}
    val_infos = []

    for i in range(num_validators):
        vid = ValidatorID.generate()
        pk, sk = generate_mldsa_keypair()
        keys[vid] = (pk, sk)
        cert = ca.issue_validator_certificate(
            subject_id=str(vid),
            public_key=pk,
            organization="Consensus Cluster",
            role="ConsensusValidator",
        )
        val_infos.append(ValidatorInfo.from_certificate(vid, cert, voting_power=1))

    val_set = ValidatorSet(validators=val_infos)
    chain_id = "tracecrypt-consensus-test"
    return val_set, keys, chain_id


@pytest.mark.unit
def test_designated_proposer_authority():
    val_set, keys, chain_id = setup_cluster_context(4)
    state = LedgerState(chain_id)
    mempool = Mempool()

    proposer_id = val_set.get_proposer(height=1, round_idx=0)
    non_proposer_id = next(v.validator_id for v in val_set.validators if v.validator_id != proposer_id)

    _, non_prop_sk = keys[non_proposer_id]
    engine = ConsensusEngine(
        validator_id=non_proposer_id,
        private_key=non_prop_sk,
        validator_set=val_set,
        chain_id=chain_id,
        state=state,
        mempool=mempool,
    )

    with pytest.raises(ConsensusError, match="not the designated proposer"):
        engine.create_proposal()


@pytest.mark.unit
def test_consensus_full_round_commit_success():
    val_set, keys, chain_id = setup_cluster_context(4)
    state = LedgerState(chain_id)
    mempool = Mempool()

    proposer_id = val_set.get_proposer(height=1, round_idx=0)
    _, prop_sk = keys[proposer_id]

    engine = ConsensusEngine(
        validator_id=proposer_id,
        private_key=prop_sk,
        validator_set=val_set,
        chain_id=chain_id,
        state=state,
        mempool=mempool,
    )

    # 1. Propose
    proposal = engine.create_proposal()
    assert proposal.header.height == 1
    assert proposal.header.proposer_id == proposer_id

    # 2. Prevote (simulate 3 validators prevoting for the proposal)
    prop_hash = proposal.header.block_hash
    now = utc_now_micros()

    for vid in list(val_set.validator_map.keys())[:3]:
        _, sk = keys[vid]
        vote = VoteMessage.create_and_sign(
            chain_id=chain_id,
            height=1,
            round=0,
            vote_type=VoteType.PREVOTE,
            block_hash=prop_hash,
            validator_id=vid,
            signing_key=sk,
            timestamp=now,
        )
        engine.add_vote(vote)

    has_quorum, q_hash = engine.check_prevote_quorum()
    assert has_quorum is True
    assert q_hash == prop_hash
    assert engine.locked_block is not None

    # 3. Precommit (simulate 3 validators precommitting for the proposal)
    for vid in list(val_set.validator_map.keys())[:3]:
        _, sk = keys[vid]
        vote = VoteMessage.create_and_sign(
            chain_id=chain_id,
            height=1,
            round=0,
            vote_type=VoteType.PRECOMMIT,
            block_hash=prop_hash,
            validator_id=vid,
            signing_key=sk,
            timestamp=now,
        )
        engine.add_vote(vote)

    has_precommit_q, cert = engine.check_precommit_quorum()
    assert has_precommit_q is True
    assert cert is not None
    assert cert.block_hash == prop_hash

    # 4. Commit
    committed_block = engine.commit_block(cert)
    assert committed_block is not None
    assert committed_block.header.height == 1
    assert engine.height == 2  # State machine advanced to height 2


@pytest.mark.unit
def test_byzantine_equivocation_detection():
    val_set, keys, chain_id = setup_cluster_context(4)
    state = LedgerState(chain_id)
    mempool = Mempool()

    vid = val_set.validators[0].validator_id
    _, sk = keys[vid]

    engine = ConsensusEngine(
        validator_id=val_set.validators[1].validator_id,
        private_key=keys[val_set.validators[1].validator_id][1],
        validator_set=val_set,
        chain_id=chain_id,
        state=state,
        mempool=mempool,
    )

    now = utc_now_micros()
    # First vote: block A
    vote_a = VoteMessage.create_and_sign(
        chain_id=chain_id,
        height=1,
        round=0,
        vote_type=VoteType.PREVOTE,
        block_hash="sha3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        validator_id=vid,
        signing_key=sk,
        timestamp=now,
    )
    engine.add_vote(vote_a)

    # Second conflicting vote by same validator: block B (equivocation!)
    vote_b = VoteMessage.create_and_sign(
        chain_id=chain_id,
        height=1,
        round=0,
        vote_type=VoteType.PREVOTE,
        block_hash="sha3-256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        validator_id=vid,
        signing_key=sk,
        timestamp=now,
    )

    with pytest.raises(ByzantineFaultDetected, match="equivocated"):
        engine.add_vote(vote_b)

    # Verify evidence was recorded
    assert len(engine.evidence_log) == 1
    evidence = list(engine.evidence_log.values())[0]
    assert evidence.validator_id == vid
    assert evidence.verify(val_set.get_validator(vid).get_public_key()) is True


@pytest.mark.unit
def test_insufficient_quorum_does_not_commit():
    val_set, keys, chain_id = setup_cluster_context(4)
    state = LedgerState(chain_id)
    mempool = Mempool()

    proposer_id = val_set.get_proposer(height=1, round_idx=0)
    _, prop_sk = keys[proposer_id]

    engine = ConsensusEngine(
        validator_id=proposer_id,
        private_key=prop_sk,
        validator_set=val_set,
        chain_id=chain_id,
        state=state,
        mempool=mempool,
    )
    proposal = engine.create_proposal()

    # Only 2 validators vote (quorum requires 3 of 4)
    now = utc_now_micros()
    for vid in list(val_set.validator_map.keys())[:2]:
        _, sk = keys[vid]
        vote = VoteMessage.create_and_sign(
            chain_id=chain_id,
            height=1,
            round=0,
            vote_type=VoteType.PRECOMMIT,
            block_hash=proposal.header.block_hash,
            validator_id=vid,
            signing_key=sk,
            timestamp=now,
        )
        engine.add_vote(vote)

    has_precommit_q, cert = engine.check_precommit_quorum()
    assert has_precommit_q is False
    assert cert is None


@pytest.mark.unit
def test_advance_round_switches_proposer():
    val_set, keys, chain_id = setup_cluster_context(4)
    state = LedgerState(chain_id)
    mempool = Mempool()

    vid = val_set.validators[0].validator_id
    _, sk = keys[vid]

    engine = ConsensusEngine(vid, sk, val_set, chain_id, state, mempool)

    proposer_r0 = val_set.get_proposer(height=1, round_idx=0)
    engine.advance_round()
    assert engine.round == 1
    proposer_r1 = val_set.get_proposer(height=1, round_idx=1)

    assert proposer_r0 != proposer_r1
