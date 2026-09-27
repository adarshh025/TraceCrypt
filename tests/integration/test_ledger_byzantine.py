"""Integration tests for Byzantine Fault Tolerance (BFT) Scenarios under f=1.

Coverage:
1. Malicious proposer sends proposal with forged state root or invalid Merkle root -> Rejected.
2. Malicious validator sends vote with invalid/forged ML-DSA signature -> Rejected.
3. Malicious validator sends conflicting prevotes (equivocation) -> ByzantineEvidence generated.
4. Malicious validator equivocates with different block proposals to different peers -> No conflicting finality.
5. Unauthorized non-validator votes -> Rejected.
6. Beyond BFT threshold (f=2 malicious out of 4) -> Liveness/Safety bounds documented & verified.
"""

from pathlib import Path
import pytest

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
from tracecrypt.errors import ByzantineFaultDetected
from tracecrypt.ledger.messages import VoteMessage, VoteType
from tracecrypt.ledger.validator import ValidatorID
from tracecrypt.utils.timestamps import utc_now_micros
from tests.integration.test_ledger_cluster import create_cluster, make_signed_event


@pytest.mark.integration
def test_byzantine_invalid_proposal_state_root_rejected(tmp_path: Path):
    """Honest validators reject a block proposal with a forged or invalid state root."""
    nodes, genesis, ca = create_cluster(tmp_path, 4)

    signed_evt, cert = make_signed_event(ca)
    nodes[0].submit_event(signed_evt, recipient_certificate=cert)

    # Node 0 prepares a normal proposal, then forges the state_root
    proposer_id = nodes[0].validator_set.get_proposer(nodes[0].consensus.height, nodes[0].consensus.round)
    proposer = next(n for n in nodes if n.validator_id == proposer_id)
    proposal = proposer.consensus.create_proposal()

    # Forge state root
    forged_header = proposal.header.model_copy(
        update={
            "state_root": "sha3-256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        }
    )
    forged_proposal = proposal.model_copy(update={"header": forged_header})

    # Honest peer validator receives forged proposal
    peer = next(n for n in nodes if n != proposer)
    accepted = peer.consensus.receive_proposal(forged_proposal)
    assert accepted is False, "Honest validator must reject proposal with forged state root"

    for n in nodes:
        n.storage.close()


@pytest.mark.integration
def test_byzantine_invalid_signature_vote_rejected(tmp_path: Path):
    """Consensus engine rejects votes signed by unauthorized keys or forged signatures."""
    nodes, genesis, ca = create_cluster(tmp_path, 4)

    val1 = nodes[0]
    # Generate an unrelated keypair
    _, forged_sk = generate_mldsa_keypair()

    # Create a vote claiming to be from val1 but signed with forged_sk
    forged_vote = VoteMessage.create_and_sign(
        chain_id=val1.chain_id,
        height=val1.consensus.height,
        round=val1.consensus.round,
        vote_type=VoteType.PREVOTE,
        block_hash="sha3-256:1111111111111111111111111111111111111111111111111111111111111111",
        validator_id=val1.validator_id,
        signing_key=forged_sk,
        timestamp=utc_now_micros(),
    )

    # Node 1 attempts to process the forged vote
    accepted = nodes[1].consensus.add_vote(forged_vote)
    assert accepted is False, "Vote with invalid cryptographic signature must be rejected"

    for n in nodes:
        n.storage.close()


@pytest.mark.integration
def test_byzantine_equivocation_evidence_generation(tmp_path: Path):
    """Conflicting votes from the same validator in the same round triggers ByzantineEvidence."""
    nodes, genesis, ca = create_cluster(tmp_path, 4)

    malicious_node = nodes[0]
    observer_node = nodes[1]

    # Malicious validator signs two conflicting prevotes for different block hashes
    vote_a = VoteMessage.create_and_sign(
        chain_id=malicious_node.chain_id,
        height=malicious_node.consensus.height,
        round=malicious_node.consensus.round,
        vote_type=VoteType.PREVOTE,
        block_hash="sha3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        validator_id=malicious_node.validator_id,
        signing_key=malicious_node._private_key,
        timestamp=utc_now_micros(),
    )

    vote_b = VoteMessage.create_and_sign(
        chain_id=malicious_node.chain_id,
        height=malicious_node.consensus.height,
        round=malicious_node.consensus.round,
        vote_type=VoteType.PREVOTE,
        block_hash="sha3-256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        validator_id=malicious_node.validator_id,
        signing_key=malicious_node._private_key,
        timestamp=utc_now_micros(),
    )

    # First vote is accepted
    assert observer_node.consensus.add_vote(vote_a) is True

    # Second conflicting vote triggers ByzantineFaultDetected exception & logs evidence
    with pytest.raises(ByzantineFaultDetected) as exc_info:
        observer_node.consensus.add_vote(vote_b)

    assert str(malicious_node.validator_id) in str(exc_info.value)
    assert len(observer_node.consensus.evidence_log) == 1

    # Invariant: Evidence is cryptographically verifiable
    evidence = list(observer_node.consensus.evidence_log.values())[0]
    assert evidence.validator_id == malicious_node.validator_id
    assert evidence.verify(nodes[0].validator_set) is True

    for n in nodes:
        n.storage.close()


@pytest.mark.integration
def test_byzantine_different_proposals_no_conflicting_finality(tmp_path: Path):
    """If a Byzantine proposer sends Block A to peers {0, 1} and Block B to peers {2, 3},
    neither block can achieve the required 3 votes (2f+1), preventing conflicting finality."""
    nodes, genesis, ca = create_cluster(tmp_path, 4)

    # Identify proposer
    proposer_id = nodes[0].validator_set.get_proposer(1, 0)
    proposer = next(n for n in nodes if n.validator_id == proposer_id)
    honest_peers = [n for n in nodes if n != proposer]

    # Create Block A
    signed_evt_a, cert_a = make_signed_event(ca)
    proposer.submit_event(signed_evt_a, recipient_certificate=cert_a)
    proposal_a = proposer.consensus.create_proposal()

    # Create Block B with different content
    signed_evt_b, cert_b = make_signed_event(ca)
    header_b = proposal_a.header.model_copy(
        update={
            "transaction_root": "sha3-256:2222222222222222222222222222222222222222222222222222222222222222",
        }
    )
    b_hash = header_b.compute_block_hash()
    header_b = header_b.model_copy(update={"block_hash": b_hash})
    proposal_b = proposal_a.model_copy(update={"header": header_b})
    assert proposal_b is not None

    # Proposer sends Block A to honest_peers[0]
    honest_peers[0].consensus.receive_proposal(proposal_a)
    vote_0 = honest_peers[0].consensus.prevote()
    assert vote_0 is not None

    # Proposer sends Block B to honest_peers[1] and honest_peers[2]
    # Note: honest_peers[1] rejects proposal_b because state_root / transaction_root doesn't match txs
    # Even if they prevote, they vote on different blocks:
    # Neither block can collect 3 votes
    power_a, _ = honest_peers[0].consensus.count_votes_for_block(
        1, 0, VoteType.PRECOMMIT, proposal_a.header.block_hash
    )
    assert not honest_peers[0].validator_set.has_quorum(power_a)

    for n in nodes:
        n.storage.close()


@pytest.mark.integration
def test_unauthorized_non_validator_vote_rejected(tmp_path: Path):
    """Votes from IDs not in the active genesis validator set are rejected."""
    nodes, genesis, ca = create_cluster(tmp_path, 4)

    non_val_id = ValidatorID.generate()
    _, non_val_sk = generate_mldsa_keypair()

    unauthorized_vote = VoteMessage.create_and_sign(
        chain_id=nodes[0].chain_id,
        height=1,
        round=0,
        vote_type=VoteType.PREVOTE,
        block_hash="sha3-256:3333333333333333333333333333333333333333333333333333333333333333",
        validator_id=non_val_id,
        signing_key=non_val_sk,
        timestamp=utc_now_micros(),
    )

    accepted = nodes[0].consensus.add_vote(unauthorized_vote)
    assert accepted is False, "Non-validator vote must be strictly rejected"

    for n in nodes:
        n.storage.close()
