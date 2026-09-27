"""Integration test for 2+2 Network Partition and Post-Healing Recovery.

Guarantees:
- In a 4-node cluster with f=1 (quorum = 3), a 2+2 network split halts liveness but strictly preserves safety.
- Neither partition can achieve quorum (2 < 3 votes), so NO conflicting blocks are finalized.
- When the partition heals and nodes reconnect, consensus proceeds deterministically and finalizes unified history.
"""

from pathlib import Path
import pytest
from tests.integration.test_ledger_cluster import create_cluster, make_signed_event


@pytest.mark.integration
def test_2_plus_2_network_partition_safety_and_recovery(tmp_path: Path):
    """Verify that a 2+2 partition prevents conflicting block finality, and healing restores consensus."""
    nodes, genesis, ca = create_cluster(tmp_path, 4)

    # 1. Commit genesis state / verify height 0
    for n in nodes:
        assert n.storage.get_latest_height() == 0

    # 2. Partition network: Partition A = {Node 1, Node 2}, Partition B = {Node 3, Node 4}
    partition_a = nodes[:2]
    partition_b = nodes[2:]

    # Submit transaction A to Partition A
    evt_a, cert_a = make_signed_event(ca)
    partition_a[0].submit_event(evt_a, recipient_certificate=cert_a)

    # Submit transaction B to Partition B
    evt_b, cert_b = make_signed_event(ca)
    partition_b[0].submit_event(evt_b, recipient_certificate=cert_b)

    # Attempt consensus round within Partition A (only 2 nodes available)
    # Quorum required is 3; 2 votes cannot commit
    res_a = partition_a[0].step_consensus_round(peer_nodes=partition_a[1:])
    assert res_a is None  # Block was NOT committed in Partition A

    # Attempt consensus round within Partition B (only 2 nodes available)
    res_b = partition_b[0].step_consensus_round(peer_nodes=partition_b[1:])
    assert res_b is None  # Block was NOT committed in Partition B

    # Invariant: Neither partition committed any block during split
    for n in nodes:
        assert n.storage.get_latest_height() == 0
        assert n.state.height == 0

    # 3. Heal partition: all 4 nodes can communicate again
    # Execute full consensus round across all 4 nodes
    committed_block = nodes[0].step_consensus_round(peer_nodes=nodes[1:])
    assert committed_block is not None
    assert committed_block.header.height == 1
    assert len(committed_block.commit_certificate.votes) >= 3

    # Invariant: All 4 nodes now have identical finalized block 1
    hashes = {n.storage.get_block(1).header.block_hash for n in nodes}
    state_roots = {n.storage.get_block(1).header.state_root for n in nodes}
    tx_roots = {n.storage.get_block(1).header.transaction_root for n in nodes}

    assert len(hashes) == 1, "Partition healing must converge on identical block hash"
    assert len(state_roots) == 1, "Partition healing must converge on identical state root"
    assert len(tx_roots) == 1, "Partition healing must converge on identical transaction root"

    for n in nodes:
        n.storage.close()
