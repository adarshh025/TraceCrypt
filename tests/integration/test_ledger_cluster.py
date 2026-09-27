"""Integration tests for 4-Node BFT Ledger Cluster, Divergence Defense, and State Catch-Up."""

import pytest
from pathlib import Path

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.event.schema import DecryptionEvent, PQCAlgorithms
from tracecrypt.event.signer import DecryptionEventSigner
from tracecrypt.identity.ca import OfflineRootCA
from tracecrypt.ledger.genesis import GenesisConfig
from tracecrypt.ledger.node import BFTLedgerNode
from tracecrypt.ledger.validator import NodeRole, ValidatorInfo, ValidatorSet
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


def create_cluster(tmp_path: Path, num_validators: int = 4):
    ca = OfflineRootCA.initialize("ca-cluster-test")
    val_infos = []
    val_keys = {}

    for i in range(num_validators):
        vid = ValidatorID.generate()
        pk, sk = generate_mldsa_keypair()
        val_keys[vid] = (pk, sk)
        cert = ca.issue_validator_certificate(str(vid), pk, "Cluster Org", "Validator")
        val_infos.append(ValidatorInfo.from_certificate(vid, cert, voting_power=1))

    val_set = ValidatorSet(validators=val_infos)
    genesis = GenesisConfig(
        chain_id="tracecrypt-integ-cluster",
        genesis_time=utc_now_micros(),
        validator_set=val_set,
        initial_state_root="sha3-256:0000000000000000000000000000000000000000000000000000000000000000",
    )

    nodes = []
    for i, v_info in enumerate(val_infos):
        node_dir = tmp_path / f"node_{i+1}"
        node_dir.mkdir(parents=True, exist_ok=True)
        _, sk = val_keys[v_info.validator_id]
        node = BFTLedgerNode(
            validator_id=v_info.validator_id,
            private_key=sk,
            genesis=genesis,
            data_dir=node_dir,
            listen_host="127.0.0.1",
            listen_port=9200 + i,
            peers=[("127.0.0.1", 9200 + j) for j in range(num_validators) if j != i],
            role=NodeRole.VALIDATOR,
        )
        nodes.append(node)

    return nodes, genesis, ca


def make_signed_event(ca: OfflineRootCA):
    pk, sk = generate_mldsa_keypair()
    recip_id = RecipientID.generate()
    cert = ca.issue_signing_certificate(str(recip_id), pk, "Attributed Org", "Recipient")

    event = DecryptionEvent(
        event_version="1.0.0",
        schema_version="1.0.0",
        protocol_version="1.0.0",
        software_version="1.0.0",
        event_type="DECRYPTION_ATTRIBUTION",
        event_id=EventID.generate(),
        document_id=DocumentID.generate(),
        distribution_id=DistributionID.generate(),
        document_hash="sha3-256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        recipient_id=recip_id,
        recipient_certificate_id=cert.serial_number,
        session_id=SessionID.generate(),
        watermark_id=WatermarkID.generate(),
        watermark_version=1,
        anti_replay_nonce=SecureRandom.random_nonce_128(),
        timestamp=utc_now_micros(),
        pqc_algorithms=PQCAlgorithms(),
    )
    signed_evt = DecryptionEventSigner.sign_event(event, sk, cert)
    return signed_evt, cert


@pytest.mark.integration
def test_4_node_cluster_identical_lockstep_and_zero_divergence(tmp_path: Path):
    nodes, genesis, ca = create_cluster(tmp_path, 4)

    # Submit transaction to node 1
    signed_evt, cert = make_signed_event(ca)
    receipt = nodes[0].submit_event(signed_evt, recipient_certificate=cert)
    assert receipt.is_committed is False  # PENDING before consensus

    # Step consensus round across all 4 nodes
    block = nodes[0].step_consensus_round(peer_nodes=nodes[1:])
    assert block is not None
    assert block.header.height == 1

    # Verify identical block hash, state root, and transaction root on all 4 nodes
    hashes = set()
    state_roots = set()
    tx_roots = set()

    for n in nodes:
        blk = n.storage.get_block(1)
        assert blk is not None
        hashes.add(blk.header.block_hash)
        state_roots.add(blk.header.state_root)
        tx_roots.add(blk.header.transaction_root)

    # Invariant: ZERO divergence across all validators
    assert len(hashes) == 1
    assert len(state_roots) == 1
    assert len(tx_roots) == 1

    for n in nodes:
        n.storage.close()


@pytest.mark.integration
def test_1_validator_offline_tolerates_byzantine_fault(tmp_path: Path):
    nodes, genesis, ca = create_cluster(tmp_path, 4)

    # Node 4 is OFFLINE
    active_nodes = nodes[:3]

    signed_evt, cert = make_signed_event(ca)
    active_nodes[0].submit_event(signed_evt, recipient_certificate=cert)

    # Consensus with only 3 nodes (2f+1 quorum = 3 of 4)
    block = active_nodes[0].step_consensus_round(peer_nodes=active_nodes[1:])
    assert block is not None
    assert block.header.height == 1
    assert len(block.commit_certificate.votes) == 3

    for n in nodes:
        n.storage.close()


@pytest.mark.integration
def test_node_catch_up_and_state_synchronization(tmp_path: Path):
    nodes, genesis, ca = create_cluster(tmp_path, 4)

    # Nodes 1, 2, 3 commit Block 1 while Node 4 is offline
    active_nodes = nodes[:3]
    offline_node = nodes[3]

    signed_evt1, cert1 = make_signed_event(ca)
    active_nodes[0].submit_event(signed_evt1, recipient_certificate=cert1)
    b1 = active_nodes[0].step_consensus_round(peer_nodes=active_nodes[1:])
    assert b1 is not None

    # Offline node is at height 0
    assert offline_node.storage.get_latest_height() == 0

    # Offline node comes back online and synchronizes from Node 1
    sync_req = offline_node.sync_manager.create_sync_request()
    assert sync_req.start_height == 1

    sync_resp = active_nodes[0].sync_manager.handle_sync_request(sync_req)
    assert len(sync_resp.blocks) == 1

    applied = offline_node.sync_manager.apply_sync_response(sync_resp)
    assert applied == 1
    assert offline_node.storage.get_latest_height() == 1

    # Invariant: Synchronized node has exact same state root and block hash as peers
    synchronized_block = offline_node.storage.get_block(1)
    assert synchronized_block.header.block_hash == b1.header.block_hash
    assert offline_node.state.state_root == active_nodes[0].state.state_root

    for n in nodes:
        n.storage.close()


@pytest.mark.integration
def test_node_restart_and_recovery(tmp_path: Path):
    nodes, genesis, ca = create_cluster(tmp_path, 4)

    # Commit Block 1
    signed_evt, cert = make_signed_event(ca)
    nodes[0].submit_event(signed_evt, recipient_certificate=cert)
    nodes[0].step_consensus_round(peer_nodes=nodes[1:])

    node1_dir = nodes[0].data_dir
    val1_id = nodes[0].validator_id
    val1_sk = nodes[0]._private_key

    # Stop node 1
    for n in nodes:
        n.storage.close()

    # Re-instantiate node 1 from same data directory (simulates crash & restart)
    recovered_node = BFTLedgerNode(
        validator_id=val1_id,
        private_key=val1_sk,
        genesis=genesis,
        data_dir=node1_dir,
        role=NodeRole.VALIDATOR,
    )

    # Node startup verification ran automatically
    assert recovered_node.storage.get_latest_height() == 1
    assert recovered_node.consensus.height == 2
    assert recovered_node.state.has_event(signed_evt.event.event_id)

    recovered_node.storage.close()
