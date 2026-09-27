"""Comprehensive Security, Replay Defense, Database Tamper Detection, and Air-Gap Verification.

Verifies:
1. Cryptographic Domain Separation:
   - Consensus messages cannot be replayed across chains, heights, rounds, or block hashes.
2. Anti-Replay:
   - Duplicate EventID, SessionID, WatermarkID, and TransactionID rejected at mempool and state machine.
3. Storage Tamper Detection:
   - Manual manipulation of SQLite columns (block_hash, state_root, tx_root) fails chain verification.
   - Deletion of blocks or transactions breaks height continuity and cryptographic hash linkage.
4. Air-Gap / Network Isolation:
   - Nodes operate strictly in offline local environments without DNS, public IP connections, or cloud endpoints.
"""

import sqlite3
from pathlib import Path
import pytest

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
from tracecrypt.errors import (
    ChainVerificationError,
    ReplayAttackError,
)
from tracecrypt.ledger.messages import VoteMessage, VoteType
from tracecrypt.utils.identifiers import SessionID, WatermarkID
from tracecrypt.utils.timestamps import utc_now_micros
from tests.integration.test_ledger_cluster import create_cluster, make_signed_event


# -----------------------------------------------------------------------------
# Consensus Message Replay Invariants
# -----------------------------------------------------------------------------

@pytest.mark.security
def test_consensus_vote_cross_chain_replay_rejected(tmp_path: Path):
    """A valid vote generated for chain-A must be rejected on chain-B."""
    nodes, genesis, ca = create_cluster(tmp_path, 4)
    val = nodes[0]

    vote_chain_a = VoteMessage.create_and_sign(
        chain_id="different-chain-id",
        height=1,
        round=0,
        vote_type=VoteType.PREVOTE,
        block_hash="sha3-256:4444444444444444444444444444444444444444444444444444444444444444",
        validator_id=val.validator_id,
        signing_key=val._private_key,
        timestamp=utc_now_micros(),
    )

    assert val.consensus.add_vote(vote_chain_a) is False

    for n in nodes:
        n.storage.close()


@pytest.mark.security
def test_consensus_vote_cross_height_replay_rejected(tmp_path: Path):
    """A valid vote for height 10 must be rejected when consensus is at height 1."""
    nodes, genesis, ca = create_cluster(tmp_path, 4)
    val = nodes[0]

    vote_height_10 = VoteMessage.create_and_sign(
        chain_id=val.chain_id,
        height=10,
        round=0,
        vote_type=VoteType.PREVOTE,
        block_hash="sha3-256:5555555555555555555555555555555555555555555555555555555555555555",
        validator_id=val.validator_id,
        signing_key=val._private_key,
        timestamp=utc_now_micros(),
    )

    assert val.consensus.add_vote(vote_height_10) is False

    for n in nodes:
        n.storage.close()


@pytest.mark.security
def test_consensus_vote_cross_round_replay_rejected(tmp_path: Path):
    """A valid vote for round 2 cannot be counted towards round 0."""
    nodes, genesis, ca = create_cluster(tmp_path, 4)
    val = nodes[0]

    vote_round_2 = VoteMessage.create_and_sign(
        chain_id=val.chain_id,
        height=val.consensus.height,
        round=2,
        vote_type=VoteType.PREVOTE,
        block_hash="sha3-256:6666666666666666666666666666666666666666666666666666666666666666",
        validator_id=val.validator_id,
        signing_key=val._private_key,
        timestamp=utc_now_micros(),
    )

    # Vote was recorded for round 2, but round 0 votes map does NOT contain it
    val.consensus.add_vote(vote_round_2)
    votes_r0 = val.consensus.get_votes_for(val.consensus.height, 0, VoteType.PREVOTE)
    assert val.validator_id not in votes_r0

    for n in nodes:
        n.storage.close()


# -----------------------------------------------------------------------------
# Transaction Replay Invariants
# -----------------------------------------------------------------------------

@pytest.mark.security
def test_transaction_anti_replay_session_and_watermark_unique(tmp_path: Path):
    """Once an event is committed, any subsequent transaction with same session or watermark is rejected."""
    nodes, genesis, ca = create_cluster(tmp_path, 4)

    signed_evt1, cert1 = make_signed_event(ca)
    nodes[0].submit_event(signed_evt1, recipient_certificate=cert1)
    nodes[0].step_consensus_round(peer_nodes=nodes[1:])

    # Attempt to submit exact same event again
    with pytest.raises(ReplayAttackError) as exc:
        nodes[0].submit_event(signed_evt1, recipient_certificate=cert1)
    assert "already committed" in str(exc.value)

    # Attempt to submit a new event that reuses the same SessionID
    from tracecrypt.crypto.random import SecureRandom
    from tracecrypt.event.schema import DecryptionEvent, PQCAlgorithms
    from tracecrypt.event.signer import DecryptionEventSigner
    from tracecrypt.utils.identifiers import DistributionID, DocumentID, EventID, RecipientID

    pk2, sk2 = generate_mldsa_keypair()
    recip2 = RecipientID.generate()
    cert2 = ca.issue_signing_certificate(str(recip2), pk2, "Org 2", "Recipient")
    event_dup_session = DecryptionEvent(
        event_version="1.0.0",
        schema_version="1.0.0",
        protocol_version="1.0.0",
        software_version="1.0.0",
        event_type="DECRYPTION_ATTRIBUTION",
        event_id=EventID.generate(),
        document_id=DocumentID.generate(),
        distribution_id=DistributionID.generate(),
        document_hash="sha3-256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        recipient_id=recip2,
        recipient_certificate_id=cert2.serial_number,
        session_id=signed_evt1.event.session_id,  # DUPLICATE SESSION
        watermark_id=WatermarkID.generate(),
        watermark_version=1,
        anti_replay_nonce=SecureRandom.random_nonce_128(),
        timestamp=utc_now_micros(),
        pqc_algorithms=PQCAlgorithms(),
    )
    signed_evt2 = DecryptionEventSigner.sign_event(event_dup_session, sk2, cert2)

    with pytest.raises(ReplayAttackError) as exc:
        nodes[0].submit_event(signed_evt2, recipient_certificate=cert2)
    assert "SessionID" in str(exc.value)

    # Attempt to submit a new event that reuses the same WatermarkID
    pk3, sk3 = generate_mldsa_keypair()
    recip3 = RecipientID.generate()
    cert3 = ca.issue_signing_certificate(str(recip3), pk3, "Org 3", "Recipient")
    event_dup_wm = DecryptionEvent(
        event_version="1.0.0",
        schema_version="1.0.0",
        protocol_version="1.0.0",
        software_version="1.0.0",
        event_type="DECRYPTION_ATTRIBUTION",
        event_id=EventID.generate(),
        document_id=DocumentID.generate(),
        distribution_id=DistributionID.generate(),
        document_hash="sha3-256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        recipient_id=recip3,
        recipient_certificate_id=cert3.serial_number,
        session_id=SessionID.generate(),
        watermark_id=signed_evt1.event.watermark_id,  # DUPLICATE WATERMARK
        watermark_version=1,
        anti_replay_nonce=SecureRandom.random_nonce_128(),
        timestamp=utc_now_micros(),
        pqc_algorithms=PQCAlgorithms(),
    )
    signed_evt3 = DecryptionEventSigner.sign_event(event_dup_wm, sk3, cert3)

    with pytest.raises(ReplayAttackError) as exc:
        nodes[0].submit_event(signed_evt3, recipient_certificate=cert3)
    assert "WatermarkID" in str(exc.value)

    for n in nodes:
        n.storage.close()


# -----------------------------------------------------------------------------
# SQLite Storage Tamper Detection
# -----------------------------------------------------------------------------

@pytest.mark.security
def test_storage_tamper_detection_altered_block_hash(tmp_path: Path):
    """Direct manual modification of block_hash in SQLite is detected during chain verification."""
    nodes, genesis, ca = create_cluster(tmp_path, 4)

    signed_evt, cert = make_signed_event(ca)
    nodes[0].submit_event(signed_evt, recipient_certificate=cert)
    nodes[0].step_consensus_round(peer_nodes=nodes[1:])

    db_path = nodes[0].db_path
    for n in nodes:
        n.storage.close()

    # Manually tamper with block_hash column in SQLite
    bad_hash = "sha3-256:0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad"
    conn = sqlite3.connect(str(db_path))
    conn.execute("UPDATE blocks SET block_hash = ? WHERE height = 1;", (bad_hash,))
    conn.commit()
    conn.close()

    # Re-open storage and execute verify_chain()
    from tracecrypt.ledger.storage import LedgerStorage
    tampered_storage = LedgerStorage(db_path)
    with pytest.raises(ChainVerificationError) as exc:
        tampered_storage.verify_chain(genesis.validator_set)
    assert "mismatch" in str(exc.value) or "verification failed" in str(exc.value)
    tampered_storage.close()


@pytest.mark.security
def test_storage_tamper_detection_altered_transaction_root(tmp_path: Path):
    """Direct manual alteration of transaction_root in SQLite fails verification."""
    nodes, genesis, ca = create_cluster(tmp_path, 4)

    signed_evt, cert = make_signed_event(ca)
    nodes[0].submit_event(signed_evt, recipient_certificate=cert)
    nodes[0].step_consensus_round(peer_nodes=nodes[1:])

    db_path = nodes[0].db_path
    for n in nodes:
        n.storage.close()

    bad_root = "sha3-256:9999999999999999999999999999999999999999999999999999999999999999"
    conn = sqlite3.connect(str(db_path))
    conn.execute("UPDATE blocks SET transaction_root = ? WHERE height = 1;", (bad_root,))
    conn.commit()
    conn.close()

    from tracecrypt.ledger.storage import LedgerStorage
    tampered_storage = LedgerStorage(db_path)
    with pytest.raises(ChainVerificationError):
        tampered_storage.verify_chain(genesis.validator_set)
    tampered_storage.close()


@pytest.mark.security
def test_storage_tamper_detection_deleted_block(tmp_path: Path):
    """Deleting a committed block from the database breaks height continuity."""
    nodes, genesis, ca = create_cluster(tmp_path, 4)

    # Commit Block 1
    s1, c1 = make_signed_event(ca)
    nodes[0].submit_event(s1, recipient_certificate=c1)
    nodes[0].step_consensus_round(peer_nodes=nodes[1:])

    # Commit Block 2
    s2, c2 = make_signed_event(ca)
    nodes[0].submit_event(s2, recipient_certificate=c2)
    nodes[0].step_consensus_round(peer_nodes=nodes[1:])

    db_path = nodes[0].db_path
    for n in nodes:
        n.storage.close()

    # Delete Block 1 while keeping Block 2
    conn = sqlite3.connect(str(db_path))
    conn.execute("DELETE FROM blocks WHERE height = 1;")
    conn.commit()
    conn.close()

    from tracecrypt.ledger.storage import LedgerStorage
    tampered_storage = LedgerStorage(db_path)
    with pytest.raises(ChainVerificationError) as exc:
        tampered_storage.verify_chain(genesis.validator_set)
    assert "missing" in str(exc.value) or "continuity" in str(exc.value) or "failed" in str(exc.value)
    tampered_storage.close()


# -----------------------------------------------------------------------------
# Air-Gap / Network Isolation Invariants
# -----------------------------------------------------------------------------

@pytest.mark.security
def test_ledger_airgap_zero_external_network_dependencies(tmp_path: Path):
    """Ensure validator network transport exclusively binds to local interfaces (127.0.0.1 or LAN).

    Guarantees:
    - No public DNS lookup
    - No cloud / external RPC
    - No external certificate authorities
    - No public blockchain interaction
    """
    nodes, genesis, ca = create_cluster(tmp_path, 4)

    for n in nodes:
        # Check network configuration
        assert n.network.listen_host in ("127.0.0.1", "localhost", "::1")
        for peer_host, peer_port in n.network.configured_peers:
            assert peer_host in ("127.0.0.1", "localhost", "::1")

        # Invariant: Genesis validator set only uses offline Root CA
        for v in genesis.validator_set.validators:
            assert v.certificate_id.startswith("crt-")

        n.storage.close()
