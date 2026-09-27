"""Unit tests for SQLite storage persistence, indexes, Merkle proof export, and tamper detection."""

import pytest
import sqlite3
from pathlib import Path

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.errors import ChainVerificationError
from tracecrypt.event.schema import DecryptionEvent, PQCAlgorithms
from tracecrypt.event.signer import DecryptionEventSigner
from tracecrypt.identity.ca import OfflineRootCA
from tracecrypt.ledger.block import Block, BlockHeader, LedgerTransaction
from tracecrypt.ledger.genesis import GenesisConfig
from tracecrypt.ledger.merkle import MerkleTree
from tracecrypt.ledger.messages import CommitCertificate, VoteMessage, VoteType
from tracecrypt.ledger.state import LedgerState
from tracecrypt.ledger.storage import LedgerStorage
from tracecrypt.ledger.validator import ValidatorInfo, ValidatorSet
from tracecrypt.utils.identifiers import (
    DistributionID,
    DocumentID,
    EventID,
    RecipientID,
    SessionID,
    TransactionID,
    ValidatorID,
    WatermarkID,
)
from tracecrypt.utils.timestamps import utc_now_micros


def setup_storage_test_env(tmp_path: Path):
    db_path = tmp_path / "test_ledger.db"
    storage = LedgerStorage(db_path)

    # Provision 4 validators
    ca = OfflineRootCA.initialize("ca-storage-test")
    val_infos = []
    val_keys = {}
    for i in range(4):
        vid = ValidatorID.generate()
        pk, sk = generate_mldsa_keypair()
        val_keys[vid] = (pk, sk)
        cert = ca.issue_validator_certificate(str(vid), pk, "Org", "Validator")
        val_infos.append(ValidatorInfo.from_certificate(vid, cert, voting_power=1))

    val_set = ValidatorSet(validators=val_infos)
    genesis = GenesisConfig(
        chain_id="tracecrypt-storage-chain",
        genesis_time=utc_now_micros(),
        validator_set=val_set,
        initial_state_root="sha3-256:0000000000000000000000000000000000000000000000000000000000000000",
    )
    storage.save_genesis(genesis)
    return storage, genesis, val_set, val_keys, ca


def make_test_tx(ca: OfflineRootCA):
    pk, sk = generate_mldsa_keypair()
    recip_id = RecipientID.generate()
    cert = ca.issue_signing_certificate(str(recip_id), pk, "Org", "Recipient")

    eid = EventID.generate()
    sid = SessionID.generate()
    wmid = WatermarkID.generate()
    did = DocumentID.generate()

    event = DecryptionEvent(
        event_version="1.0.0",
        schema_version="1.0.0",
        protocol_version="1.0.0",
        software_version="1.0.0",
        event_type="DECRYPTION_ATTRIBUTION",
        event_id=eid,
        document_id=did,
        distribution_id=DistributionID.generate(),
        document_hash="sha3-256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        recipient_id=recip_id,
        recipient_certificate_id=cert.serial_number,
        session_id=sid,
        watermark_id=wmid,
        watermark_version=1,
        anti_replay_nonce=SecureRandom.random_nonce_128(),
        timestamp=utc_now_micros(),
        pqc_algorithms=PQCAlgorithms(),
    )
    signed_evt = DecryptionEventSigner.sign_event(event, sk, cert)
    return LedgerTransaction.from_signed_event(
        transaction_id=TransactionID.generate(),
        signed_event=signed_evt,
        submitted_at=utc_now_micros(),
        recipient_certificate=cert,
    )


def commit_test_block(
    storage: LedgerStorage,
    height: int,
    prev_hash: str,
    txs,
    val_set,
    val_keys,
    state: LedgerState,
) -> Block:
    # 1. State transition
    for tx in txs:
        state.apply_transaction(tx)
    state_root = state.compute_state_root()

    # 2. Transaction root
    tx_bytes = [t.to_canonical_bytes() for t in txs]
    tx_root = MerkleTree.build_merkle_root(tx_bytes)

    proposer_id = val_set.validators[0].validator_id
    now = utc_now_micros()

    header_proto = BlockHeader(
        chain_id=state.chain_id,
        height=height,
        round=0,
        previous_block_hash=prev_hash,
        timestamp=now,
        proposer_id=proposer_id,
        transaction_root=tx_root,
        state_root=state_root,
        validator_set_hash=val_set.compute_hash(),
        protocol_version="1.0.0",
        block_hash="",
    )
    b_hash = header_proto.compute_block_hash()
    header = header_proto.model_copy(update={"block_hash": b_hash})

    # 3. Create CommitCertificate with 3 Precommits
    votes = []
    for vid in list(val_keys.keys())[:3]:
        _, sk = val_keys[vid]
        v = VoteMessage.create_and_sign(
            chain_id=state.chain_id,
            height=height,
            round=0,
            vote_type=VoteType.PRECOMMIT,
            block_hash=b_hash,
            validator_id=vid,
            signing_key=sk,
            timestamp=now,
        )
        votes.append(v)

    cert = CommitCertificate(
        chain_id=state.chain_id,
        height=height,
        round=0,
        block_hash=b_hash,
        votes=votes,
        validator_set_hash=val_set.compute_hash(),
    )
    block = Block(header=header, transactions=txs, commit_certificate=cert)
    storage.save_block(block)
    return block


@pytest.mark.unit
def test_storage_save_and_retrieve_block(tmp_path: Path):
    storage, genesis, val_set, val_keys, ca = setup_storage_test_env(tmp_path)
    state = LedgerState(genesis.chain_id, genesis.initial_state_root)

    tx1 = make_test_tx(ca)
    tx2 = make_test_tx(ca)
    block1 = commit_test_block(
        storage=storage,
        height=1,
        prev_hash="sha3-256:0000000000000000000000000000000000000000000000000000000000000000",
        txs=[tx1, tx2],
        val_set=val_set,
        val_keys=val_keys,
        state=state,
    )

    retrieved = storage.get_block(1)
    assert retrieved is not None
    assert retrieved.header.block_hash == block1.header.block_hash
    assert len(retrieved.transactions) == 2
    assert retrieved.transactions[0].transaction_id == tx1.transaction_id

    # Forensic lookups
    evt_by_wm = storage.lookup_by_watermark(tx1.signed_event.event.watermark_id)
    assert evt_by_wm is not None
    assert evt_by_wm.event.event_id == tx1.signed_event.event.event_id

    storage.close()


@pytest.mark.unit
def test_storage_verify_chain_clean(tmp_path: Path):
    storage, genesis, val_set, val_keys, ca = setup_storage_test_env(tmp_path)
    state = LedgerState(genesis.chain_id, genesis.initial_state_root)

    tx1 = make_test_tx(ca)
    b1 = commit_test_block(
        storage, 1, "sha3-256:0000000000000000000000000000000000000000000000000000000000000000",
        [tx1], val_set, val_keys, state,
    )

    tx2 = make_test_tx(ca)
    commit_test_block(storage, 2, b1.header.block_hash, [tx2], val_set, val_keys, state)

    # Verification must pass clean
    assert storage.verify_chain(val_set) is True
    storage.close()


@pytest.mark.unit
def test_storage_tamper_detection_altered_database(tmp_path: Path):
    storage, genesis, val_set, val_keys, ca = setup_storage_test_env(tmp_path)
    state = LedgerState(genesis.chain_id, genesis.initial_state_root)

    tx1 = make_test_tx(ca)
    commit_test_block(
        storage, 1, "sha3-256:0000000000000000000000000000000000000000000000000000000000000000",
        [tx1], val_set, val_keys, state,
    )
    storage.close()

    # Directly tamper with SQLite table: alter previous_block_hash
    conn = sqlite3.connect(str(tmp_path / "test_ledger.db"))
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE blocks SET previous_block_hash = "
        "'sha3-256:bad0000000000000000000000000000000000000000000000000000000000000' WHERE height = 1;"
    )
    conn.commit()
    conn.close()

    # Reopen and run verify_chain: MUST detect tampering!
    tampered_storage = LedgerStorage(tmp_path / "test_ledger.db")
    with pytest.raises(ChainVerificationError, match="previous_block_hash mismatch"):
        tampered_storage.verify_chain(val_set)

    tampered_storage.close()


@pytest.mark.unit
def test_storage_export_and_verify_merkle_proof(tmp_path: Path):
    storage, genesis, val_set, val_keys, ca = setup_storage_test_env(tmp_path)
    state = LedgerState(genesis.chain_id, genesis.initial_state_root)

    tx1 = make_test_tx(ca)
    tx2 = make_test_tx(ca)
    tx3 = make_test_tx(ca)
    b1 = commit_test_block(
        storage, 1, "sha3-256:0000000000000000000000000000000000000000000000000000000000000000",
        [tx1, tx2, tx3], val_set, val_keys, state,
    )

    bundle = storage.export_merkle_proof(tx2.transaction_id)
    assert bundle["transaction"]["transaction_id"] == str(tx2.transaction_id)
    assert bundle["block_header"]["block_hash"] == b1.header.block_hash

    # Independent mathematical verification
    proof = bundle["merkle_proof"]
    from tracecrypt.ledger.merkle import MerkleInclusionProof
    proof_obj = MerkleInclusionProof.model_validate(proof)
    leaf_bytes = tx2.to_canonical_bytes()
    assert MerkleTree.verify_merkle_proof(leaf_bytes, proof_obj, b1.header.transaction_root) is True

    storage.close()
