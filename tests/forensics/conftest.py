"""Shared fixtures and test helpers for TraceCrypt forensic investigation tests."""

from __future__ import annotations

import io
from pathlib import Path
from typing import Dict, List, Tuple
import numpy as np
import pytest
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
from tracecrypt.crypto.pqc_kem import generate_mlkem_keypair
from tracecrypt.event.schema import DecryptionEvent
from tracecrypt.event.signer import DecryptionEventSigner
from tracecrypt.identity.ca import OfflineRootCA
from tracecrypt.identity.certificate import PQCIdentityCertificate
from tracecrypt.identity.keystore import KeystoreManager
from tracecrypt.identity.lifecycle import OfflineRevocationStore
from tracecrypt.ledger.block import Block, BlockHeader, LedgerTransaction
from tracecrypt.ledger.genesis import GenesisConfig
from tracecrypt.ledger.merkle import MerkleTree
from tracecrypt.ledger.messages import CommitCertificate, VoteMessage, VoteType
from tracecrypt.ledger.state import LedgerState
from tracecrypt.ledger.storage import LedgerStorage
from tracecrypt.ledger.validator import ValidatorInfo, ValidatorSet
from tracecrypt.utils.identifiers import RecipientID, TransactionID, ValidatorID
from tracecrypt.utils.timestamps import utc_now_micros


def make_test_pdf_bytes(num_pages: int = 2) -> bytes:
    """Generate in-memory test PDF document."""
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    for p in range(num_pages):
        c.setFont("Helvetica-Bold", 14)
        c.drawString(72, 720, f"TraceCrypt Forensic Test Evidence - Page {p + 1}")
        c.setFont("Helvetica", 10)
        c.drawString(72, 690, "Classified test document for offline blind watermark attribution.")
        for line in range(10):
            msg = f"Paragraph {line}: Secure post-quantum attribution line {p * 10 + line}."
            c.drawString(72, 650 - line * 20, msg)
        c.showPage()
    c.save()
    return buf.getvalue()


def make_test_image_array(h: int = 512, w: int = 512) -> np.ndarray:
    """Generate deterministic synthetic grayscale page image with text-like high frequency patterns."""
    rng = np.random.default_rng(12345)
    img = np.full((h, w), 240, dtype=np.uint8)
    for i in range(20, h - 20, 24):
        for j in range(20, w - 20, 8):
            if rng.random() > 0.4:
                img[i : i + 8, j : j + 6] = rng.integers(20, 60, size=(8, 6), dtype=np.uint8)
    return img


@pytest.fixture
def forensic_environment(tmp_path: Path):
    """Set up complete offline test PKI and 4-validator permissioned ledger cluster."""
    root_ca = OfflineRootCA.initialize("ca-forensic-test")

    # 1. Enroll Recipient Alice
    recip_id = RecipientID.generate()
    kem_pk, kem_sk = generate_mlkem_keypair()
    kem_cert = root_ca.issue_kem_certificate(
        subject_id=str(recip_id),
        public_key=kem_pk,
        organization="Forensic Testing Bureau",
        role="Recipient",
    )
    dsa_pk, dsa_sk = generate_mldsa_keypair()
    dsa_cert = root_ca.issue_signing_certificate(
        subject_id=str(recip_id),
        public_key=dsa_pk,
        organization="Forensic Testing Bureau",
        role="Recipient",
    )

    # 2. Provision 4 Validators for BFT Consensus
    val_infos: List[ValidatorInfo] = []
    val_keys: Dict[ValidatorID, Tuple[bytes, bytes]] = {}
    for i in range(4):
        vid = ValidatorID.generate()
        v_pk, v_sk = generate_mldsa_keypair()
        val_keys[vid] = (v_pk, v_sk)
        v_cert = root_ca.issue_validator_certificate(str(vid), v_pk, "Ledger Consortium", "Validator")
        val_infos.append(ValidatorInfo.from_certificate(vid, v_cert, voting_power=1))

    val_set = ValidatorSet(validators=val_infos)
    db_path = tmp_path / "forensic_ledger.db"
    storage = LedgerStorage(db_path)

    genesis = GenesisConfig(
        chain_id="tracecrypt-forensic-chain",
        genesis_time=utc_now_micros(),
        validator_set=val_set,
        initial_state_root="sha3-256:0000000000000000000000000000000000000000000000000000000000000000",
    )
    storage.save_genesis(genesis)
    state = LedgerState(chain_id=genesis.chain_id, initial_state_root=genesis.initial_state_root)

    # Setup keystore and revocation store
    keystore = KeystoreManager()
    revocation_store = OfflineRevocationStore(tmp_path / "revocations.db")

    class Helper:
        @staticmethod
        def commit_event(
            event: DecryptionEvent,
            signer_sk: bytes,
            cert: PQCIdentityCertificate,
            height: int = 1,
            prev_hash: str = "sha3-256:0000000000000000000000000000000000000000000000000000000000000000",
        ) -> Tuple[Block, LedgerTransaction]:
            signed_evt = DecryptionEventSigner.sign_event(event, signer_sk, cert)
            tx = LedgerTransaction.from_signed_event(
                transaction_id=TransactionID.generate(),
                signed_event=signed_evt,
                submitted_at=utc_now_micros(),
                recipient_certificate=cert,
            )

            state.apply_transaction(tx)
            state_root = state.compute_state_root()

            tx_bytes = [tx.to_canonical_bytes()]
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

            # Create quorum CommitCertificate (3 of 4)
            votes: List[VoteMessage] = []
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

            commit_cert = CommitCertificate(
                chain_id=state.chain_id,
                height=height,
                round=0,
                block_hash=b_hash,
                validator_set_hash=val_set.compute_hash(),
                votes=votes,
            )

            block = Block(
                header=header,
                transactions=[tx],
                commit_certificate=commit_cert,
            )
            storage.save_block(block)
            return block, tx

    return {
        "root_ca": root_ca,
        "recipient_id": recip_id,
        "kem_cert": kem_cert,
        "dsa_cert": dsa_cert,
        "dsa_sk": dsa_sk,
        "storage": storage,
        "val_set": val_set,
        "val_keys": val_keys,
        "state": state,
        "keystore": keystore,
        "revocation_store": revocation_store,
        "helper": Helper,
        "tmp_path": tmp_path,
    }
