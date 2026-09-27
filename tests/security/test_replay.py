"""Adversarial Anti-Replay Testing Suite for TraceCrypt.

Validates:
- Rejection of duplicate DecryptionEvent submissions.
- Rejection of duplicate SessionID across transactions.
- Rejection of duplicate WatermarkID across transactions.
- Rejection of replayed transactions in both mempool and committed state.
"""

from __future__ import annotations

import pytest

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.errors import ReplayAttackError
from tracecrypt.event.schema import DecryptionEvent, PQCAlgorithms
from tracecrypt.event.signed_event import SignedDecryptionEvent
from tracecrypt.ledger.block import LedgerTransaction
from tracecrypt.ledger.mempool import Mempool
from tracecrypt.ledger.state import LedgerState
from tracecrypt.utils.identifiers import (
    DocumentID,
    EventID,
    RecipientID,
    SessionID,
    TransactionID,
    WatermarkID,
)


def _make_signed_event(
    dsa_sk,
    dsa_pk,
    event_id: EventID | None = None,
    session_id: SessionID | None = None,
    watermark_id: WatermarkID | None = None,
) -> SignedDecryptionEvent:
    eid = event_id or EventID.generate()
    sid = session_id or SessionID.generate()
    wmid = watermark_id or WatermarkID.generate()
    recip_id = RecipientID.generate()

    from tracecrypt.identity.ca import OfflineRootCA
    root_ca = OfflineRootCA.initialize("ca-replay-test")
    cert = root_ca.issue_signing_certificate(
        subject_id=str(recip_id),
        public_key=dsa_pk,
        organization="Test Org",
        role="Recipient",
    )

    event = DecryptionEvent(
        event_id=eid,
        document_id=DocumentID.generate(),
        document_hash="sha3-256:" + "bb" * 32,
        recipient_id=recip_id,
        session_id=sid,
        watermark_id=wmid,
        anti_replay_nonce=SecureRandom.random_nonce_128(),
        timestamp=1700000000000000,
        pqc_algorithms=PQCAlgorithms(),
    )
    from tracecrypt.event.signer import DecryptionEventSigner
    return DecryptionEventSigner.sign_event(event, dsa_sk, cert)


def _make_tx(signed_event: SignedDecryptionEvent, tx_id: TransactionID | None = None) -> LedgerTransaction:
    return LedgerTransaction.from_signed_event(
        transaction_id=tx_id or TransactionID.generate(),
        signed_event=signed_event,
        submitted_at=1700000000000000,
    )


class TestReplayAttacks:
    """Evaluate mempool and state resistance against replay attacks."""

    def test_mempool_duplicate_event_rejection(self) -> None:
        """Mempool must reject replayed EventID."""
        dsa_pk, dsa_sk = generate_mldsa_keypair()
        mempool = Mempool()

        se1 = _make_signed_event(dsa_sk, dsa_pk)
        tx1 = _make_tx(se1)
        mempool.add_transaction(tx1)

        # Replay same event with different TransactionID
        tx2 = _make_tx(se1)

        with pytest.raises(ReplayAttackError, match="Duplicate event"):
            mempool.add_transaction(tx2)

    def test_mempool_duplicate_session_rejection(self) -> None:
        """Mempool must reject replayed SessionID even with new EventID."""
        dsa_pk, dsa_sk = generate_mldsa_keypair()
        mempool = Mempool()
        shared_session = SessionID.generate()

        se1 = _make_signed_event(dsa_sk, dsa_pk, session_id=shared_session)
        tx1 = _make_tx(se1)
        mempool.add_transaction(tx1)

        se2 = _make_signed_event(dsa_sk, dsa_pk, session_id=shared_session)
        tx2 = _make_tx(se2)

        with pytest.raises(ReplayAttackError, match="Duplicate session"):
            mempool.add_transaction(tx2)

    def test_mempool_duplicate_watermark_rejection(self) -> None:
        """Mempool must reject replayed WatermarkID."""
        dsa_pk, dsa_sk = generate_mldsa_keypair()
        mempool = Mempool()
        shared_wmid = WatermarkID.generate()

        se1 = _make_signed_event(dsa_sk, dsa_pk, watermark_id=shared_wmid)
        tx1 = _make_tx(se1)
        mempool.add_transaction(tx1)

        se2 = _make_signed_event(dsa_sk, dsa_pk, watermark_id=shared_wmid)
        tx2 = _make_tx(se2)

        with pytest.raises(ReplayAttackError, match="Duplicate watermark"):
            mempool.add_transaction(tx2)

    def test_state_rejection_against_committed_transactions(self) -> None:
        """Committed state must reject transactions replaying committed identifiers."""
        dsa_pk, dsa_sk = generate_mldsa_keypair()
        state = LedgerState(chain_id="tracecrypt-test-chain")

        se1 = _make_signed_event(dsa_sk, dsa_pk)
        tx1 = _make_tx(se1)
        state.apply_transaction(tx1)

        # 1. Replay exact transaction
        with pytest.raises(ReplayAttackError, match="already committed"):
            state.apply_transaction(tx1)

        # 2. Replay with new tx_id but same event_id
        tx2 = _make_tx(se1)
        with pytest.raises(ReplayAttackError, match="already committed"):
            state.apply_transaction(tx2)

        # 3. Replay with new event_id but same session_id
        se3 = _make_signed_event(dsa_sk, dsa_pk, session_id=se1.event.session_id)
        tx3 = _make_tx(se3)
        with pytest.raises(ReplayAttackError, match="already committed"):
            state.apply_transaction(tx3)

        # 4. Replay with new event_id but same watermark_id
        se4 = _make_signed_event(dsa_sk, dsa_pk, watermark_id=se1.event.watermark_id)
        tx4 = _make_tx(se4)
        with pytest.raises(ReplayAttackError, match="already committed"):
            state.apply_transaction(tx4)
