"""Unit tests for Deterministic Logical State Machine and Anti-Replay."""

import pytest

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.errors import ReplayAttackError
from tracecrypt.event.schema import DecryptionEvent, PQCAlgorithms
from tracecrypt.event.signer import DecryptionEventSigner
from tracecrypt.identity.ca import OfflineRootCA
from tracecrypt.ledger.block import LedgerTransaction
from tracecrypt.ledger.state import LedgerState
from tracecrypt.utils.identifiers import (
    DistributionID,
    DocumentID,
    EventID,
    RecipientID,
    SessionID,
    TransactionID,
    WatermarkID,
)
from tracecrypt.utils.timestamps import utc_now_micros


def make_test_signed_event():
    ca = OfflineRootCA.initialize("ca-test-state")
    pk, sk = generate_mldsa_keypair()
    recip_id = RecipientID.generate()
    cert = ca.issue_signing_certificate(
        subject_id=str(recip_id),
        public_key=pk,
        organization="Test",
        role="Recipient",
    )

    eid = EventID.generate()
    sid = SessionID.generate()
    wmid = WatermarkID.generate()
    did = DocumentID.generate()
    distid = DistributionID.generate()

    event = DecryptionEvent(
        event_version="1.0.0",
        schema_version="1.0.0",
        protocol_version="1.0.0",
        software_version="1.0.0",
        event_type="DECRYPTION_ATTRIBUTION",
        event_id=eid,
        document_id=did,
        distribution_id=distid,
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

    signed_event = DecryptionEventSigner.sign_event(event, sk, cert)
    return signed_event, cert


@pytest.mark.unit
def test_state_apply_valid_transaction():
    state = LedgerState("tracecrypt-test")
    signed_evt, cert = make_test_signed_event()
    tx = LedgerTransaction.from_signed_event(
        transaction_id=TransactionID.generate(),
        signed_event=signed_evt,
        submitted_at=utc_now_micros(),
        recipient_certificate=cert,
    )

    state.apply_transaction(tx)

    assert state.has_event(signed_evt.event.event_id)
    assert state.has_session(signed_evt.event.session_id)
    assert state.has_watermark(signed_evt.event.watermark_id)
    assert state.has_transaction(tx.transaction_id)
    assert state.get_event(signed_evt.event.event_id) is not None


@pytest.mark.unit
def test_state_anti_replay_duplicate_event_id():
    state = LedgerState("tracecrypt-test")
    signed_evt, cert = make_test_signed_event()
    tx1 = LedgerTransaction.from_signed_event(
        transaction_id=TransactionID.generate(),
        signed_event=signed_evt,
        submitted_at=utc_now_micros(),
        recipient_certificate=cert,
    )
    state.apply_transaction(tx1)

    # Attempt to apply tx with duplicate event_id
    tx2 = LedgerTransaction.from_signed_event(
        transaction_id=TransactionID.generate(),
        signed_event=signed_evt,
        submitted_at=utc_now_micros(),
        recipient_certificate=cert,
    )
    with pytest.raises(ReplayAttackError, match="EventID .* already committed"):
        state.apply_transaction(tx2)


@pytest.mark.unit
def test_state_anti_replay_duplicate_watermark_id():
    state = LedgerState("tracecrypt-test")
    signed_evt1, cert = make_test_signed_event()
    tx1 = LedgerTransaction.from_signed_event(
        transaction_id=TransactionID.generate(),
        signed_event=signed_evt1,
        submitted_at=utc_now_micros(),
        recipient_certificate=cert,
    )
    state.apply_transaction(tx1)

    # Create new event sharing the same watermark_id
    signed_evt2, _ = make_test_signed_event()
    evt2_dict = signed_evt2.event.model_dump()
    evt2_dict["watermark_id"] = str(signed_evt1.event.watermark_id)
    evt2 = DecryptionEvent.model_validate(evt2_dict)
    pk, sk = generate_mldsa_keypair()
    ca = OfflineRootCA.initialize("ca-wm-dup")
    c2 = ca.issue_signing_certificate(str(evt2.recipient_id), pk, "Org", "Recip")
    signed_evt2_recreated = DecryptionEventSigner.sign_event(evt2, sk, c2)

    tx2 = LedgerTransaction.from_signed_event(
        transaction_id=TransactionID.generate(),
        signed_event=signed_evt2_recreated,
        submitted_at=utc_now_micros(),
        recipient_certificate=c2,
    )
    with pytest.raises(ReplayAttackError, match="WatermarkID .* already committed"):
        state.apply_transaction(tx2)


@pytest.mark.unit
def test_deterministic_state_root():
    state1 = LedgerState("tracecrypt-test")
    state2 = LedgerState("tracecrypt-test")

    signed_evt1, cert1 = make_test_signed_event()
    signed_evt2, cert2 = make_test_signed_event()

    tx1 = LedgerTransaction.from_signed_event(TransactionID.generate(), signed_evt1, 100, cert1)
    tx2 = LedgerTransaction.from_signed_event(TransactionID.generate(), signed_evt2, 200, cert2)

    # Apply in order tx1, tx2 to state1
    state1.apply_transaction(tx1)
    state1.apply_transaction(tx2)

    # Apply in reverse order tx2, tx1 to state2
    state2.apply_transaction(tx2)
    state2.apply_transaction(tx1)

    # State roots MUST be identical regardless of insertion sequence!
    root1 = state1.compute_state_root()
    root2 = state2.compute_state_root()

    assert root1 == root2
    assert root1.startswith("sha3-256:")
