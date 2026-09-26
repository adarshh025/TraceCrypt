"""Unit tests for InMemoryLedgerAdapter enforcing replay protection, status tracking, and simulated failure modes."""

import pytest

from tracecrypt.crypto.random import SecureRandom
from tracecrypt.errors import LedgerError, ReplayAttackError
from tracecrypt.event.schema import DecryptionEvent, PQCAlgorithms
from tracecrypt.event.signed_event import SignedDecryptionEvent
from tracecrypt.ledger.in_memory_adapter import InMemoryLedgerAdapter
from tracecrypt.ledger.types import CommitStatus
from tracecrypt.utils.identifiers import (
    DistributionID,
    DocumentID,
    EventID,
    RecipientID,
    SessionID,
    WatermarkID,
)


def make_dummy_signed_event(
    event_id=None,
    document_id=None,
    session_id=None,
    watermark_id=None,
) -> SignedDecryptionEvent:
    eid = event_id or SecureRandom.generate_typed_id(EventID)
    did = document_id or SecureRandom.generate_typed_id(DocumentID)
    sid = session_id or SecureRandom.generate_typed_id(SessionID)
    wmid = watermark_id or SecureRandom.generate_typed_id(WatermarkID)

    event = DecryptionEvent(
        event_version="1.0.0",
        schema_version="1.0.0",
        protocol_version="1.0.0",
        software_version="1.0.0",
        event_type="DECRYPTION_ATTRIBUTION",
        event_id=eid,
        document_id=did,
        distribution_id=SecureRandom.generate_typed_id(DistributionID),
        document_hash="sha3-256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        recipient_id=RecipientID("rcp-0123456789abcdef0123456789abcdef"),
        session_id=sid,
        watermark_id=wmid,
        watermark_version=1,
        anti_replay_nonce=SecureRandom.generate_nonce(16),
        timestamp=1727280000000000,
        pqc_algorithms=PQCAlgorithms(),
    )

    import base64
    return SignedDecryptionEvent(
        event=event,
        canonical_event=event.to_canonical_bytes().decode("utf-8"),
        event_digest=event.compute_event_digest(),
        signature=base64.b64encode(b"\x55" * 3309).decode("ascii"),
        signing_key_id="key-test",
        certificate_id="crt-test",
        certificate_fingerprint="mldsa65:test",
        signed_at=1727280000000000,
    )


@pytest.mark.unit
def test_ledger_submit_and_retrieve_success():
    ledger = InMemoryLedgerAdapter()
    assert ledger.ENVIRONMENT == "DEVELOPMENT / TEST ONLY"

    signed_event = make_dummy_signed_event()
    receipt = ledger.submit_event(signed_event)

    assert receipt.status == CommitStatus.COMMITTED
    assert receipt.is_committed is True
    assert receipt.transaction_id.startswith("tx-")
    assert receipt.event_id == signed_event.event.event_id

    # Retrieve by EventID
    retrieved = ledger.get_event(signed_event.event.event_id)
    assert retrieved is not None
    assert retrieved.ledger_transaction_id == receipt.transaction_id

    # Lookup by WatermarkID
    by_wm = ledger.lookup_by_watermark(signed_event.event.watermark_id)
    assert by_wm is not None
    assert by_wm.event.event_id == signed_event.event.event_id


@pytest.mark.unit
def test_ledger_anti_replay_duplicate_event_id():
    ledger = InMemoryLedgerAdapter()
    signed_event = make_dummy_signed_event()

    ledger.submit_event(signed_event)

    # Attempt to submit same event again
    with pytest.raises(ReplayAttackError, match="Replay rejected: EventID"):
        ledger.submit_event(signed_event)


@pytest.mark.unit
def test_ledger_anti_replay_duplicate_session_id():
    ledger = InMemoryLedgerAdapter()
    shared_session = SecureRandom.generate_typed_id(SessionID)

    event1 = make_dummy_signed_event(session_id=shared_session)
    ledger.submit_event(event1)

    # Event 2 has different EventID but same SessionID
    event2 = make_dummy_signed_event(session_id=shared_session)
    with pytest.raises(ReplayAttackError, match="Replay rejected: SessionID"):
        ledger.submit_event(event2)


@pytest.mark.unit
def test_ledger_anti_replay_duplicate_watermark_id():
    ledger = InMemoryLedgerAdapter()
    shared_wm = SecureRandom.generate_typed_id(WatermarkID)

    event1 = make_dummy_signed_event(watermark_id=shared_wm)
    ledger.submit_event(event1)

    # Event 2 has different EventID but same WatermarkID
    event2 = make_dummy_signed_event(watermark_id=shared_wm)
    with pytest.raises(ReplayAttackError, match="Replay rejected: WatermarkID"):
        ledger.submit_event(event2)


@pytest.mark.unit
def test_ledger_simulated_rejection():
    ledger = InMemoryLedgerAdapter(simulate_rejection=True)
    signed_event = make_dummy_signed_event()

    receipt = ledger.submit_event(signed_event)
    assert receipt.status == CommitStatus.REJECTED
    assert receipt.is_committed is False
    assert "quorum rejection" in str(receipt.error_message)


@pytest.mark.unit
def test_ledger_simulated_timeout_unknown_state():
    ledger = InMemoryLedgerAdapter(simulate_timeout=True)
    signed_event = make_dummy_signed_event()

    receipt = ledger.submit_event(signed_event)
    assert receipt.status == CommitStatus.UNKNOWN_COMMIT_STATE
    assert receipt.is_committed is False


@pytest.mark.unit
def test_ledger_simulated_network_failure():
    ledger = InMemoryLedgerAdapter(simulate_network_failure=True)
    signed_event = make_dummy_signed_event()

    with pytest.raises(LedgerError, match="Simulated ledger transport"):
        ledger.submit_event(signed_event)
