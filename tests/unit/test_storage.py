"""Unit tests for hardened local SQLite storage manager."""

from pathlib import Path
import pytest

from tracecrypt.event.schema import DecryptionEvent, PQCAlgorithms
from tracecrypt.models.domain import Device, Document, User, UserRole, UserStatus
from tracecrypt.storage.sqlite_store import SQLiteStorageManager
from tracecrypt.utils.identifiers import (
    DeviceID,
    DocumentID,
    EventID,
    RecipientID,
    SessionID,
    UserID,
    WatermarkID,
)


@pytest.fixture
def temp_db(tmp_path: Path):
    db_file = tmp_path / "test_tracecrypt.db"
    store = SQLiteStorageManager(db_file)
    store.initialize()
    return store


@pytest.mark.unit
def test_user_persistence(temp_db: SQLiteStorageManager):
    user = User(
        user_id=UserID("usr-0123456789abcdef0123456789abcdef"),
        display_name="Analyst Bob",
        email_hash="sha3-256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        organization_unit="Legal Forensics",
        role=UserRole.RECIPIENT,
        created_at=1727280000000000,
        status=UserStatus.ACTIVE,
    )
    temp_db.save_user(user)
    loaded = temp_db.get_user(str(user.user_id))
    assert loaded is not None
    assert loaded.user_id == user.user_id
    assert loaded.display_name == "Analyst Bob"
    assert loaded.role == UserRole.RECIPIENT


@pytest.mark.unit
def test_device_persistence(temp_db: SQLiteStorageManager):
    user = User(
        user_id=UserID("usr-0123456789abcdef0123456789abcdef"),
        display_name="Analyst Bob",
        email_hash="sha3-256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        organization_unit="Legal Forensics",
        role=UserRole.RECIPIENT,
        created_at=1727280000000000,
        status=UserStatus.ACTIVE,
    )
    temp_db.save_user(user)

    device = Device(
        device_id=DeviceID("dev-0123456789abcdef0123456789abcdef"),
        user_id=user.user_id,
        hostname="SEC-WORKSTATION-4",
        fingerprint_hash="sha3-256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        os_version="Windows 11 Pro 23H2",
        enrolled_at=1727280000000000,
        is_trusted=True,
    )
    temp_db.save_device(device)
    loaded = temp_db.get_device(str(device.device_id))
    assert loaded is not None
    assert loaded.hostname == "SEC-WORKSTATION-4"
    assert loaded.is_trusted is True


@pytest.mark.unit
def test_document_and_event_persistence(temp_db: SQLiteStorageManager):
    # Save user
    user = User(
        user_id=UserID("usr-0123456789abcdef0123456789abcdef"),
        display_name="Analyst Bob",
        email_hash="sha3-256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        organization_unit="Legal Forensics",
        role=UserRole.RECIPIENT,
        created_at=1727280000000000,
        status=UserStatus.ACTIVE,
    )
    temp_db.save_user(user)

    # Save document
    doc = Document(
        document_id=DocumentID("doc-0123456789abcdef0123456789abcdef"),
        title="Classified Brief",
        page_count=5,
        canonical_hash="sha3-256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        mime_type="application/pdf",
        file_size_bytes=524288,
        sender_id=user.user_id,
        created_at=1727280000000000,
    )
    temp_db.save_document(doc)

    # Save event
    event = DecryptionEvent(
        event_id=EventID("evt-0123456789abcdef0123456789abcdef"),
        document_id=doc.document_id,
        document_hash=doc.canonical_hash,
        recipient_id=RecipientID("rcp-0123456789abcdef0123456789abcdef"),
        device_id=DeviceID("dev-0123456789abcdef0123456789abcdef"),
        session_id=SessionID("ses-0123456789abcdef0123456789abcdef"),
        watermark_id=WatermarkID("wm-0123456789abcdef0123456789abcdef"),
        anti_replay_nonce="f8a7c2b3d4e5f6011223344556677889",
        timestamp=1727280000000000,
        pqc_algorithms=PQCAlgorithms(),
    )
    temp_db.save_event(event, sync_status="PENDING_COMMIT")

    loaded_event = temp_db.get_event(str(event.event_id))
    assert loaded_event is not None
    assert loaded_event.event_id == event.event_id
    assert loaded_event.document_id == doc.document_id

    events = temp_db.get_events_by_document(str(doc.document_id))
    assert len(events) == 1
    assert events[0].event_id == event.event_id
