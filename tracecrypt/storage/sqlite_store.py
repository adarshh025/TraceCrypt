"""Local SQLite storage manager with hardened security settings.

Security Settings Applied:
- WAL Mode (Write-Ahead Logging) for atomic concurrent reads and writes.
- Synchronous = FULL to protect against corruption during power loss.
- Foreign Keys = ON for referential integrity.
- Busy Timeout = 5000ms.
- Explicit schema definitions without plaintext private keys or sensitive payloads.
"""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from typing import List, Optional

from tracecrypt.errors import StorageError
from tracecrypt.event.schema import DecryptionEvent
from tracecrypt.models.domain import Device, Document, User, UserRole, UserStatus
from tracecrypt.utils.identifiers import DeviceID, DocumentID, UserID


class SQLiteStorageManager:
    """Hardened local SQLite storage implementation."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def _get_connection(self) -> sqlite3.Connection:
        try:
            conn = sqlite3.connect(str(self.db_path), timeout=5.0)
            conn.row_factory = sqlite3.Row
            # Enforce SQLite security and integrity pragmas
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = FULL;")
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA busy_timeout = 5000;")
            return conn
        except Exception as e:
            raise StorageError(f"Failed to connect to SQLite database at {self.db_path}: {e}") from e

    def initialize(self) -> None:
        """Create tables and verify schema integrity."""
        schema = """
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            email_hash TEXT NOT NULL,
            organization_unit TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            status TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            hostname TEXT NOT NULL,
            fingerprint_hash TEXT NOT NULL,
            os_version TEXT NOT NULL,
            enrolled_at INTEGER NOT NULL,
            is_trusted INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE RESTRICT
        );

        CREATE TABLE IF NOT EXISTS documents (
            document_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            page_count INTEGER NOT NULL,
            canonical_hash TEXT NOT NULL,
            mime_type TEXT NOT NULL,
            file_size_bytes INTEGER NOT NULL,
            sender_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (sender_id) REFERENCES users(user_id) ON DELETE RESTRICT
        );

        CREATE TABLE IF NOT EXISTS local_events (
            event_id TEXT PRIMARY KEY,
            document_id TEXT NOT NULL,
            recipient_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            watermark_id TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            canonical_json TEXT NOT NULL,
            event_digest TEXT NOT NULL,
            sync_status TEXT NOT NULL,
            FOREIGN KEY (document_id) REFERENCES documents(document_id) ON DELETE RESTRICT
        );

        CREATE INDEX IF NOT EXISTS idx_events_document ON local_events(document_id);
        CREATE INDEX IF NOT EXISTS idx_events_recipient ON local_events(recipient_id);
        """
        try:
            with self._get_connection() as conn:
                conn.executescript(schema)
                conn.commit()
        except Exception as e:
            raise StorageError(f"Failed to initialize SQLite schema: {e}") from e

    def save_user(self, user: User) -> None:
        query = """
        INSERT INTO users (user_id, display_name, email_hash, organization_unit, role, created_at, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            display_name = excluded.display_name,
            email_hash = excluded.email_hash,
            organization_unit = excluded.organization_unit,
            role = excluded.role,
            status = excluded.status;
        """
        try:
            with self._get_connection() as conn:
                conn.execute(
                    query,
                    (
                        str(user.user_id),
                        user.display_name,
                        user.email_hash,
                        user.organization_unit,
                        user.role.value,
                        user.created_at,
                        user.status.value,
                    ),
                )
                conn.commit()
        except Exception as e:
            raise StorageError(f"Failed to save user {user.user_id}: {e}") from e

    def get_user(self, user_id: str) -> Optional[User]:
        query = "SELECT * FROM users WHERE user_id = ?;"
        try:
            with self._get_connection() as conn:
                cur = conn.execute(query, (user_id,))
                row = cur.fetchone()
                if not row:
                    return None
                return User(
                    user_id=UserID(row["user_id"]),
                    display_name=row["display_name"],
                    email_hash=row["email_hash"],
                    organization_unit=row["organization_unit"],
                    role=UserRole(row["role"]),
                    created_at=row["created_at"],
                    status=UserStatus(row["status"]),
                )
        except Exception as e:
            raise StorageError(f"Failed to retrieve user {user_id}: {e}") from e

    def save_device(self, device: Device) -> None:
        query = """
        INSERT INTO devices (device_id, user_id, hostname, fingerprint_hash, os_version, enrolled_at, is_trusted)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(device_id) DO UPDATE SET
            hostname = excluded.hostname,
            fingerprint_hash = excluded.fingerprint_hash,
            os_version = excluded.os_version,
            is_trusted = excluded.is_trusted;
        """
        try:
            with self._get_connection() as conn:
                conn.execute(
                    query,
                    (
                        str(device.device_id),
                        str(device.user_id),
                        device.hostname,
                        device.fingerprint_hash,
                        device.os_version,
                        device.enrolled_at,
                        1 if device.is_trusted else 0,
                    ),
                )
                conn.commit()
        except Exception as e:
            raise StorageError(f"Failed to save device {device.device_id}: {e}") from e

    def get_device(self, device_id: str) -> Optional[Device]:
        query = "SELECT * FROM devices WHERE device_id = ?;"
        try:
            with self._get_connection() as conn:
                cur = conn.execute(query, (device_id,))
                row = cur.fetchone()
                if not row:
                    return None
                return Device(
                    device_id=DeviceID(row["device_id"]),
                    user_id=UserID(row["user_id"]),
                    hostname=row["hostname"],
                    fingerprint_hash=row["fingerprint_hash"],
                    os_version=row["os_version"],
                    enrolled_at=row["enrolled_at"],
                    is_trusted=bool(row["is_trusted"]),
                )
        except Exception as e:
            raise StorageError(f"Failed to retrieve device {device_id}: {e}") from e

    def save_document(self, doc: Document) -> None:
        query = """
        INSERT INTO documents (
            document_id, title, page_count, canonical_hash,
            mime_type, file_size_bytes, sender_id, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(document_id) DO UPDATE SET
            title = excluded.title,
            page_count = excluded.page_count,
            canonical_hash = excluded.canonical_hash,
            file_size_bytes = excluded.file_size_bytes;
        """
        try:
            with self._get_connection() as conn:
                conn.execute(
                    query,
                    (
                        str(doc.document_id),
                        doc.title,
                        doc.page_count,
                        doc.canonical_hash,
                        doc.mime_type,
                        doc.file_size_bytes,
                        str(doc.sender_id),
                        doc.created_at,
                    ),
                )
                conn.commit()
        except Exception as e:
            raise StorageError(f"Failed to save document {doc.document_id}: {e}") from e

    def get_document(self, document_id: str) -> Optional[Document]:
        query = "SELECT * FROM documents WHERE document_id = ?;"
        try:
            with self._get_connection() as conn:
                cur = conn.execute(query, (document_id,))
                row = cur.fetchone()
                if not row:
                    return None
                return Document(
                    document_id=DocumentID(row["document_id"]),
                    title=row["title"],
                    page_count=row["page_count"],
                    canonical_hash=row["canonical_hash"],
                    mime_type=row["mime_type"],
                    file_size_bytes=row["file_size_bytes"],
                    sender_id=UserID(row["sender_id"]),
                    created_at=row["created_at"],
                )
        except Exception as e:
            raise StorageError(f"Failed to retrieve document {document_id}: {e}") from e

    def save_event(self, event: DecryptionEvent, sync_status: str = "PENDING_COMMIT") -> None:
        query = """
        INSERT INTO local_events (
            event_id, document_id, recipient_id, session_id, watermark_id,
            timestamp, canonical_json, event_digest, sync_status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(event_id) DO UPDATE SET sync_status = excluded.sync_status;
        """
        canonical_bytes = event.to_canonical_bytes()
        digest = event.compute_event_digest()
        try:
            with self._get_connection() as conn:
                conn.execute(
                    query,
                    (
                        str(event.event_id),
                        str(event.document_id),
                        str(event.recipient_id),
                        str(event.session_id),
                        str(event.watermark_id),
                        event.timestamp,
                        canonical_bytes.decode("utf-8"),
                        digest,
                        sync_status,
                    ),
                )
                conn.commit()
        except Exception as e:
            raise StorageError(f"Failed to save local event {event.event_id}: {e}") from e

    def get_event(self, event_id: str) -> Optional[DecryptionEvent]:
        query = "SELECT canonical_json FROM local_events WHERE event_id = ?;"
        try:
            with self._get_connection() as conn:
                cur = conn.execute(query, (event_id,))
                row = cur.fetchone()
                if not row:
                    return None
                data = json.loads(row["canonical_json"])
                return DecryptionEvent.model_validate(data)
        except Exception as e:
            raise StorageError(f"Failed to retrieve event {event_id}: {e}") from e

    def get_events_by_document(self, document_id: str) -> List[DecryptionEvent]:
        query = "SELECT canonical_json FROM local_events WHERE document_id = ? ORDER BY timestamp ASC;"
        try:
            with self._get_connection() as conn:
                cur = conn.execute(query, (document_id,))
                rows = cur.fetchall()
                results: List[DecryptionEvent] = []
                for r in rows:
                    data = json.loads(r["canonical_json"])
                    results.append(DecryptionEvent.model_validate(data))
                return results
        except Exception as e:
            raise StorageError(f"Failed to query events for document {document_id}: {e}") from e
