"""Local SQLite storage manager with hardened security settings.

Security Settings Applied:
- WAL Mode (Write-Ahead Logging) for atomic concurrent reads and writes.
- Synchronous = FULL to protect against corruption during power loss.
- Foreign Keys = ON for referential integrity.
- Busy Timeout = 5000ms.
- Explicit schema definitions without plaintext private keys or sensitive payloads.
- References encrypted keystore paths rather than storing keys.
"""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from typing import List, Optional

from tracecrypt.crypto.types import KeyMetadata, KeyPurpose, KeyStatus
from tracecrypt.errors import StorageError
from tracecrypt.event.schema import DecryptionEvent
from tracecrypt.event.signed_event import SignedDecryptionEvent
from tracecrypt.identity.certificate import PQCIdentityCertificate
from tracecrypt.identity.lifecycle import RevocationRecord
from tracecrypt.models.domain import Device, Document, User, UserRole, UserStatus
from tracecrypt.utils.identifiers import DeviceID, DocumentID, UserID
from tracecrypt.utils.timestamps import utc_now_micros


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

        CREATE TABLE IF NOT EXISTS certificates (
            serial_number TEXT PRIMARY KEY,
            issuer_ca_id TEXT NOT NULL,
            subject_id TEXT NOT NULL,
            device_id TEXT,
            organization TEXT NOT NULL,
            role TEXT NOT NULL,
            key_purpose TEXT NOT NULL,
            algorithm TEXT NOT NULL,
            parameter_set TEXT NOT NULL,
            public_key_b64 TEXT NOT NULL,
            public_key_fingerprint TEXT NOT NULL,
            valid_from INTEGER NOT NULL,
            valid_until INTEGER NOT NULL,
            signature_b64 TEXT NOT NULL,
            canonical_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS key_metadata (
            key_id TEXT PRIMARY KEY,
            owner_id TEXT NOT NULL,
            purpose TEXT NOT NULL,
            algorithm TEXT NOT NULL,
            parameter_set TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            activated_at INTEGER,
            expires_at INTEGER,
            status TEXT NOT NULL,
            version INTEGER NOT NULL,
            fingerprint TEXT NOT NULL,
            keystore_path TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS revocation_records (
            revocation_id TEXT PRIMARY KEY,
            serial_number TEXT NOT NULL UNIQUE,
            key_id TEXT NOT NULL,
            reason TEXT NOT NULL,
            revoked_at INTEGER NOT NULL,
            revoked_by_ca_id TEXT NOT NULL,
            signature_b64 TEXT NOT NULL,
            canonical_json TEXT NOT NULL
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
        CREATE INDEX IF NOT EXISTS idx_certs_subject ON certificates(subject_id);
        CREATE INDEX IF NOT EXISTS idx_keys_owner ON key_metadata(owner_id);
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

    # -------------------------------------------------------------------------
    # Certificate, Key Metadata & Revocation Persistence
    # -------------------------------------------------------------------------

    def save_certificate(self, cert: PQCIdentityCertificate) -> None:
        query = """
        INSERT INTO certificates (
            serial_number, issuer_ca_id, subject_id, device_id, organization,
            role, key_purpose, algorithm, parameter_set, public_key_b64,
            public_key_fingerprint, valid_from, valid_until, signature_b64, canonical_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(serial_number) DO UPDATE SET
            valid_until = excluded.valid_until,
            signature_b64 = excluded.signature_b64;
        """
        raw_json = cert.model_dump_json()
        try:
            with self._get_connection() as conn:
                conn.execute(
                    query,
                    (
                        cert.serial_number,
                        cert.issuer_ca_id,
                        cert.subject_id,
                        cert.device_id,
                        cert.organization,
                        cert.role,
                        cert.key_purpose.value,
                        cert.algorithm,
                        cert.parameter_set,
                        cert.public_key_b64,
                        cert.public_key_fingerprint,
                        cert.valid_from,
                        cert.valid_until,
                        cert.signature_b64,
                        raw_json,
                    ),
                )
                conn.commit()
        except Exception as e:
            raise StorageError(f"Failed to save certificate {cert.serial_number}: {e}") from e

    def get_certificate(self, serial_number: str) -> Optional[PQCIdentityCertificate]:
        query = "SELECT canonical_json FROM certificates WHERE serial_number = ?;"
        try:
            with self._get_connection() as conn:
                cur = conn.execute(query, (serial_number,))
                row = cur.fetchone()
                if not row:
                    return None
                data = json.loads(row["canonical_json"])
                return PQCIdentityCertificate.model_validate(data)
        except Exception as e:
            raise StorageError(f"Failed to retrieve certificate {serial_number}: {e}") from e

    def list_certificates_for_subject(self, subject_id: str) -> List[PQCIdentityCertificate]:
        query = "SELECT canonical_json FROM certificates WHERE subject_id = ? ORDER BY valid_from DESC;"
        try:
            with self._get_connection() as conn:
                cur = conn.execute(query, (subject_id,))
                rows = cur.fetchall()
                results: List[PQCIdentityCertificate] = []
                for r in rows:
                    data = json.loads(r["canonical_json"])
                    results.append(PQCIdentityCertificate.model_validate(data))
                return results
        except Exception as e:
            raise StorageError(f"Failed to query certificates for subject {subject_id}: {e}") from e

    def get_active_kem_certificate(self, subject_id: str) -> Optional[PQCIdentityCertificate]:
        """Retrieve the currently valid, unrevoked ML-KEM certificate for a subject."""
        certs = self.list_certificates_for_subject(subject_id)
        revocations = {r.serial_number for r in self.list_revocations()}
        now = utc_now_micros()
        for cert in certs:
            if cert.key_purpose == KeyPurpose.KEY_ENCAPSULATION:
                if cert.serial_number in revocations:
                    continue
                if cert.valid_from <= now <= cert.valid_until:
                    return cert
        return None

    def get_active_kem_keystore_path(self, owner_id: str) -> Optional[Path]:
        """Find the keystore file path for the active KEM key of the owner."""
        query = """
        SELECT keystore_path FROM key_metadata
        WHERE owner_id = ? AND purpose = ? AND status = ?
        ORDER BY created_at DESC;
        """
        try:
            with self._get_connection() as conn:
                cur = conn.execute(
                    query,
                    (owner_id, KeyPurpose.KEY_ENCAPSULATION.value, KeyStatus.ACTIVE.value),
                )
                row = cur.fetchone()
                if row and row["keystore_path"]:
                    p = Path(row["keystore_path"])
                    if p.exists():
                        return p
                return None
        except Exception as e:
            raise StorageError(f"Failed to query KEM keystore path for {owner_id}: {e}") from e

    def get_active_dsa_certificate(self, subject_id: str) -> Optional[PQCIdentityCertificate]:
        """Retrieve the currently valid, unrevoked ML-DSA certificate for a subject."""
        certs = self.list_certificates_for_subject(subject_id)
        revocations = {r.serial_number for r in self.list_revocations()}
        now = utc_now_micros()
        for cert in certs:
            if cert.key_purpose == KeyPurpose.DIGITAL_SIGNATURE:
                if cert.serial_number in revocations:
                    continue
                if cert.valid_from <= now <= cert.valid_until:
                    return cert
        return None

    def get_active_dsa_keystore_path(self, owner_id: str) -> Optional[Path]:
        """Find the keystore file path for the active DSA key of the owner."""
        query = """
        SELECT keystore_path FROM key_metadata
        WHERE owner_id = ? AND purpose = ? AND status = ?
        ORDER BY created_at DESC;
        """
        try:
            with self._get_connection() as conn:
                cur = conn.execute(
                    query,
                    (owner_id, KeyPurpose.DIGITAL_SIGNATURE.value, KeyStatus.ACTIVE.value),
                )
                row = cur.fetchone()
                if row and row["keystore_path"]:
                    p = Path(row["keystore_path"])
                    if p.exists():
                        return p
                return None
        except Exception as e:
            raise StorageError(f"Failed to query DSA keystore path for {owner_id}: {e}") from e

    def list_all_certificates(self) -> List[PQCIdentityCertificate]:
        query = "SELECT canonical_json FROM certificates ORDER BY valid_from DESC;"
        try:
            with self._get_connection() as conn:
                cur = conn.execute(query)
                rows = cur.fetchall()
                results: List[PQCIdentityCertificate] = []
                for r in rows:
                    data = json.loads(r["canonical_json"])
                    results.append(PQCIdentityCertificate.model_validate(data))
                return results
        except Exception as e:
            raise StorageError(f"Failed to query all certificates: {e}") from e

    def list_subjects(self) -> List[str]:
        query = "SELECT DISTINCT subject_id FROM certificates ORDER BY subject_id ASC;"
        try:
            with self._get_connection() as conn:
                cur = conn.execute(query)
                rows = cur.fetchall()
                return [r["subject_id"] for r in rows]
        except Exception as e:
            raise StorageError(f"Failed to query subjects: {e}") from e

    def save_key_metadata(self, metadata: KeyMetadata, keystore_path: str) -> None:
        query = """
        INSERT INTO key_metadata (
            key_id, owner_id, purpose, algorithm, parameter_set,
            created_at, activated_at, expires_at, status, version, fingerprint, keystore_path
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(key_id) DO UPDATE SET
            status = excluded.status,
            activated_at = excluded.activated_at,
            expires_at = excluded.expires_at,
            keystore_path = excluded.keystore_path;
        """
        try:
            with self._get_connection() as conn:
                conn.execute(
                    query,
                    (
                        metadata.key_id,
                        metadata.owner_id,
                        metadata.purpose.value,
                        metadata.algorithm,
                        metadata.parameter_set,
                        metadata.created_at,
                        metadata.activated_at,
                        metadata.expires_at,
                        metadata.status.value,
                        metadata.version,
                        metadata.fingerprint,
                        str(keystore_path),
                    ),
                )
                conn.commit()
        except Exception as e:
            raise StorageError(f"Failed to save key metadata {metadata.key_id}: {e}") from e

    def get_key_metadata(self, key_id: str) -> Optional[KeyMetadata]:
        query = "SELECT * FROM key_metadata WHERE key_id = ?;"
        try:
            with self._get_connection() as conn:
                cur = conn.execute(query, (key_id,))
                row = cur.fetchone()
                if not row:
                    return None
                return KeyMetadata(
                    key_id=row["key_id"],
                    owner_id=row["owner_id"],
                    purpose=KeyPurpose(row["purpose"]),
                    algorithm=row["algorithm"],
                    parameter_set=row["parameter_set"],
                    created_at=row["created_at"],
                    activated_at=row["activated_at"],
                    expires_at=row["expires_at"],
                    status=KeyStatus(row["status"]),
                    version=row["version"],
                    fingerprint=row["fingerprint"],
                )
        except Exception as e:
            raise StorageError(f"Failed to retrieve key metadata {key_id}: {e}") from e

    def list_all_keys(self) -> List[KeyMetadata]:
        query = "SELECT * FROM key_metadata ORDER BY created_at DESC;"
        try:
            with self._get_connection() as conn:
                cur = conn.execute(query)
                rows = cur.fetchall()
                results: List[KeyMetadata] = []
                for r in rows:
                    results.append(
                        KeyMetadata(
                            key_id=r["key_id"],
                            owner_id=r["owner_id"],
                            purpose=KeyPurpose(r["purpose"]),
                            algorithm=r["algorithm"],
                            parameter_set=r["parameter_set"],
                            created_at=r["created_at"],
                            activated_at=r["activated_at"],
                            expires_at=r["expires_at"],
                            status=KeyStatus(r["status"]),
                            version=r["version"],
                            fingerprint=r["fingerprint"],
                        )
                    )
                return results
        except Exception as e:
            raise StorageError(f"Failed to list all keys: {e}") from e

    def save_revocation(self, record: RevocationRecord) -> None:
        query = """
        INSERT INTO revocation_records (
            revocation_id, serial_number, key_id, reason, revoked_at,
            revoked_by_ca_id, signature_b64, canonical_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(serial_number) DO NOTHING;
        """
        raw_json = record.model_dump_json()
        try:
            with self._get_connection() as conn:
                conn.execute(
                    query,
                    (
                        record.revocation_id,
                        record.serial_number,
                        record.key_id,
                        record.reason.value,
                        record.revoked_at,
                        record.revoked_by_ca_id,
                        record.signature_b64,
                        raw_json,
                    ),
                )
                conn.commit()
        except Exception as e:
            raise StorageError(f"Failed to save revocation record {record.serial_number}: {e}") from e

    def get_revocation(self, serial_number: str) -> Optional[RevocationRecord]:
        query = "SELECT canonical_json FROM revocation_records WHERE serial_number = ?;"
        try:
            with self._get_connection() as conn:
                cur = conn.execute(query, (serial_number,))
                row = cur.fetchone()
                if not row:
                    return None
                data = json.loads(row["canonical_json"])
                return RevocationRecord.model_validate(data)
        except Exception as e:
            raise StorageError(f"Failed to retrieve revocation {serial_number}: {e}") from e

    def list_revocations(self) -> List[RevocationRecord]:
        query = "SELECT canonical_json FROM revocation_records ORDER BY revoked_at DESC;"
        try:
            with self._get_connection() as conn:
                cur = conn.execute(query)
                rows = cur.fetchall()
                results: List[RevocationRecord] = []
                for r in rows:
                    data = json.loads(r["canonical_json"])
                    results.append(RevocationRecord.model_validate(data))
                return results
        except Exception as e:
            raise StorageError(f"Failed to list revocation records: {e}") from e

    # -------------------------------------------------------------------------
    # Event Indexing
    # -------------------------------------------------------------------------

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

    def save_signed_event(self, signed_event: SignedDecryptionEvent, sync_status: str = "COMMITTED") -> None:
        """Persist a SignedDecryptionEvent with full canonical JSON representation."""
        query = """
        INSERT INTO local_events (
            event_id, document_id, recipient_id, session_id, watermark_id,
            timestamp, canonical_json, event_digest, sync_status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(event_id) DO UPDATE SET
            sync_status = excluded.sync_status,
            canonical_json = excluded.canonical_json;
        """
        event = signed_event.event
        raw_json = signed_event.to_canonical_json()
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
                        raw_json,
                        signed_event.event_digest,
                        sync_status,
                    ),
                )
                conn.commit()
        except Exception as e:
            raise StorageError(f"Failed to save signed event {event.event_id}: {e}") from e

    def get_signed_event(self, event_id: str) -> Optional[SignedDecryptionEvent]:
        """Retrieve a SignedDecryptionEvent by its event_id."""
        query = "SELECT canonical_json FROM local_events WHERE event_id = ?;"
        try:
            with self._get_connection() as conn:
                cur = conn.execute(query, (event_id,))
                row = cur.fetchone()
                if not row:
                    return None
                data = json.loads(row["canonical_json"])
                return SignedDecryptionEvent.model_validate(data)
        except Exception as e:
            raise StorageError(f"Failed to retrieve signed event {event_id}: {e}") from e
