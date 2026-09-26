"""Storage abstraction interfaces for TraceCrypt.

NOTE ON LEDGER SEPARATION:
These interfaces are intended exclusively for local client metadata caching, local device
configuration, and offline indexing. They are NOT the distributed ledger. The permissioned
BFT ledger subsystem is implemented in Phase 6.
"""

from __future__ import annotations

from typing import List, Optional, Protocol, runtime_checkable

from tracecrypt.crypto.types import KeyMetadata
from tracecrypt.event.schema import DecryptionEvent
from tracecrypt.identity.certificate import PQCIdentityCertificate
from tracecrypt.identity.lifecycle import RevocationRecord
from tracecrypt.models.domain import Device, Document, User


@runtime_checkable
class MetadataStore(Protocol):
    """Protocol for local user, device, and document metadata persistence."""

    def initialize(self) -> None:
        """Create tables and verify database integrity."""
        ...

    def save_user(self, user: User) -> None:
        """Store or update user profile."""
        ...

    def get_user(self, user_id: str) -> Optional[User]:
        """Retrieve user by UserID."""
        ...

    def save_device(self, device: Device) -> None:
        """Store or update enrolled device."""
        ...

    def get_device(self, device_id: str) -> Optional[Device]:
        """Retrieve device by DeviceID."""
        ...

    def save_document(self, doc: Document) -> None:
        """Store document metadata."""
        ...

    def get_document(self, document_id: str) -> Optional[Document]:
        """Retrieve document metadata by DocumentID."""
        ...


@runtime_checkable
class IdentityStore(Protocol):
    """Protocol for local certificate, key metadata, and revocation state persistence."""

    def save_certificate(self, cert: PQCIdentityCertificate) -> None:
        """Store certified PQC identity certificate."""
        ...

    def get_certificate(self, serial_number: str) -> Optional[PQCIdentityCertificate]:
        """Retrieve certificate by serial number."""
        ...

    def list_certificates_for_subject(self, subject_id: str) -> List[PQCIdentityCertificate]:
        """List all certificates issued to a subject."""
        ...

    def list_all_certificates(self) -> List[PQCIdentityCertificate]:
        """List all certificates currently in the store."""
        ...

    def list_subjects(self) -> List[str]:
        """List distinct subject IDs having certificates in the store."""
        ...

    def save_key_metadata(self, metadata: KeyMetadata, keystore_path: str) -> None:
        """Store key metadata referencing local encrypted keystore container."""
        ...

    def get_key_metadata(self, key_id: str) -> Optional[KeyMetadata]:
        """Retrieve key metadata."""
        ...

    def list_all_keys(self) -> List[KeyMetadata]:
        """List all key metadata records."""
        ...

    def save_revocation(self, record: RevocationRecord) -> None:
        """Store signed revocation assertion."""
        ...

    def get_revocation(self, serial_number: str) -> Optional[RevocationRecord]:
        """Retrieve revocation record for a certificate serial."""
        ...

    def list_revocations(self) -> List[RevocationRecord]:
        """Return all local revocation records."""
        ...


@runtime_checkable
class EventIndexStore(Protocol):
    """Protocol for indexing locally generated or observed decryption events."""

    def save_event(self, event: DecryptionEvent, sync_status: str = "PENDING_COMMIT") -> None:
        """Index a canonical decryption event with ledger sync status."""
        ...

    def get_event(self, event_id: str) -> Optional[DecryptionEvent]:
        """Retrieve event by EventID."""
        ...

    def get_events_by_document(self, document_id: str) -> List[DecryptionEvent]:
        """Retrieve all local decryption events associated with a document."""
        ...
