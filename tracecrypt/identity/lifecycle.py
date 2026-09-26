"""Key Lifecycle, Controlled State Transitions, Rotation, and Offline Revocation.

Enforces strict monotonic lifecycle state transitions (prohibiting un-revocation),
key rotation with historical event preservation, and offline revocation records.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union
from pydantic import BaseModel, ConfigDict, Field

from tracecrypt.crypto.pqc_dsa import sign as sign_mldsa
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.crypto.types import (
    KeyMetadata,
    KeyStatus,
    MLDSAPrivateKey,
)
from tracecrypt.errors import SecurityError
from tracecrypt.event.canonicalizer import canonicalize
from tracecrypt.identity.certificate import PQCIdentityCertificate
from tracecrypt.utils.timestamps import utc_now_micros


class RevocationReason(str, Enum):
    """Authorized grounds for offline credential revocation."""
    KEY_COMPROMISE = "KEY_COMPROMISE"
    DEVICE_COMPROMISE = "DEVICE_COMPROMISE"
    AFFILIATION_TERMINATION = "AFFILIATION_TERMINATION"
    SUPERSEDED = "SUPERSEDED"
    ADMINISTRATIVE = "ADMINISTRATIVE"


class RevocationRecord(BaseModel):
    """Cryptographically signed offline revocation assertion."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    revocation_id: str = Field(description="Unique revocation record identifier")
    serial_number: str = Field(description="Serial number of revoked certificate")
    key_id: str = Field(description="Identifier of revoked key")
    reason: RevocationReason
    revoked_at: int = Field(description="POSIX microsecond timestamp")
    revoked_by_ca_id: str
    signature_b64: str = Field(description="Root CA ML-DSA-65 signature over canonical assertion")

    def to_signing_dict(self) -> Dict[str, object]:
        data = self.model_dump(mode="json")
        data.pop("signature_b64", None)
        return data

    def to_signing_bytes(self) -> bytes:
        return canonicalize(self.to_signing_dict())


class KeyLifecycleManager:
    """State transition machine and key lifecycle operations."""

    # Explicit whitelist of permitted state transitions
    ALLOWED_TRANSITIONS: Dict[KeyStatus, Set[KeyStatus]] = {
        KeyStatus.GENERATED: {KeyStatus.PENDING_ACTIVATION, KeyStatus.DESTROYED},
        KeyStatus.PENDING_ACTIVATION: {KeyStatus.ACTIVE, KeyStatus.REVOKED, KeyStatus.DESTROYED},
        KeyStatus.ACTIVE: {
            KeyStatus.SUSPENDED,
            KeyStatus.REVOKED,
            KeyStatus.EXPIRED,
            KeyStatus.COMPROMISED,
        },
        KeyStatus.SUSPENDED: {KeyStatus.ACTIVE, KeyStatus.REVOKED, KeyStatus.COMPROMISED},
        KeyStatus.EXPIRED: {KeyStatus.REVOKED, KeyStatus.DESTROYED},
        KeyStatus.COMPROMISED: {KeyStatus.REVOKED, KeyStatus.DESTROYED},
        KeyStatus.REVOKED: {KeyStatus.DESTROYED},
        KeyStatus.DESTROYED: set(),
    }

    @classmethod
    def validate_transition(cls, current: KeyStatus, target: KeyStatus) -> None:
        """Enforce state transition graph rules. Fails closed on illegal transitions."""
        if target == current:
            return
        allowed = cls.ALLOWED_TRANSITIONS.get(current, set())
        if target not in allowed:
            raise SecurityError(
                f"Prohibited key status transition: '{current.value}' -> '{target.value}'. "
                f"Allowed destinations: {[s.value for s in allowed]}"
            )

    @classmethod
    def transition(cls, metadata: KeyMetadata, target: KeyStatus) -> KeyMetadata:
        """Execute validated key status transition."""
        cls.validate_transition(metadata.status, target)
        now = utc_now_micros()
        activated = metadata.activated_at
        if target == KeyStatus.ACTIVE and activated is None:
            activated = now
        return metadata.model_copy(update={"status": target, "activated_at": activated})

    @classmethod
    def rotate_key(
        cls,
        active_key: KeyMetadata,
        new_key_id: str,
        new_fingerprint: str,
    ) -> tuple[KeyMetadata, KeyMetadata]:
        """Rotate an active key to a new version while preserving historical audibility."""
        cls.validate_transition(active_key.status, KeyStatus.REVOKED)
        revoked_key = active_key.model_copy(update={"status": KeyStatus.REVOKED})
        now = utc_now_micros()
        new_key = KeyMetadata(
            key_id=new_key_id,
            owner_id=active_key.owner_id,
            purpose=active_key.purpose,
            algorithm=active_key.algorithm,
            parameter_set=active_key.parameter_set,
            created_at=now,
            activated_at=now,
            expires_at=None,
            status=KeyStatus.ACTIVE,
            version=active_key.version + 1,
            fingerprint=new_fingerprint,
        )
        return revoked_key, new_key

    @classmethod
    def create_revocation_record(
        cls,
        serial_number: Union[str, PQCIdentityCertificate],
        key_id: str,
        reason: RevocationReason,
        ca: Optional[Any] = None,
        root_ca_id: Optional[str] = None,
        root_ca_private_key: Optional[MLDSAPrivateKey] = None,
    ) -> RevocationRecord:
        """Create a cryptographically signed revocation record."""
        if isinstance(serial_number, PQCIdentityCertificate):
            serial = serial_number.serial_number
        else:
            serial = str(serial_number)

        if ca is not None:
            ca_id = getattr(ca, "ca_id", "")
            ca_sk = getattr(ca, "_private_key", None)
        else:
            ca_id = root_ca_id or ""
            ca_sk = root_ca_private_key

        if ca_sk is None:
            raise SecurityError("Root CA private key required to sign revocation record.")

        rev_id = f"rev-{SecureRandom.random_nonce_128()}"
        now = utc_now_micros()

        proto = RevocationRecord(
            revocation_id=rev_id,
            serial_number=serial,
            key_id=key_id,
            reason=reason,
            revoked_at=now,
            revoked_by_ca_id=ca_id,
            signature_b64="",
        )

        signing_bytes = proto.to_signing_bytes()
        sig = sign_mldsa(ca_sk, signing_bytes)

        return proto.model_copy(update={"signature_b64": sig.to_b64()})


class OfflineRevocationStore:
    """Local offline store tracking revoked certificate serials and revocation records."""

    def __init__(self, storage: Optional[Any] = None) -> None:
        self.storage = storage
        self._revoked_serials: Dict[str, RevocationRecord] = {}
        if self.storage is not None:
            try:
                for r in self.storage.list_revocations():
                    self._revoked_serials[r.serial_number] = r
            except Exception:
                pass

    def register_revocation(self, record: RevocationRecord) -> None:
        """Add a signed revocation record to the offline registry."""
        self._revoked_serials[record.serial_number] = record
        if self.storage is not None:
            try:
                self.storage.save_revocation(record)
            except Exception:
                pass

    def record_revocation(self, record: RevocationRecord) -> None:
        """Alias for register_revocation."""
        self.register_revocation(record)

    def is_serial_revoked(self, serial_number: str) -> bool:
        """Check if certificate serial has been revoked."""
        if serial_number in self._revoked_serials:
            return True
        if self.storage is not None:
            try:
                rec = self.storage.get_revocation(serial_number)
                if rec is not None:
                    self._revoked_serials[serial_number] = rec
                    return True
            except Exception:
                pass
        return False

    def get_revocation(self, serial_number: str) -> Optional[RevocationRecord]:
        """Retrieve revocation details for a revoked serial number."""
        rec = self._revoked_serials.get(serial_number)
        if rec is None and self.storage is not None:
            try:
                rec = self.storage.get_revocation(serial_number)
                if rec is not None:
                    self._revoked_serials[serial_number] = rec
            except Exception:
                pass
        return rec

    def get_revocation_record(self, serial_number: str) -> Optional[RevocationRecord]:
        """Alias for get_revocation."""
        return self.get_revocation(serial_number)

    def list_revocations(self) -> List[RevocationRecord]:
        """Return all active revocation records."""
        return list(self._revoked_serials.values())
