"""Canonical DecryptionEvent schema for TraceCrypt.

The DecryptionEvent is the primary cryptographic audit record created at the moment
of successful decryption. It binds the document, recipient, session, and embedded
watermark into an immutable structure signed with the recipient's ML-DSA-65 private key.

Versioning Policy:
- The schema is strictly versioned using 'schema_version' (currently '1.0.0').
- Extra/unknown fields are strictly forbidden ('extra = forbid') to guarantee canonical determinism.
- If a new schema version is introduced in the future, it must be registered with a distinct
  version identifier, while the canonicalizer and verifier retain historical version parsers
  to ensure historical ledger transactions remain 100% verifiable forever.
"""

from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

from tracecrypt.crypto.hashing import HashAlgorithm, Hasher
from tracecrypt.errors import ValidationError
from tracecrypt.event.canonicalizer import canonical_hash, canonicalize
from tracecrypt.utils.identifiers import (
    DeviceID,
    DistributionID,
    DocumentID,
    EventID,
    RecipientID,
    SessionID,
    WatermarkID,
)


class PQCAlgorithms(BaseModel):
    """Cryptographic algorithm identifiers used for the decryption session."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    kem: str = Field(default="ML-KEM-768", description="Key encapsulation algorithm")
    dsa: str = Field(default="ML-DSA-65", description="Digital signature algorithm")
    hash: str = Field(default="SHA3-256", description="Cryptographic hash algorithm")


class DecryptionEvent(BaseModel):
    """Canonical decryption event record committing to the decryption session.

    This record is canonicalized using RFC 8785 before being hashed and signed.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_version: str = Field(default="1.0.0", description="Event specification version")
    schema_version: str = Field(default="1.0.0", description="Event schema specification version")
    protocol_version: str = Field(default="1.0.0", description="TraceCrypt protocol version")
    software_version: str = Field(default="1.0.0", description="Software version that produced the event")
    event_type: str = Field(default="DECRYPTION_ATTRIBUTION", description="Audit event type classification")
    event_id: EventID = Field(description="Unique CSPRNG event identifier")
    document_id: DocumentID = Field(description="Identifier of source document")
    distribution_id: Optional[DistributionID] = Field(default=None, description="Distribution package identifier")
    document_hash: str = Field(description="Canonical pre-watermark SHA3-256 digest of original document")
    recipient_id: RecipientID = Field(description="Certified recipient identifier")
    recipient_key_id: Optional[str] = Field(default=None, description="Recipient ML-DSA signing key identifier")
    recipient_certificate_id: Optional[str] = Field(
        default=None, description="Recipient signing certificate serial number"
    )
    device_id: Optional[DeviceID] = Field(default=None, description="Certified hardware workstation identifier")
    session_id: SessionID = Field(description="Ephemeral decryption session identifier")
    watermark_id: WatermarkID = Field(description="128-bit identifier embedded in the forensic watermark")
    watermark_version: int = Field(default=1, ge=1, le=255, description="Forensic watermark version embedded")
    anti_replay_nonce: str = Field(description="128-bit random CSPRNG nonce")
    timestamp: int = Field(description="POSIX microsecond UTC timestamp at decryption event creation")
    rendered_watermarked_artifact_hash: Optional[str] = Field(
        default=None,
        description="SHA3-256 digest of released watermarked PDF artifact"
    )
    pqc_algorithms: PQCAlgorithms = Field(default_factory=PQCAlgorithms)

    # Cryptographic signature fields (structured for Phase 2 / Phase 5 integration)
    signature: Optional[str] = Field(
        default=None,
        description="Base64-encoded ML-DSA-65 digital signature over canonical event digest"
    )
    public_key_ref: Optional[str] = Field(
        default=None,
        description="Reference identifier or fingerprint of signer's certified public key"
    )

    @field_validator("document_hash")
    @classmethod
    def validate_hash_format(cls, v: str) -> str:
        if not v.startswith("sha3-256:"):
            raise ValidationError(f"Document hash must use canonical 'sha3-256:<hex>' format, got {v!r}")
        hex_part = v.split(":", 1)[1]
        if len(hex_part) != 64:
            raise ValidationError(f"Invalid SHA3-256 hex length ({len(hex_part)} != 64)")
        return v

    @field_validator("anti_replay_nonce")
    @classmethod
    def validate_nonce_entropy(cls, v: str) -> str:
        if not isinstance(v, str) or len(v.strip()) < 32:
            raise ValidationError(
                f"Anti-replay nonce must be a hex string of at least 32 characters "
                f"(128-bit entropy), got {len(v)} chars"
            )
        try:
            int(v, 16)
        except ValueError:
            raise ValidationError("Anti-replay nonce must contain valid hexadecimal characters.")
        return v

    def to_canonical_dict(self) -> dict[str, object]:
        """Convert event to dictionary excluding signature fields for signing input."""
        d = self.model_dump(mode="json")
        # Signatures cover the canonical event excluding the signature itself
        d.pop("signature", None)
        d.pop("public_key_ref", None)
        return d

    def to_canonical_bytes(self) -> bytes:
        """Produce the RFC 8785 canonical byte representation of the signing payload."""
        return canonicalize(self.to_canonical_dict())

    def compute_event_digest(self) -> str:
        """Compute the deterministic canonical SHA3-256 hash digest of this event."""
        return canonical_hash(self.to_canonical_dict())

    def compute_event_digest_bytes(self) -> bytes:
        """Compute the raw 32-byte SHA3-256 digest of the canonical event bytes."""
        return Hasher.digest_bytes(self.to_canonical_bytes(), HashAlgorithm.SHA3_256.value).raw_bytes
