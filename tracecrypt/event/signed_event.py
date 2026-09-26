"""Signed Decryption Event container for TraceCrypt.

Encapsulates the canonical DecryptionEvent along with its RFC 8785 canonical representation,
SHA3-256 event digest, ML-DSA-65 post-quantum digital signature, recipient certificate binding,
and ledger transaction metadata.
"""

from __future__ import annotations

import base64
import json
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

from tracecrypt.crypto.types import MLDSASignature
from tracecrypt.errors import ValidationError
from tracecrypt.event.canonicalizer import canonicalize
from tracecrypt.event.schema import DecryptionEvent


class SignedDecryptionEvent(BaseModel):
    """Immutable signed record proving recipient attribution for a decryption event.

    Separates the unsigned canonical event from its signature container to eliminate
    circular self-hashing while providing a verifiable audit token.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    event: DecryptionEvent = Field(description="The underlying structured decryption event")
    canonical_event: str = Field(description="Exact RFC 8785 canonical JSON representation of event payload")
    event_digest: str = Field(description="SHA3-256 digest of canonical_event in format 'sha3-256:<hex>'")
    signature: str = Field(description="Base64-encoded NIST FIPS 204 ML-DSA-65 signature (3309 bytes)")
    signing_key_id: str = Field(description="Signer's ML-DSA-65 key identifier")
    certificate_id: str = Field(description="Serial number of signer's certified identity certificate")
    certificate_fingerprint: str = Field(description="Signer certificate public key fingerprint")
    signed_at: int = Field(description="POSIX microsecond UTC timestamp at signing")
    ledger_transaction_id: Optional[str] = Field(
        default=None,
        description="Assigned ledger transaction reference after successful commit"
    )

    @field_validator("event_digest")
    @classmethod
    def validate_digest_format(cls, v: str) -> str:
        if not v.startswith("sha3-256:"):
            raise ValidationError(f"Event digest must start with 'sha3-256:', got {v!r}")
        hex_part = v.split(":", 1)[1]
        if len(hex_part) != 64:
            raise ValidationError(f"Invalid SHA3-256 hex length ({len(hex_part)} != 64)")
        return v

    @field_validator("signature")
    @classmethod
    def validate_signature_encoding(cls, v: str) -> str:
        try:
            raw = base64.b64decode(v, validate=True)
            if len(raw) != MLDSASignature.EXPECTED_LENGTH:
                raise ValidationError(
                    f"Invalid ML-DSA-65 signature length: expected {MLDSASignature.EXPECTED_LENGTH} bytes, "
                    f"got {len(raw)} bytes"
                )
        except Exception as e:
            raise ValidationError(f"Invalid base64 signature encoding: {e}") from e
        return v

    def get_signature_bytes(self) -> bytes:
        """Return the decoded raw 3309-byte ML-DSA-65 signature."""
        return base64.b64decode(self.signature)

    def get_event_digest_bytes(self) -> bytes:
        """Return the raw 32-byte SHA3-256 digest."""
        hex_str = self.event_digest.split(":", 1)[1]
        return bytes.fromhex(hex_str)

    def to_canonical_bytes(self) -> bytes:
        """Produce the RFC 8785 canonical bytes of the full signed event record."""
        return canonicalize(self.model_dump(mode="json"))

    def to_canonical_json(self) -> str:
        """Produce RFC 8785 canonical JSON string."""
        return self.to_canonical_bytes().decode("utf-8")

    @classmethod
    def from_canonical_json(cls, json_str: str) -> SignedDecryptionEvent:
        """Parse SignedDecryptionEvent from canonical JSON string."""
        try:
            data = json.loads(json_str)
            return cls.model_validate(data)
        except Exception as e:
            raise ValidationError(f"Failed to parse SignedDecryptionEvent from JSON: {e}") from e

    def with_transaction_id(self, tx_id: str) -> SignedDecryptionEvent:
        """Return a copy of this signed event with ledger_transaction_id set."""
        d = self.model_dump()
        d["ledger_transaction_id"] = tx_id
        return SignedDecryptionEvent.model_validate(d)
