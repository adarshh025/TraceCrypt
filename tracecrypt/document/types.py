"""Strongly-typed data structures for the Encrypted Document Distribution Subsystem.

Enforces strict schemas, cryptographic role separation, memory zeroization,
and RFC 8785 canonical metadata binding.
"""

from __future__ import annotations

import base64
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from tracecrypt.errors import SecurityError, ValidationError
from tracecrypt.event.canonicalizer import canonicalize
from tracecrypt.utils.identifiers import DistributionID, DocumentID, RecipientID


class RecipientEnvelope(BaseModel):
    """Encapsulated key material and authorization envelope for a specific recipient."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: str = Field(default="1.0.0")
    recipient_id: RecipientID
    key_id: str = Field(min_length=1)
    certificate_serial: str = Field(min_length=1)
    kem_algorithm: str = Field(default="ML-KEM-768")
    kem_parameter_set: str = Field(default="ML-KEM-768")
    kem_ciphertext_b64: str = Field(description="Base64 encoded ML-KEM-768 ciphertext (1088 bytes)")
    derived_key_context: str = Field(description="Domain separation context for KDF derivation")
    wrap_nonce_b64: str = Field(description="Base64 encoded AES-256-GCM wrapping nonce (12 bytes)")
    wrapped_cek_b64: str = Field(description="Base64 encoded wrapped CEK (32-byte key + 16-byte tag = 48 bytes)")
    public_key_fingerprint: str = Field(description="Recipient ML-KEM public key fingerprint")

    def get_kem_ciphertext_bytes(self) -> bytes:
        try:
            raw = base64.b64decode(self.kem_ciphertext_b64, validate=True)
            if len(raw) != 1088:
                raise ValidationError(f"Invalid ML-KEM-768 ciphertext length: {len(raw)} != 1088")
            return raw
        except Exception as e:
            raise ValidationError(f"Failed to decode ML-KEM ciphertext: {e}") from e

    def get_wrap_nonce_bytes(self) -> bytes:
        try:
            raw = base64.b64decode(self.wrap_nonce_b64, validate=True)
            if len(raw) != 12:
                raise ValidationError(f"Invalid wrap nonce length: {len(raw)} != 12")
            return raw
        except Exception as e:
            raise ValidationError(f"Failed to decode wrap nonce: {e}") from e

    def get_wrapped_cek_bytes(self) -> bytes:
        try:
            raw = base64.b64decode(self.wrapped_cek_b64, validate=True)
            if len(raw) != 48:
                raise ValidationError(f"Invalid wrapped CEK length: {len(raw)} != 48")
            return raw
        except Exception as e:
            raise ValidationError(f"Failed to decode wrapped CEK: {e}") from e

    @property
    def key_fingerprint(self) -> str:
        return self.public_key_fingerprint

    @property
    def mlkem_algorithm(self) -> str:
        return self.kem_algorithm

    @property
    def mlkem_parameter_set(self) -> str:
        return self.kem_parameter_set

    @property
    def encapsulated_key_b64(self) -> str:
        return self.kem_ciphertext_b64

    @property
    def encrypted_cek_b64(self) -> str:
        return self.wrapped_cek_b64


class DistributionPackageHeader(BaseModel):
    """Immutable canonical metadata header for a .tcdist package."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: str = Field(default="1.0.0")
    distribution_id: DistributionID
    document_id: DocumentID
    mime_type: str = Field(default="application/pdf")
    filename: str = Field(min_length=1, max_length=255)
    source_document_hash: str = Field(description="SHA3-256 hash of original unencrypted document")
    source_size_bytes: int = Field(ge=1)
    cipher_algorithm: str = Field(default="AES-256-GCM")
    kem_algorithm: str = Field(default="ML-KEM-768")
    recipient_envelopes: List[RecipientEnvelope] = Field(min_length=1)
    created_at: int = Field(description="POSIX microsecond timestamp")

    @property
    def recipients(self) -> List[RecipientEnvelope]:
        return self.recipient_envelopes

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Convert header to JSON-serializable dictionary."""
        return self.model_dump(mode="json")

    def to_canonical_bytes(self) -> bytes:
        """Serialize header using RFC 8785 JSON Canonicalization Scheme."""
        return canonicalize(self.to_canonical_dict())

    def compute_aad_bytes(self) -> bytes:
        """Produce deterministic RFC 8785 canonical bytes for Authenticated Associated Data."""
        aad_data: Dict[str, Any] = {
            "format_version": self.format_version,
            "distribution_id": str(self.distribution_id),
            "document_id": str(self.document_id),
            "mime_type": self.mime_type,
            "filename": self.filename,
            "source_document_hash": self.source_document_hash,
            "source_size_bytes": self.source_size_bytes,
            "cipher_algorithm": self.cipher_algorithm,
            "kem_algorithm": self.kem_algorithm,
            "recipient_count": len(self.recipient_envelopes),
            "recipient_fingerprints": sorted([e.public_key_fingerprint for e in self.recipient_envelopes]),
            "created_at": self.created_at,
        }
        return canonicalize(aad_data)


class SecureDocumentBuffer:
    """In-memory decrypted plaintext document buffer with explicit zeroization controls."""

    def __init__(
        self,
        data: bytes | bytearray,
        document_id: DocumentID,
        distribution_id: DistributionID,
        source_document_hash: str,
        mime_type: str = "application/pdf",
        filename: str = "document.pdf",
    ) -> None:
        self._buffer: bytearray = bytearray(data)
        self._document_id = document_id
        self._distribution_id = distribution_id
        self._source_document_hash = source_document_hash
        self._mime_type = mime_type
        self._filename = filename
        self._zeroized: bool = False

    @property
    def document_id(self) -> DocumentID:
        return self._document_id

    @property
    def distribution_id(self) -> DistributionID:
        return self._distribution_id

    @property
    def source_document_hash(self) -> str:
        return self._source_document_hash

    @property
    def mime_type(self) -> str:
        return self._mime_type

    @property
    def filename(self) -> str:
        return self._filename

    @property
    def size_bytes(self) -> int:
        if self._zeroized:
            raise SecurityError("SecureDocumentBuffer has already been zeroized.")
        return len(self._buffer)

    @property
    def raw_bytes(self) -> bytes:
        """Obtain immutable view of decrypted document bytes."""
        if self._zeroized:
            raise SecurityError("SecureDocumentBuffer has already been zeroized.")
        return bytes(self._buffer)

    def __len__(self) -> int:
        return self.size_bytes

    def __bytes__(self) -> bytes:
        return self.raw_bytes

    def zeroize(self) -> None:
        """Actively overwrite decrypted document buffer with zeros."""
        if not self._zeroized:
            for i in range(len(self._buffer)):
                self._buffer[i] = 0
            self._zeroized = True

    def __enter__(self) -> SecureDocumentBuffer:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.zeroize()

    def __del__(self) -> None:
        self.zeroize()

    def __repr__(self) -> str:
        status = "ZEROIZED" if self._zeroized else f"ACTIVE len={len(self._buffer)}"
        return f"<SecureDocumentBuffer id={self._document_id} status={status}>"


class PackageValidationResult(BaseModel):
    """Result of offline 17-point .tcdist package validation."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    valid: bool
    checks_passed: int = Field(ge=0, le=17)
    error: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)

    @property
    def errors(self) -> List[str]:
        if self.error:
            return [self.error]
        return self.details.get("errors", [])

    @property
    def header(self) -> Optional[Any]:
        return self.details.get("header")
