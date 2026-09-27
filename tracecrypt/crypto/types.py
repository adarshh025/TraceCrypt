"""Strongly typed cryptographic key representations and key metadata for TraceCrypt.

Enforces strict key lengths, binary representation, key-purpose separation,
public-key fingerprinting, and zeroization for private key material.
"""

from __future__ import annotations

import base64
from enum import Enum
from typing import ClassVar, Optional
from pydantic import BaseModel, ConfigDict, Field

from tracecrypt.crypto.hashing import HashAlgorithm, Hasher
from tracecrypt.errors import CryptographicError, ValidationError


class KeyPurpose(str, Enum):
    """Cryptographic purpose. Enforces separation between KEM and DSA."""
    KEY_ENCAPSULATION = "KEY_ENCAPSULATION"
    DIGITAL_SIGNATURE = "DIGITAL_SIGNATURE"
    ROOT_AUTHORITY = "ROOT_AUTHORITY"
    CONSENSUS_VALIDATION = "CONSENSUS_VALIDATION"


class KeyStatus(str, Enum):
    """Explicit lifecycle states for cryptographic keys."""
    GENERATED = "GENERATED"
    PENDING_ACTIVATION = "PENDING_ACTIVATION"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    COMPROMISED = "COMPROMISED"
    DESTROYED = "DESTROYED"


# -------------------------------------------------------------------------
# ML-KEM-768 Types (NIST FIPS 203)
# -------------------------------------------------------------------------

class MLKEMPublicKey:
    """Strongly-typed NIST FIPS 203 ML-KEM-768 public encapsulation key (1184 bytes)."""
    EXPECTED_LENGTH: ClassVar[int] = 1184
    ALGORITHM: ClassVar[str] = "ML-KEM-768"

    def __init__(self, key_bytes: Union[bytes, bytearray, MLKEMPublicKey]) -> None:
        self._key_bytes = b""
        self._fingerprint = ""
        if isinstance(key_bytes, MLKEMPublicKey):
            key_bytes = key_bytes.raw_bytes
        if not isinstance(key_bytes, (bytes, bytearray)):
            raise ValidationError(f"MLKEMPublicKey must be bytes, got {type(key_bytes).__name__}")
        if len(key_bytes) != self.EXPECTED_LENGTH:
            raise ValidationError(
                f"Invalid ML-KEM-768 public key length: expected {self.EXPECTED_LENGTH} bytes, got {len(key_bytes)}"
            )
        self._key_bytes = bytes(key_bytes)
        digest = Hasher.digest_bytes(self._key_bytes, HashAlgorithm.SHA3_256.value)
        self._fingerprint = f"mlkem768:{digest.formatted}"

    @property
    def raw_bytes(self) -> bytes:
        """Return raw public key bytes."""
        return self._key_bytes

    @property
    def fingerprint(self) -> str:
        """Return canonical deterministic fingerprint: 'mlkem768:sha3-256:<hex>'."""
        return self._fingerprint

    @property
    def purpose(self) -> KeyPurpose:
        return KeyPurpose.KEY_ENCAPSULATION

    @property
    def algorithm(self) -> str:
        return self.ALGORITHM

    def to_b64(self) -> str:
        """Return base64-encoded string representation."""
        return base64.b64encode(self._key_bytes).decode("ascii")

    @classmethod
    def from_b64(cls, b64_str: str) -> MLKEMPublicKey:
        """Construct from base64-encoded string."""
        try:
            raw = base64.b64decode(b64_str, validate=True)
            return cls(raw)
        except Exception as e:
            raise ValidationError(f"Failed to decode base64 MLKEMPublicKey: {e}") from e

    def __repr__(self) -> str:
        return f"<MLKEMPublicKey algorithm={self.ALGORITHM} fingerprint={self._fingerprint}>"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, MLKEMPublicKey):
            return self._key_bytes == other._key_bytes
        return False

    def __hash__(self) -> int:
        return hash(self._key_bytes)


class MLKEMPrivateKey:
    """Strongly-typed NIST FIPS 203 ML-KEM-768 private decapsulation key (2400 bytes)."""
    EXPECTED_LENGTH: ClassVar[int] = 2400
    ALGORITHM: ClassVar[str] = "ML-KEM-768"

    def __init__(self, key_bytes: Union[bytes, bytearray, MLKEMPrivateKey]) -> None:
        self._key_bytes: Optional[bytearray] = None
        if isinstance(key_bytes, MLKEMPrivateKey):
            key_bytes = key_bytes.raw_bytes
        if not isinstance(key_bytes, (bytes, bytearray)):
            raise ValidationError(f"MLKEMPrivateKey must be bytes, got {type(key_bytes).__name__}")
        if len(key_bytes) != self.EXPECTED_LENGTH:
            raise ValidationError(
                f"Invalid ML-KEM-768 private key length: expected {self.EXPECTED_LENGTH} bytes, got {len(key_bytes)}"
            )
        self._key_bytes = bytearray(key_bytes)

    @property
    def raw_bytes(self) -> bytes:
        """Return copy of raw private key bytes."""
        if self._key_bytes is None:
            raise CryptographicError("MLKEMPrivateKey has been zeroized or destroyed.")
        return bytes(self._key_bytes)

    @property
    def purpose(self) -> KeyPurpose:
        return KeyPurpose.KEY_ENCAPSULATION

    @property
    def algorithm(self) -> str:
        return self.ALGORITHM

    def zeroize(self) -> None:
        """Actively overwrite private key bytes in memory with zeros."""
        if self._key_bytes is not None:
            for i in range(len(self._key_bytes)):
                self._key_bytes[i] = 0
            self._key_bytes = None

    def __repr__(self) -> str:
        status = "ZEROIZED" if self._key_bytes is None else "ACTIVE"
        return f"<MLKEMPrivateKey algorithm={self.ALGORITHM} status={status} [REDACTED]>"

    def __del__(self) -> None:
        self.zeroize()


class MLKEMCiphertext:
    """Strongly-typed NIST FIPS 203 ML-KEM-768 ciphertext (1088 bytes)."""
    EXPECTED_LENGTH: ClassVar[int] = 1088

    def __init__(self, ct_bytes: bytes) -> None:
        self._ct_bytes = b""
        if not isinstance(ct_bytes, (bytes, bytearray)):
            raise ValidationError(f"MLKEMCiphertext must be bytes, got {type(ct_bytes).__name__}")
        if len(ct_bytes) != self.EXPECTED_LENGTH:
            raise ValidationError(
                f"Invalid ML-KEM-768 ciphertext length: expected {self.EXPECTED_LENGTH} bytes, got {len(ct_bytes)}"
            )
        self._ct_bytes = bytes(ct_bytes)

    @property
    def raw_bytes(self) -> bytes:
        return self._ct_bytes

    def to_b64(self) -> str:
        return base64.b64encode(self._ct_bytes).decode("ascii")

    @classmethod
    def from_b64(cls, b64_str: str) -> MLKEMCiphertext:
        try:
            raw = base64.b64decode(b64_str, validate=True)
            return cls(raw)
        except Exception as e:
            raise ValidationError(f"Failed to decode base64 MLKEMCiphertext: {e}") from e

    def __repr__(self) -> str:
        return f"<MLKEMCiphertext len={len(self._ct_bytes)}>"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, MLKEMCiphertext):
            return self._ct_bytes == other._ct_bytes
        return False


# -------------------------------------------------------------------------
# ML-DSA-65 Types (NIST FIPS 204)
# -------------------------------------------------------------------------

class MLDSAPublicKey:
    """Strongly-typed NIST FIPS 204 ML-DSA-65 public verification key (1952 bytes)."""
    EXPECTED_LENGTH: ClassVar[int] = 1952
    ALGORITHM: ClassVar[str] = "ML-DSA-65"

    def __init__(self, key_bytes: Union[bytes, bytearray, MLDSAPublicKey]) -> None:
        self._key_bytes = b""
        self._fingerprint = ""
        if isinstance(key_bytes, MLDSAPublicKey):
            key_bytes = key_bytes.raw_bytes
        if not isinstance(key_bytes, (bytes, bytearray)):
            raise ValidationError(f"MLDSAPublicKey must be bytes, got {type(key_bytes).__name__}")
        if len(key_bytes) != self.EXPECTED_LENGTH:
            raise ValidationError(
                f"Invalid ML-DSA-65 public key length: expected {self.EXPECTED_LENGTH} bytes, got {len(key_bytes)}"
            )
        self._key_bytes = bytes(key_bytes)
        digest = Hasher.digest_bytes(self._key_bytes, HashAlgorithm.SHA3_256.value)
        self._fingerprint = f"mldsa65:{digest.formatted}"

    @property
    def raw_bytes(self) -> bytes:
        return self._key_bytes

    @property
    def fingerprint(self) -> str:
        """Return canonical deterministic fingerprint: 'mldsa65:sha3-256:<hex>'."""
        return self._fingerprint

    @property
    def purpose(self) -> KeyPurpose:
        return KeyPurpose.DIGITAL_SIGNATURE

    @property
    def algorithm(self) -> str:
        return self.ALGORITHM

    def to_b64(self) -> str:
        return base64.b64encode(self._key_bytes).decode("ascii")

    @classmethod
    def from_b64(cls, b64_str: str) -> MLDSAPublicKey:
        try:
            raw = base64.b64decode(b64_str, validate=True)
            return cls(raw)
        except Exception as e:
            raise ValidationError(f"Failed to decode base64 MLDSAPublicKey: {e}") from e

    def __repr__(self) -> str:
        return f"<MLDSAPublicKey algorithm={self.ALGORITHM} fingerprint={self._fingerprint}>"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, MLDSAPublicKey):
            return self._key_bytes == other._key_bytes
        return False

    def __hash__(self) -> int:
        return hash(self._key_bytes)


class MLDSAPrivateKey:
    """Strongly-typed NIST FIPS 204 ML-DSA-65 private signing key (4032 bytes)."""
    EXPECTED_LENGTH: ClassVar[int] = 4032
    ALGORITHM: ClassVar[str] = "ML-DSA-65"

    def __init__(self, key_bytes: Union[bytes, bytearray, MLDSAPrivateKey]) -> None:
        self._key_bytes: Optional[bytearray] = None
        if isinstance(key_bytes, MLDSAPrivateKey):
            key_bytes = key_bytes.raw_bytes
        if not isinstance(key_bytes, (bytes, bytearray)):
            raise ValidationError(f"MLDSAPrivateKey must be bytes, got {type(key_bytes).__name__}")
        if len(key_bytes) != self.EXPECTED_LENGTH:
            raise ValidationError(
                f"Invalid ML-DSA-65 private key length: expected {self.EXPECTED_LENGTH} bytes, got {len(key_bytes)}"
            )
        self._key_bytes = bytearray(key_bytes)

    @property
    def raw_bytes(self) -> bytes:
        if self._key_bytes is None:
            raise CryptographicError("MLDSAPrivateKey has been zeroized or destroyed.")
        return bytes(self._key_bytes)

    @property
    def purpose(self) -> KeyPurpose:
        return KeyPurpose.DIGITAL_SIGNATURE

    @property
    def algorithm(self) -> str:
        return self.ALGORITHM

    def to_b64(self) -> str:
        """Encode raw private key bytes to base64."""
        return base64.b64encode(self.raw_bytes).decode("ascii")

    @classmethod
    def from_b64(cls, b64_str: str) -> MLDSAPrivateKey:
        """Construct MLDSAPrivateKey from base64-encoded string."""
        try:
            raw = base64.b64decode(b64_str, validate=True)
            return cls(raw)
        except Exception as e:
            raise ValidationError(f"Failed to decode base64 MLDSAPrivateKey: {e}") from e

    def zeroize(self) -> None:
        """Actively overwrite private key bytes in memory with zeros."""
        if self._key_bytes is not None:
            for i in range(len(self._key_bytes)):
                self._key_bytes[i] = 0
            self._key_bytes = None

    def __repr__(self) -> str:
        status = "ZEROIZED" if self._key_bytes is None else "ACTIVE"
        return f"<MLDSAPrivateKey algorithm={self.ALGORITHM} status={status} [REDACTED]>"

    def __del__(self) -> None:
        self.zeroize()


class MLDSASignature:
    """Strongly-typed NIST FIPS 204 ML-DSA-65 digital signature (3309 bytes)."""
    EXPECTED_LENGTH: ClassVar[int] = 3309

    def __init__(self, sig_bytes: bytes) -> None:
        self._sig_bytes = b""
        if not isinstance(sig_bytes, (bytes, bytearray)):
            raise ValidationError(f"MLDSASignature must be bytes, got {type(sig_bytes).__name__}")
        if len(sig_bytes) != self.EXPECTED_LENGTH:
            raise ValidationError(
                f"Invalid ML-DSA-65 signature length: expected {self.EXPECTED_LENGTH} bytes, got {len(sig_bytes)}"
            )
        self._sig_bytes = bytes(sig_bytes)

    @property
    def raw_bytes(self) -> bytes:
        return self._sig_bytes

    def to_b64(self) -> str:
        return base64.b64encode(self._sig_bytes).decode("ascii")

    @classmethod
    def from_b64(cls, b64_str: str) -> MLDSASignature:
        try:
            raw = base64.b64decode(b64_str, validate=True)
            return cls(raw)
        except Exception as e:
            raise ValidationError(f"Failed to decode base64 MLDSASignature: {e}") from e

    def __repr__(self) -> str:
        return f"<MLDSASignature len={len(self._sig_bytes)}>"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, MLDSASignature):
            return self._sig_bytes == other._sig_bytes
        return False


# -------------------------------------------------------------------------
# Key Metadata & References
# -------------------------------------------------------------------------

class KeyMetadata(BaseModel):
    """Metadata bound immutably to a cryptographic key instance."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    key_id: str = Field(description="Unique key identifier, e.g. key-...")
    owner_id: str = Field(description="UserID or RecipientID")
    purpose: KeyPurpose = Field(description="Enforced cryptographic role")
    algorithm: str = Field(description="Standardized algorithm (ML-KEM-768 or ML-DSA-65)")
    parameter_set: str = Field(description="Parameter set name")
    created_at: int = Field(description="POSIX microsecond timestamp")
    activated_at: Optional[int] = Field(default=None)
    expires_at: Optional[int] = Field(default=None)
    status: KeyStatus = Field(default=KeyStatus.GENERATED)
    version: int = Field(default=1, ge=1)
    fingerprint: str = Field(description="Public key fingerprint")


class KeyReference(BaseModel):
    """Safe reference to a public key without exposing private material."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    key_id: str
    owner_id: str
    purpose: KeyPurpose
    algorithm: str
    public_key_b64: str
    fingerprint: str
    status: KeyStatus
    created_at: int
    expires_at: Optional[int] = None
