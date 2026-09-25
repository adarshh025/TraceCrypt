"""Deterministic SHA-3 family hashing utilities for TraceCrypt.

All hashes are formatted in the canonical representation: '<algorithm>:<hex>'
(e.g., 'sha3-256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855').
"""

from __future__ import annotations

import hashlib
from enum import Enum
from pathlib import Path
from typing import BinaryIO, Union

from tracecrypt.errors import CryptographicError, ValidationError


class HashAlgorithm(str, Enum):
    """Supported cryptographic hash algorithms."""
    SHA3_256 = "sha3-256"
    SHA3_512 = "sha3-512"
    SHAKE_256 = "shake-256"
    SHA_256 = "sha-256"


class HashDigest:
    """Strongly-typed hash digest envelope maintaining the algorithm and hex string."""

    def __init__(self, algorithm: str, hex_digest: str) -> None:
        self.algorithm = algorithm.lower().strip()
        self.hex_digest = hex_digest.lower().strip()
        self._formatted = f"{self.algorithm}:{self.hex_digest}"

    @classmethod
    def from_formatted(cls, formatted_string: str) -> HashDigest:
        """Parse a '<algorithm>:<hex>' formatted string."""
        if not isinstance(formatted_string, str):
            raise ValidationError(f"Formatted hash must be str, got {type(formatted_string).__name__}")
        if ":" not in formatted_string:
            raise ValidationError(f"Invalid formatted digest. Expected '<algorithm>:<hex>', got '{formatted_string}'")
        algo, hex_val = formatted_string.split(":", 1)
        if not algo or not hex_val:
            raise ValidationError(f"Malformed hash digest string: '{formatted_string}'")
        return cls(algo, hex_val)

    @property
    def formatted(self) -> str:
        """Return the canonical formatted string representation."""
        return self._formatted

    def __str__(self) -> str:
        return self._formatted

    def __repr__(self) -> str:
        return f"HashDigest('{self._formatted}')"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, HashDigest):
            return self._formatted == other._formatted
        if isinstance(other, str):
            return self._formatted == other.lower().strip()
        return False

    def __hash__(self) -> int:
        return hash(self._formatted)


class Hasher:
    """Deterministic hashing engine supporting bytes, files, and canonical streams."""

    CHUNK_SIZE = 64 * 1024  # 64 KB streaming chunks

    @classmethod
    def _get_hash_instance(cls, algorithm: str) -> hashlib._Hash:
        norm_algo = algorithm.lower().strip()
        if norm_algo == HashAlgorithm.SHA3_256.value:
            return hashlib.sha3_256()
        elif norm_algo == HashAlgorithm.SHA3_512.value:
            return hashlib.sha3_512()
        elif norm_algo == HashAlgorithm.SHA_256.value:
            return hashlib.sha256()
        else:
            raise CryptographicError(f"Unsupported or unauthorized hash algorithm: '{algorithm}'")

    @classmethod
    def digest_bytes(cls, data: bytes, algorithm: str = HashAlgorithm.SHA3_256.value) -> HashDigest:
        """Compute formatted digest for arbitrary raw bytes."""
        if not isinstance(data, (bytes, bytearray)):
            raise ValidationError(f"Data to hash must be bytes or bytearray, got {type(data).__name__}")
        hasher = cls._get_hash_instance(algorithm)
        hasher.update(data)
        return HashDigest(algorithm, hasher.hexdigest())

    @classmethod
    def digest_file(
        cls,
        file_input: Union[str, Path, BinaryIO],
        algorithm: str = HashAlgorithm.SHA3_256.value,
        chunk_size: int = CHUNK_SIZE
    ) -> HashDigest:
        """Compute formatted digest for a file path or binary stream using chunks."""
        hasher = cls._get_hash_instance(algorithm)
        if isinstance(file_input, (str, Path)):
            p = Path(file_input)
            if not p.is_file():
                raise ValidationError(f"Target path does not exist or is not a file: {p}")
            with p.open("rb") as f:
                while chunk := f.read(chunk_size):
                    hasher.update(chunk)
        elif hasattr(file_input, "read"):
            while chunk := file_input.read(chunk_size):
                hasher.update(chunk)
        else:
            raise ValidationError(f"Invalid file input type: {type(file_input).__name__}")
        return HashDigest(algorithm, hasher.hexdigest())

    @classmethod
    def digest_canonical(cls, canonical_bytes: bytes, algorithm: str = HashAlgorithm.SHA3_256.value) -> HashDigest:
        """Compute formatted digest for RFC 8785 canonical bytes."""
        return cls.digest_bytes(canonical_bytes, algorithm)

    @classmethod
    def verify(cls, data: bytes, expected_digest: Union[str, HashDigest]) -> bool:
        """Verify that data matches the expected formatted hash digest."""
        if isinstance(expected_digest, str):
            exp = HashDigest.from_formatted(expected_digest)
        elif isinstance(expected_digest, HashDigest):
            exp = expected_digest
        else:
            raise ValidationError(f"Expected digest must be str or HashDigest, got {type(expected_digest).__name__}")
        actual = cls.digest_bytes(data, exp.algorithm)
        return actual == exp
