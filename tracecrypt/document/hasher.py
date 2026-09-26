"""Cryptographic document hashing utilities for TraceCrypt.

Computes immutable SHA3-256 source document hashes without silent normalization.
Explicitly distinguishes source document hashes from future rendered or watermarked hashes.
"""

from __future__ import annotations

from pathlib import Path
from tracecrypt.crypto.hashing import HashAlgorithm, Hasher
from tracecrypt.errors import ValidationError


class DocumentHasher:
    """Computes and verifies exact SHA3-256 cryptographic digests of source documents."""

    HASH_ALGORITHM = HashAlgorithm.SHA3_256.value

    @classmethod
    def hash_bytes(cls, data: bytes) -> str:
        """Calculate canonical SHA3-256 hash of raw source document bytes.

        Does NOT perform any normalization, whitespace stripping, or transcoding.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise ValidationError(f"DocumentHasher expects bytes, got {type(data).__name__}")
        digest = Hasher.digest_bytes(bytes(data), cls.HASH_ALGORITHM)
        return digest.formatted

    @classmethod
    def hash_file(cls, filepath: Path | str) -> str:
        """Calculate canonical SHA3-256 hash of an on-disk source document."""
        path = Path(filepath)
        if not path.is_file():
            raise FileNotFoundError(f"Document file not found: {path}")
        digest = Hasher.digest_file(path, cls.HASH_ALGORITHM)
        return digest.formatted

    @classmethod
    def verify_hash(cls, data: bytes, expected_hash: str) -> bool:
        """Verify that document bytes match the expected source hash."""
        computed = cls.hash_bytes(data)
        return computed == expected_hash
