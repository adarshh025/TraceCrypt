"""Unit tests for DocumentHasher."""

from __future__ import annotations

from pathlib import Path
import pytest

from tracecrypt.document.hasher import DocumentHasher
from tracecrypt.errors import ValidationError


def test_hasher_bytes_exact_digest() -> None:
    """Verify that hashing bytes produces exact SHA3-256 digest without normalization."""
    data = b"CONFIDENTIAL SOURCE DOCUMENT\r\n\t  PADDING"
    digest = DocumentHasher.hash_bytes(data)

    assert digest.startswith("sha3-256:")
    assert len(digest) == len("sha3-256:") + 64
    assert DocumentHasher.verify_hash(data, digest) is True
    assert DocumentHasher.verify_hash(data + b" ", digest) is False


def test_hasher_file_stream(tmp_path: Path) -> None:
    """Verify that hashing from a file matches direct byte hashing."""
    test_file = tmp_path / "sample.pdf"
    content = b"%PDF-1.7\nSample document binary content\x00\xff\xfe"
    test_file.write_bytes(content)

    file_digest = DocumentHasher.hash_file(test_file)
    byte_digest = DocumentHasher.hash_bytes(content)

    assert file_digest == byte_digest


def test_hasher_invalid_input_type() -> None:
    """Verify that non-bytes inputs raise ValidationError."""
    with pytest.raises(ValidationError):
        DocumentHasher.hash_bytes("not bytes")  # type: ignore
