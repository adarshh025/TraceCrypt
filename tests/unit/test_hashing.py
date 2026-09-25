"""Unit tests for SHA-3 deterministic hashing utilities."""

import io
import pytest

from tracecrypt.crypto.hashing import HashAlgorithm, HashDigest, Hasher
from tracecrypt.errors import CryptographicError, ValidationError


@pytest.mark.unit
def test_digest_bytes_format():
    data = b"TraceCrypt Post-Quantum Forensic Attribution"
    digest = Hasher.digest_bytes(data, algorithm=HashAlgorithm.SHA3_256.value)
    assert digest.algorithm == "sha3-256"
    assert len(digest.hex_digest) == 64
    assert str(digest).startswith("sha3-256:")
    assert digest.formatted == f"sha3-256:{digest.hex_digest}"


@pytest.mark.unit
def test_digest_determinism():
    data = b"Deterministic payload check"
    d1 = Hasher.digest_bytes(data, HashAlgorithm.SHA3_256.value)
    d2 = Hasher.digest_bytes(data, HashAlgorithm.SHA3_256.value)
    assert d1 == d2
    assert d1.hex_digest == d2.hex_digest


@pytest.mark.unit
def test_digest_file():
    content = b"Large streamed file content simulation " * 1000
    stream = io.BytesIO(content)
    digest_stream = Hasher.digest_file(stream, HashAlgorithm.SHA3_256.value)
    digest_bytes = Hasher.digest_bytes(content, HashAlgorithm.SHA3_256.value)
    assert digest_stream == digest_bytes


@pytest.mark.unit
def test_verify_hash():
    data = b"Confidential document section"
    digest = Hasher.digest_bytes(data)
    assert Hasher.verify(data, digest)
    assert Hasher.verify(data, digest.formatted)
    # Corrupted data should fail verification
    assert not Hasher.verify(b"Tampered document section", digest)


@pytest.mark.unit
def test_unsupported_algorithm_rejection():
    with pytest.raises(CryptographicError, match="Unsupported"):
        Hasher.digest_bytes(b"data", algorithm="md5")


@pytest.mark.unit
def test_malformed_hash_digest_string():
    with pytest.raises(ValidationError):
        HashDigest.from_formatted("invalid_no_colon")
    with pytest.raises(ValidationError):
        HashDigest.from_formatted(":empty_algo")
