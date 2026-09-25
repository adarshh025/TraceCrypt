"""Unit tests for secure CSPRNG randomness abstraction."""

from unittest.mock import patch
import pytest

from tracecrypt.crypto.random import SecureRandom
from tracecrypt.errors import ValidationError
from tracecrypt.utils.identifiers import DocumentID, SessionID, WatermarkID


@pytest.mark.unit
def test_random_bytes():
    b1 = SecureRandom.random_bytes(32)
    b2 = SecureRandom.random_bytes(32)
    assert len(b1) == 32
    assert len(b2) == 32
    assert b1 != b2  # Independent entropy


@pytest.mark.unit
def test_random_nonce_128():
    n1 = SecureRandom.random_nonce_128()
    n2 = SecureRandom.random_nonce_128()
    assert len(n1) == 32  # 16 bytes hex = 32 chars
    assert n1 != n2


@pytest.mark.unit
def test_generate_typed_id():
    doc_id = SecureRandom.generate_id(DocumentID)
    ses_id = SecureRandom.generate_id(SessionID)
    wm_id = SecureRandom.generate_id(WatermarkID)

    assert isinstance(doc_id, DocumentID)
    assert doc_id.startswith("doc-")
    assert isinstance(ses_id, SessionID)
    assert ses_id.startswith("ses-")
    assert isinstance(wm_id, WatermarkID)
    assert wm_id.startswith("wm-")


@pytest.mark.unit
def test_invalid_byte_length_rejection():
    with pytest.raises(ValidationError):
        SecureRandom.random_bytes(0)
    with pytest.raises(ValidationError):
        SecureRandom.random_bytes(-5)


@pytest.mark.unit
def test_zero_reliance_on_insecure_prng():
    """Prove that SecureRandom does not invoke Python's non-cryptographic random module."""
    with patch("random.random", side_effect=RuntimeError("INSECURE PRNG CALLED")):
        with patch("random.randint", side_effect=RuntimeError("INSECURE PRNG CALLED")):
            # All calls below must succeed using os.urandom without triggering the mock
            b = SecureRandom.random_bytes(16)
            nonce = SecureRandom.random_nonce_128()
            doc_id = SecureRandom.generate_id(DocumentID)
            assert len(b) == 16
            assert len(nonce) == 32
            assert str(doc_id).startswith("doc-")
