"""Unit tests for WatermarkPayload serialization, CRC-16, and cryptographic binding.

Validates:
- Exact 256-bit (32-byte) binary layout.
- Field widths, byte ordering, and version invariants.
- CRC-16-CCITT integrity checksum calculation and tamper detection.
- Cryptographic domain-separated document binding.
- Anti-collision and CSPRNG freshness guarantees (no PII, distinct IDs).
"""

from tracecrypt.crypto.random import SecureRandom
from tracecrypt.errors import ValidationError
from tracecrypt.utils.identifiers import SessionID, WatermarkID
from tracecrypt.watermark.types import WatermarkPayload


class TestWatermarkPayload:
    """Test 256-bit watermark payload structure and integrity."""

    def test_payload_exact_size(self) -> None:
        wm_id = SecureRandom.generate_typed_id(WatermarkID)
        ses_id = SecureRandom.generate_typed_id(SessionID)
        doc_hash = "sha3-256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

        payload = WatermarkPayload.create(wm_id, ses_id, doc_hash)
        raw = payload.to_bytes()

        assert len(raw) == 32
        assert len(raw) * 8 == 256

    def test_roundtrip_serialization(self) -> None:
        wm_id = SecureRandom.generate_typed_id(WatermarkID)
        ses_id = SecureRandom.generate_typed_id(SessionID)
        doc_hash = "sha3-256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

        payload = WatermarkPayload.create(wm_id, ses_id, doc_hash)
        raw = payload.to_bytes()

        restored = WatermarkPayload.from_bytes(raw)
        assert restored.version == 1
        assert restored.watermark_id == wm_id
        assert restored.session_tag == payload.session_tag
        assert restored.document_binding == payload.document_binding
        assert restored.checksum == payload.checksum

    def test_tamper_detection_via_checksum(self) -> None:
        wm_id = SecureRandom.generate_typed_id(WatermarkID)
        ses_id = SecureRandom.generate_typed_id(SessionID)
        doc_hash = "sha3-256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

        payload = WatermarkPayload.create(wm_id, ses_id, doc_hash)
        raw = bytearray(payload.to_bytes())

        # Flip a bit in the WatermarkID
        raw[5] ^= 0x01
        import pytest
        with pytest.raises(ValidationError):
            WatermarkPayload.from_bytes(bytes(raw))

    def test_document_binding_verification(self) -> None:
        wm_id = SecureRandom.generate_typed_id(WatermarkID)
        ses_id = SecureRandom.generate_typed_id(SessionID)
        doc_hash1 = "sha3-256:1111111111111111111111111111111111111111111111111111111111111111"
        doc_hash2 = "sha3-256:2222222222222222222222222222222222222222222222222222222222222222"

        payload = WatermarkPayload.create(wm_id, ses_id, doc_hash1)
        assert payload.verify_document_binding(doc_hash1, ses_id) is True
        # Wrong document must fail binding check
        assert payload.verify_document_binding(doc_hash2, ses_id) is False

    def test_anti_collision_uniqueness(self) -> None:
        """Verify that repeated generations yield strictly unique IDs."""
        wm_ids = {SecureRandom.generate_typed_id(WatermarkID) for _ in range(1000)}
        assert len(wm_ids) == 1000

        ses_ids = {SecureRandom.generate_typed_id(SessionID) for _ in range(1000)}
        assert len(ses_ids) == 1000

    def test_no_plaintext_pii(self) -> None:
        """Verify no recipient name, email, or credentials appear in the 32-byte payload."""
        wm_id = SecureRandom.generate_typed_id(WatermarkID)
        ses_id = SecureRandom.generate_typed_id(SessionID)
        doc_hash = "sha3-256:3333333333333333333333333333333333333333333333333333333333333333"

        payload = WatermarkPayload.create(wm_id, ses_id, doc_hash)
        raw = payload.to_bytes()

        # Check for ASCII strings that look like common PII
        for keyword in [b"alice", b"bob", b"admin", b"@example", b"tracecrypt", b"http"]:
            assert keyword not in raw
