"""Unit tests for Reed-Solomon RS(32,16) forward error correction in forensic extraction."""

from __future__ import annotations

import pytest

from tracecrypt.utils.identifiers import SessionID, WatermarkID
from tracecrypt.watermark.ecc import ReedSolomonError, WatermarkPayloadEncoder
from tracecrypt.watermark.types import WatermarkPayload


class TestECCRecovery:
    """Validate RS(32,16) 16-symbol codeword error correction capabilities and limits."""

    def test_rs_clean_decode_zero_errors(self) -> None:
        encoder = WatermarkPayloadEncoder()
        wmid = WatermarkID.generate()
        sid = SessionID.generate()
        payload = WatermarkPayload.create(
            watermark_id=wmid,
            session_id=sid,
            document_hash="sha3-256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        )
        raw_payload = payload.to_bytes()
        encoded = bytearray(encoder.encode_payload(raw_payload))

        decoded, num_corrected = encoder.decode_payload(bytes(encoded))
        assert decoded == raw_payload
        assert num_corrected == 0

    def test_rs_corrects_within_capacity(self) -> None:
        """RS(32,16) can correct up to t = (32 - 16) / 2 = 8 byte symbol errors."""
        encoder = WatermarkPayloadEncoder()
        wmid = WatermarkID.generate()
        sid = SessionID.generate()
        payload = WatermarkPayload.create(
            watermark_id=wmid,
            session_id=sid,
            document_hash="sha3-256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        )
        raw_payload = payload.to_bytes()
        encoded = bytearray(encoder.encode_payload(raw_payload))

        # Test corrupting 1, 3, 5, 8 symbols
        for num_errors in [1, 3, 5, 8]:
            corrupted = bytearray(encoded)
            for i in range(num_errors):
                corrupted[i * 3] ^= 0xFF  # Flip bits in distinct symbols

            decoded, num_corrected = encoder.decode_payload(bytes(corrupted))
            assert decoded == raw_payload
            assert num_corrected == num_errors

    def test_rs_exceeding_capacity_raises_error(self) -> None:
        """Corrupting 9 or more symbols exceeds RS(32,16) capacity and must fail safely."""
        encoder = WatermarkPayloadEncoder()
        wmid = WatermarkID.generate()
        sid = SessionID.generate()
        payload = WatermarkPayload.create(
            watermark_id=wmid,
            session_id=sid,
            document_hash="sha3-256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        )
        raw_payload = payload.to_bytes()
        encoded = bytearray(encoder.encode_payload(raw_payload))

        # Corrupt 10 symbols (> 8)
        corrupted = bytearray(encoded)
        for i in range(10):
            corrupted[i * 2] ^= 0xAA

        with pytest.raises(ReedSolomonError):
            encoder.decode_payload(bytes(corrupted))
