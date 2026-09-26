"""Unit tests for Reed-Solomon RS(32,16) error correction over GF(2^8).

Validates:
- GF(2^8) field arithmetic correctness (multiplication, inversion, generator).
- Systematic Reed-Solomon RS(32,16) encoding (n=32, k=16, 2t=16, t=8).
- Error correction capabilities (0, 1, 2, 4, 8 symbol errors).
- Error detection beyond capacity (>= 9 errors fail deterministically).
- 2-block interleaving for 32-byte payload to 64-byte codeword.
- Burst error tolerance via interleaving.
"""

import os
import pytest

from tracecrypt.watermark.ecc import (
    GaloisField256,
    ReedSolomon32_16,
    ReedSolomonError,
    WatermarkPayloadEncoder,
)


class TestGaloisField256:
    """Test mathematical invariants of the GF(2^8) field representation."""

    def test_additive_identity_and_inverses(self) -> None:
        gf = GaloisField256()
        for a in range(256):
            assert gf.add(a, 0) == a
            assert gf.sub(a, 0) == a
            # In characteristic 2, addition and subtraction are XOR
            assert gf.add(a, a) == 0
            assert gf.sub(a, a) == 0

    def test_multiplicative_identity_and_inverses(self) -> None:
        gf = GaloisField256()
        for a in range(1, 256):
            assert gf.mul(a, 1) == a
            inv = gf.inv(a)
            assert gf.mul(a, inv) == 1
            assert gf.div(a, a) == 1

    def test_division_by_zero_fails(self) -> None:
        gf = GaloisField256()
        with pytest.raises(ZeroDivisionError):
            gf.div(5, 0)
        with pytest.raises(ZeroDivisionError):
            gf.inv(0)

    def test_generator_order(self) -> None:
        gf = GaloisField256()
        # Generator alpha=2 should generate all non-zero elements
        seen = set()
        val = 1
        for _ in range(255):
            seen.add(val)
            val = gf.mul(val, 2)
        assert len(seen) == 255
        assert val == 1  # 2^255 = 1 in GF(2^8)


class TestReedSolomon32_16:
    """Test systematic RS(32,16) codec."""

    def test_codeword_dimensions(self) -> None:
        rs = ReedSolomon32_16()
        assert rs.N == 32
        assert rs.K == 16
        assert rs.N_PARITY == 16
        assert rs.T_CAPACITY == 8

        msg = bytes(range(16))
        codeword = rs.encode(msg)
        assert len(codeword) == 32
        # Systematic property: first 16 bytes match message exactly
        assert codeword[:16] == msg

    def test_invalid_message_length(self) -> None:
        rs = ReedSolomon32_16()
        with pytest.raises(ValueError):
            rs.encode(b"too_short")
        with pytest.raises(ValueError):
            rs.decode(b"too_short_codeword")

    def test_uncorrupted_decode(self) -> None:
        rs = ReedSolomon32_16()
        msg = os.urandom(16)
        codeword = rs.encode(msg)
        recovered, corrected = rs.decode(codeword)
        assert recovered == msg
        assert corrected == 0

    @pytest.mark.parametrize("err_count", [1, 2, 3, 4, 6, 8])
    def test_correctable_errors(self, err_count: int) -> None:
        """Verify correction up to theoretical limit t = 8 symbol errors."""
        rs = ReedSolomon32_16()
        msg = os.urandom(16)
        codeword = bytearray(rs.encode(msg))

        # Select err_count distinct indices to corrupt
        error_positions = [i * 3 % 32 for i in range(err_count)]
        for pos in error_positions:
            codeword[pos] ^= 0x5A  # Flip bits to alter symbol

        recovered, corrected = rs.decode(bytes(codeword))
        assert recovered == msg
        assert corrected == err_count

    def test_uncorrectable_errors_fail_deterministically(self) -> None:
        """Inject 9 symbol errors (t=8 max capability); must fail closed."""
        rs = ReedSolomon32_16()
        msg = os.urandom(16)
        codeword = bytearray(rs.encode(msg))

        # Corrupt 9 distinct positions
        for pos in range(9):
            codeword[pos] ^= 0xFF

        with pytest.raises(ReedSolomonError):
            rs.decode(bytes(codeword))


class TestWatermarkPayloadEncoder:
    """Test 32-byte payload encoding into 64-byte interleaved codeword."""

    def test_dimensions(self) -> None:
        encoder = WatermarkPayloadEncoder()
        payload = os.urandom(32)
        coded = encoder.encode_payload(payload)
        assert len(coded) == 64

    def test_clean_roundtrip(self) -> None:
        encoder = WatermarkPayloadEncoder()
        payload = os.urandom(32)
        coded = encoder.encode_payload(payload)
        recovered, corrected = encoder.decode_payload(coded)
        assert recovered == payload
        assert corrected == 0

    def test_interleaved_burst_error_tolerance(self) -> None:
        """Verify that interleaving allows recovery of a burst of 16 corrupted bytes."""
        encoder = WatermarkPayloadEncoder()
        payload = os.urandom(32)
        coded = bytearray(encoder.encode_payload(payload))

        # Corrupt 16 consecutive bytes (e.g., indices 10 to 25)
        # Because of 2-way interleaving, block 0 gets 8 errors and block 1 gets 8 errors.
        # Both blocks are within their t=8 limit!
        for i in range(10, 26):
            coded[i] ^= 0x7E

        recovered, corrected = encoder.decode_payload(bytes(coded))
        assert recovered == payload
        assert corrected == 16

    def test_excessive_errors_fail(self) -> None:
        """Corrupt 20 consecutive bytes (10 errors per block, exceeding t=8)."""
        encoder = WatermarkPayloadEncoder()
        payload = os.urandom(32)
        coded = bytearray(encoder.encode_payload(payload))

        for i in range(20):
            coded[i] ^= 0xFF

        with pytest.raises(ReedSolomonError):
            encoder.decode_payload(bytes(coded))
