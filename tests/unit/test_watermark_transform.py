"""Unit tests for 2D Haar DWT and 8x8 Block DCT transforms.

Validates:
- 2D Haar DWT forward and inverse mathematical invertibility (MSE < 1e-12).
- Orthogonal 8x8 2D DCT forward and inverse invertibility (MSE < 1e-12).
- Full-image 8x8 block grid DCT and IDCT reconstruction.
- Mid-frequency zigzag coefficient extraction.
"""

import numpy as np
import pytest

from tracecrypt.watermark.transform import (
    dct2_block,
    dct2_image_blocks,
    get_zigzag_indices,
    haar_dwt2,
    haar_idwt2,
    idct2_block,
    idct2_image_blocks,
)


class TestHaarDWT:
    """Test 2D Haar Discrete Wavelet Transform accuracy."""

    def test_dwt_shapes(self) -> None:
        img = np.random.uniform(0, 255, (256, 256)).astype(np.float64)
        ll, lh, hl, hh = haar_dwt2(img)
        assert ll.shape == (128, 128)
        assert lh.shape == (128, 128)
        assert hl.shape == (128, 128)
        assert hh.shape == (128, 128)

    def test_dwt_odd_dimension_raises(self) -> None:
        img = np.random.uniform(0, 255, (255, 256)).astype(np.float64)
        with pytest.raises(ValueError):
            haar_dwt2(img)

    def test_dwt_perfect_reconstruction(self) -> None:
        """Verify idwt2(dwt2(image)) reconstructs within numerical tolerance (MSE < 1e-12)."""
        rng = np.random.default_rng(42)
        for h, w in [(64, 64), (128, 256), (512, 512)]:
            img = rng.uniform(0, 255, (h, w)).astype(np.float64)
            ll, lh, hl, hh = haar_dwt2(img)
            reconstructed = haar_idwt2(ll, lh, hl, hh)

            mse = np.mean((img - reconstructed) ** 2)
            assert mse < 1e-12, f"Haar DWT reconstruction MSE {mse} exceeds threshold"

    def test_constant_image_subbands(self) -> None:
        """For a constant image, detail subbands (LH, HL, HH) should be identically zero."""
        img = np.full((128, 128), 128.0, dtype=np.float64)
        ll, lh, hl, hh = haar_dwt2(img)
        assert np.allclose(ll, 256.0)
        assert np.allclose(lh, 0.0)
        assert np.allclose(hl, 0.0)
        assert np.allclose(hh, 0.0)


class TestBlockDCT:
    """Test 8x8 block-based Discrete Cosine Transform accuracy."""

    def test_single_block_reconstruction(self) -> None:
        rng = np.random.default_rng(123)
        block = rng.uniform(-128, 127, (8, 8)).astype(np.float64)
        freq = dct2_block(block)
        rec = idct2_block(freq)

        mse = np.mean((block - rec) ** 2)
        assert mse < 1e-12, f"DCT block reconstruction MSE {mse} exceeds threshold"

    def test_image_blocks_reconstruction(self) -> None:
        """Verify full image block DCT/IDCT reconstruction."""
        rng = np.random.default_rng(456)
        img = rng.uniform(0, 255, (128, 128)).astype(np.float64)
        freq_grid = dct2_image_blocks(img, block_size=8)
        assert freq_grid.shape == (128, 128)

        rec_img = idct2_image_blocks(freq_grid, block_size=8)
        mse = np.mean((img - rec_img) ** 2)
        assert mse < 1e-12, f"Full image block DCT reconstruction MSE {mse} exceeds threshold"

    def test_zigzag_ordering(self) -> None:
        """Verify 8x8 zigzag scan indices."""
        indices = get_zigzag_indices(8)
        assert len(indices) == 64
        # DC component must be first (0, 0)
        assert indices[0] == (0, 0)
        # All 64 grid positions must be unique and present
        assert len(set(indices)) == 64
        for r, c in indices:
            assert 0 <= r < 8
            assert 0 <= c < 8
        # Highest frequency (7, 7) must be last
        assert indices[-1] == (7, 7)
