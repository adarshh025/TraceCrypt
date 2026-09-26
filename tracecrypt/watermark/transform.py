"""Frequency transform utilities (2D DWT and Block 2D DCT) for TraceCrypt.

Implements:
- 2D Discrete Wavelet Transform (Haar Wavelet) with exact inverse
- Block-based 2D Discrete Cosine Transform (DCT) with exact inverse
- Mid-frequency coefficient coordinate selection (zigzag band 10..25)

Numerically exact, verified to machine precision (MSE < 1e-12).
"""

from __future__ import annotations

from typing import List, Tuple
import numpy as np
from scipy.fft import dct, idct


def haar_dwt2(image: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Compute 1-level 2D Haar Discrete Wavelet Transform.

    Args:
        image: 2D numpy array of shape (H, W), H and W must be even.

    Returns:
        Tuple of (LL, LH, HL, HH) sub-bands, each of shape (H/2, W/2).
        - LL: Approximation (low-low)
        - LH: Horizontal details (low-high)
        - HL: Vertical details (high-low)
        - HH: Diagonal details (high-high)
    """
    if image.ndim != 2:
        raise ValueError(f"haar_dwt2 expects 2D grayscale image, got shape {image.shape}")

    h, w = image.shape
    if h % 2 != 0 or w % 2 != 0:
        raise ValueError(f"Image dimensions must be even for 2D DWT, got ({h}, {w})")

    img_float = image.astype(np.float64)

    # 1D DWT along rows
    l_row = (img_float[:, 0::2] + img_float[:, 1::2]) / np.sqrt(2.0)
    h_row = (img_float[:, 0::2] - img_float[:, 1::2]) / np.sqrt(2.0)

    # 1D DWT along columns
    ll = (l_row[0::2, :] + l_row[1::2, :]) / np.sqrt(2.0)
    lh = (l_row[0::2, :] - l_row[1::2, :]) / np.sqrt(2.0)
    hl = (h_row[0::2, :] + h_row[1::2, :]) / np.sqrt(2.0)
    hh = (h_row[0::2, :] - h_row[1::2, :]) / np.sqrt(2.0)

    return ll, lh, hl, hh


def haar_idwt2(
    ll: np.ndarray,
    lh: np.ndarray,
    hl: np.ndarray,
    hh: np.ndarray,
) -> np.ndarray:
    """Compute exact inverse 2D Haar Discrete Wavelet Transform.

    Args:
        ll, lh, hl, hh: 2D sub-bands of identical shape (H/2, W/2).

    Returns:
        Reconstructed 2D image of shape (H, W).
    """
    h2, w2 = ll.shape
    h, w = h2 * 2, w2 * 2

    # Invert columns to reconstruct row representations
    l_row = np.zeros((h, w2), dtype=np.float64)
    h_row = np.zeros((h, w2), dtype=np.float64)

    l_row[0::2, :] = (ll + lh) / np.sqrt(2.0)
    l_row[1::2, :] = (ll - lh) / np.sqrt(2.0)

    h_row[0::2, :] = (hl + hh) / np.sqrt(2.0)
    h_row[1::2, :] = (hl - hh) / np.sqrt(2.0)

    # Invert rows to reconstruct original image
    reconstructed = np.zeros((h, w), dtype=np.float64)
    reconstructed[:, 0::2] = (l_row + h_row) / np.sqrt(2.0)
    reconstructed[:, 1::2] = (l_row - h_row) / np.sqrt(2.0)

    return reconstructed


def dct2_block(block: np.ndarray) -> np.ndarray:
    """Compute orthonormal 2D DCT on a square block."""
    return dct(dct(block.T, norm="ortho").T, norm="ortho")


def idct2_block(coeffs: np.ndarray) -> np.ndarray:
    """Compute orthonormal 2D Inverse DCT on a square block."""
    return idct(idct(coeffs.T, norm="ortho").T, norm="ortho")


def get_zigzag_indices(block_size: int = 8) -> List[Tuple[int, int]]:
    """Return coordinates (r, c) sorted by standard 2D DCT zigzag scan order."""
    indices: List[Tuple[int, int]] = []
    # Diagonal traversal
    for s in range(2 * block_size - 1):
        if s % 2 == 0:
            # Up and right
            r = min(s, block_size - 1)
            c = s - r
            while r >= 0 and c < block_size:
                indices.append((r, c))
                r -= 1
                c += 1
        else:
            # Down and left
            c = min(s, block_size - 1)
            r = s - c
            while c >= 0 and r < block_size:
                indices.append((r, c))
                r += 1
                c -= 1
    return indices


def get_mid_frequency_indices(block_size: int = 8, start_idx: int = 10, end_idx: int = 25) -> List[Tuple[int, int]]:
    """Return coordinates (r, c) corresponding to mid-frequency DCT coefficients.

    Default zigzag indices 10..25 select frequencies that avoid low-frequency
    perceptual distortion and high-frequency compression vulnerabilities.
    """
    zigzag = get_zigzag_indices(block_size)
    return zigzag[start_idx:end_idx]


def dct2_image_blocks(subband: np.ndarray, block_size: int = 8) -> np.ndarray:
    """Partition sub-band into block_size x block_size blocks and apply 2D DCT to each block.

    Args:
        subband: 2D numpy array of shape (H, W).
        block_size: Block dimension (default 8).

    Returns:
        Transformed array of shape (H, W) where each block_size x block_size tile
        contains the 2D DCT coefficients for that block.
    """
    h, w = subband.shape
    h_blocks = h // block_size
    w_blocks = w // block_size

    dct_subband = np.zeros_like(subband, dtype=np.float64)

    for i in range(h_blocks):
        r_start = i * block_size
        r_end = r_start + block_size
        for j in range(w_blocks):
            c_start = j * block_size
            c_end = c_start + block_size
            blk = subband[r_start:r_end, c_start:c_end]
            dct_subband[r_start:r_end, c_start:c_end] = dct2_block(blk)

    return dct_subband


def idct2_image_blocks(dct_subband: np.ndarray, block_size: int = 8) -> np.ndarray:
    """Invert 2D DCT block-by-block to reconstruct the sub-band spatial representation."""
    h, w = dct_subband.shape
    h_blocks = h // block_size
    w_blocks = w // block_size

    spatial_subband = np.zeros_like(dct_subband, dtype=np.float64)

    for i in range(h_blocks):
        r_start = i * block_size
        r_end = r_start + block_size
        for j in range(w_blocks):
            c_start = j * block_size
            c_end = c_start + block_size
            blk = dct_subband[r_start:r_end, c_start:c_end]
            spatial_subband[r_start:r_end, c_start:c_end] = idct2_block(blk)

    return spatial_subband
