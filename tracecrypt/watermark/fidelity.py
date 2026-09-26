"""Perceptual fidelity and error metrics for TraceCrypt watermarking.

Calculates:
- Peak Signal-to-Noise Ratio (PSNR in dB)
- Structural Similarity Index (SSIM)
- Bit Error Rate (BER)
- Symbol Error Rate (SER)
"""

from __future__ import annotations

import numpy as np
from scipy.ndimage import gaussian_filter

from tracecrypt.watermark.types import FidelityMetrics


def calculate_mse(original: np.ndarray, watermarked: np.ndarray) -> float:
    """Compute Mean Squared Error between pristine and watermarked images."""
    if original.shape != watermarked.shape:
        raise ValueError(f"Shape mismatch: {original.shape} vs {watermarked.shape}")
    diff = original.astype(np.float64) - watermarked.astype(np.float64)
    return float(np.mean(diff ** 2))


def calculate_psnr(original: np.ndarray, watermarked: np.ndarray, max_val: float = 255.0) -> float:
    """Compute Peak Signal-to-Noise Ratio in decibels (dB).

    A higher value indicates superior perceptual fidelity.
    TraceCrypt acceptance target: PSNR >= 42.0 dB.
    """
    mse = calculate_mse(original, watermarked)
    if mse == 0.0:
        return 100.0  # Identical images
    return float(10.0 * np.log10((max_val ** 2) / mse))


def calculate_ssim(
    original: np.ndarray,
    watermarked: np.ndarray,
    max_val: float = 255.0,
    k1: float = 0.01,
    k2: float = 0.03,
    sigma: float = 1.5,
) -> float:
    """Compute Structural Similarity Index (SSIM) using standard Gaussian weighting.

    Wang et al. (2004) canonical implementation.
    TraceCrypt acceptance target: SSIM >= 0.995.
    """
    if original.shape != watermarked.shape:
        raise ValueError(f"Shape mismatch: {original.shape} vs {watermarked.shape}")

    im1 = original.astype(np.float64)
    im2 = watermarked.astype(np.float64)

    c1 = (k1 * max_val) ** 2
    c2 = (k2 * max_val) ** 2

    mu1 = gaussian_filter(im1, sigma=sigma)
    mu2 = gaussian_filter(im2, sigma=sigma)

    mu1_sq = mu1 ** 2
    mu2_sq = mu2 ** 2
    mu1_mu2 = mu1 * mu2

    sigma1_sq = gaussian_filter(im1 ** 2, sigma=sigma) - mu1_sq
    sigma2_sq = gaussian_filter(im2 ** 2, sigma=sigma) - mu2_sq
    sigma12 = gaussian_filter(im1 * im2, sigma=sigma) - mu1_mu2

    num = (2 * mu1_mu2 + c1) * (2 * sigma12 + c2)
    den = (mu1_sq + mu2_sq + c1) * (sigma1_sq + sigma2_sq + c2)

    ssim_map = num / den
    return float(np.mean(ssim_map))


def evaluate_fidelity(original: np.ndarray, watermarked: np.ndarray) -> FidelityMetrics:
    """Evaluate comprehensive fidelity metrics (MSE, PSNR, SSIM)."""
    mse = calculate_mse(original, watermarked)
    psnr = calculate_psnr(original, watermarked)
    ssim = calculate_ssim(original, watermarked)
    return FidelityMetrics(psnr=psnr, ssim=ssim, mse=mse)


def calculate_ber(reference_bits: np.ndarray | bytes, candidate_bits: np.ndarray | bytes) -> float:
    """Calculate raw Bit Error Rate (ratio of differing bits)."""
    if isinstance(reference_bits, bytes):
        ref_arr = np.unpackbits(np.frombuffer(reference_bits, dtype=np.uint8))
    else:
        ref_arr = np.asarray(reference_bits, dtype=np.uint8).flatten()

    if isinstance(candidate_bits, bytes):
        cand_arr = np.unpackbits(np.frombuffer(candidate_bits, dtype=np.uint8))
    else:
        cand_arr = np.asarray(candidate_bits, dtype=np.uint8).flatten()

    if len(ref_arr) != len(cand_arr):
        min_len = min(len(ref_arr), len(cand_arr))
        ref_arr = ref_arr[:min_len]
        cand_arr = cand_arr[:min_len]

    if len(ref_arr) == 0:
        return 0.0

    differing = np.count_nonzero(ref_arr != cand_arr)
    return float(differing / len(ref_arr))
