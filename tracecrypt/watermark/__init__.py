"""Forensic watermarking subsystem for TraceCrypt.

Components:
- 2D Discrete Wavelet Transform (Haar) & Block 2D Discrete Cosine Transform (DCT)
- Mid-frequency pseudo-random spread-spectrum modulation
- Reed-Solomon RS(32, 16) Forward Error Correction
- Blind frequency-domain extraction algorithm
- Multi-page consistency analyzer
- Image/PDF forensic normalization pipeline
"""

from __future__ import annotations

from tracecrypt.watermark.benchmark import WatermarkBenchmark
from tracecrypt.watermark.ecc import (
    GaloisField256,
    ReedSolomon32_16,
    ReedSolomonError,
    WatermarkPayloadEncoder,
)
from tracecrypt.watermark.embedder import WatermarkEmbedder, WatermarkEmbeddingResult
from tracecrypt.watermark.extractor import WatermarkExtractor
from tracecrypt.watermark.fidelity import (
    calculate_ber,
    calculate_mse,
    calculate_psnr,
    calculate_ssim,
    evaluate_fidelity,
)
from tracecrypt.watermark.normalizer import WatermarkNormalizer
from tracecrypt.watermark.spread_spectrum import SpreadSpectrumEngine
from tracecrypt.watermark.transform import (
    dct2_block,
    dct2_image_blocks,
    get_mid_frequency_indices,
    get_zigzag_indices,
    haar_dwt2,
    haar_idwt2,
    idct2_block,
    idct2_image_blocks,
)
from tracecrypt.watermark.types import (
    ExtractionStatus,
    FidelityMetrics,
    WatermarkExtractionResult,
    WatermarkParameters,
    WatermarkPayload,
)

__all__ = [
    "ExtractionStatus",
    "FidelityMetrics",
    "GaloisField256",
    "ReedSolomon32_16",
    "ReedSolomonError",
    "SpreadSpectrumEngine",
    "WatermarkBenchmark",
    "WatermarkEmbedder",
    "WatermarkEmbeddingResult",
    "WatermarkExtractionResult",
    "WatermarkExtractor",
    "WatermarkNormalizer",
    "WatermarkParameters",
    "WatermarkPayload",
    "WatermarkPayloadEncoder",
    "calculate_ber",
    "calculate_mse",
    "calculate_psnr",
    "calculate_ssim",
    "dct2_block",
    "dct2_image_blocks",
    "evaluate_fidelity",
    "get_mid_frequency_indices",
    "get_zigzag_indices",
    "haar_dwt2",
    "haar_idwt2",
    "idct2_block",
    "idct2_image_blocks",
]
