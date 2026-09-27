"""Deterministic forensic normalization pipeline for leaked documents and raster images.

Ensures that pages are prepared for blind frequency-domain extraction without
aggressive destructive filtering or thresholding that would distort embedded signals.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
import cv2
import numpy as np

from tracecrypt.watermark.normalizer import WatermarkNormalizer


class DocumentNormalizer:
    """Forensic normalization engine operating on in-memory page representations."""

    @classmethod
    def normalize_page(
        cls,
        page_image: np.ndarray,
        deskew_enabled: bool = True,
        target_shape: Optional[Tuple[int, int]] = None,
    ) -> Tuple[np.ndarray, Dict[str, Any]]:
        """Normalize a single page for blind DWT-DCT extraction.

        Pipeline:
        1. Grayscale luminance conversion (preserving mid-frequency energy).
        2. Orientation / small deskew alignment (if enabled).
        3. Dimension alignment to multiple of 16 for 2-level DWT and 8x8 DCT blocks.
        4. Telemetry logging for the forensic audit trail.

        Returns:
            Tuple of (normalized uint8 2D array, normalization telemetry dict).
        """
        telemetry: Dict[str, Any] = {
            "initial_shape": list(page_image.shape),
            "initial_dtype": str(page_image.dtype),
        }

        # 1. Grayscale conversion
        gray = WatermarkNormalizer.to_grayscale(page_image)

        # 2. Deskewing (if enabled)
        skew_angle = 0.0
        if deskew_enabled:
            skew_angle = WatermarkNormalizer.estimate_skew_angle(gray)
            if abs(skew_angle) >= 0.1:
                gray = WatermarkNormalizer.deskew(gray, skew_angle)
        telemetry["detected_skew_degrees"] = skew_angle

        # 3. Target shape scaling if explicitly requested
        if target_shape is not None:
            if gray.shape != target_shape:
                gray = cv2.resize(
                    gray, (target_shape[1], target_shape[0]), interpolation=cv2.INTER_AREA
                )
                telemetry["rescaled_to"] = list(target_shape)

        # 4. Dimension alignment (multiple of 16)
        aligned = WatermarkNormalizer.align_dimensions(gray, multiple=16)
        telemetry["normalized_shape"] = list(aligned.shape)

        return aligned, telemetry

    @classmethod
    def normalize_all_pages(
        cls,
        pages: List[np.ndarray],
        deskew_enabled: bool = True,
    ) -> Tuple[List[np.ndarray], List[Dict[str, Any]]]:
        """Normalize all pages of an ingested document."""
        normalized_pages: List[np.ndarray] = []
        all_telemetry: List[Dict[str, Any]] = []

        for p in pages:
            norm_p, tel = cls.normalize_page(p, deskew_enabled=deskew_enabled)
            normalized_pages.append(norm_p)
            all_telemetry.append(tel)

        return normalized_pages, all_telemetry
