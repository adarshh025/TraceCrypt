"""Image and PDF normalization pipeline for forensic watermark extraction.

Implements:
- PDF page rasterization via pypdfium2 at controlled DPI scale
- High-fidelity PDF document reconstruction from processed image pages
- Luminance/grayscale conversion
- Deskewing and rotation estimation
- Canvas scaling and aspect ratio alignment
- Contrast normalization
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import cv2
import numpy as np
from PIL import Image
import pypdfium2 as pdfium
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas


class WatermarkNormalizer:
    """Forensic normalization pipeline preparing leaked artifacts for blind extraction."""

    @classmethod
    def rasterize_pdf(cls, pdf_input: bytes | Path | str, scale: float = 2.0) -> List[np.ndarray]:
        """Rasterize all pages of a PDF into 2D grayscale NumPy arrays.

        Args:
            pdf_input: PDF bytes or file path.
            scale: Rendering scale factor (2.0 gives ~144-150 DPI).

        Returns:
            List of 2D uint8 NumPy arrays, one per page.
        """
        if isinstance(pdf_input, (str, Path)):
            pdf_bytes = Path(pdf_input).read_bytes()
        else:
            pdf_bytes = pdf_input

        doc = pdfium.PdfDocument(pdf_bytes)
        pages: List[np.ndarray] = []

        for page in doc:
            pil_img = page.render(scale=scale).to_pil().convert("L")
            arr = np.array(pil_img, dtype=np.uint8)
            pages.append(arr)

        return pages

    @classmethod
    def pages_to_pdf(cls, pages: List[np.ndarray], dpi: float = 144.0) -> bytes:
        """Reconstruct a multi-page PDF document losslessly from 2D NumPy image arrays."""
        if not pages:
            raise ValueError("pages_to_pdf requires at least one page")

        out_buf = io.BytesIO()
        first_h, first_w = pages[0].shape[:2]
        c = canvas.Canvas(out_buf, pagesize=(first_w * 72.0 / dpi, first_h * 72.0 / dpi))

        for p in pages:
            h_px, w_px = p.shape[:2]
            w_pt = w_px * 72.0 / dpi
            h_pt = h_px * 72.0 / dpi
            c.setPageSize((w_pt, h_pt))
            pil_im = Image.fromarray(np.clip(p, 0, 255).astype(np.uint8))
            c.drawImage(ImageReader(pil_im), 0, 0, width=w_pt, height=h_pt)
            c.showPage()

        c.save()
        return out_buf.getvalue()

    @classmethod
    def to_grayscale(cls, image: np.ndarray) -> np.ndarray:
        """Convert arbitrary image (RGB, BGR, RGBA) to single-channel 2D uint8."""
        if image.ndim == 2:
            return image.astype(np.uint8)
        elif image.ndim == 3:
            if image.shape[2] == 4:
                # RGBA -> Gray
                return cv2.cvtColor(image, cv2.COLOR_RGBA2GRAY)
            elif image.shape[2] == 3:
                # RGB -> Gray
                return cv2.cvtColor(image, cv2.COLOR_RGB2GRAY)
        raise ValueError(f"Unsupported image shape for grayscale conversion: {image.shape}")

    @classmethod
    def estimate_skew_angle(cls, gray_image: np.ndarray, max_angle: float = 10.0) -> float:
        """Estimate rotation/skew angle in degrees using image moments or Radon/Hough lines.

        Returns:
            Angle in degrees by which the image is tilted from horizontal.
        """
        # Threshold to isolate text lines
        _, thresh = cv2.threshold(gray_image, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)

        # Detect horizontal lines
        kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (30, 1))
        dilated = cv2.dilate(thresh, kernel, iterations=1)

        # Detect lines using Probabilistic Hough Transform
        lines = cv2.HoughLinesP(dilated, 1, np.pi / 180, threshold=100, minLineLength=100, maxLineGap=20)
        if lines is None or len(lines) == 0:
            return 0.0

        angles: List[float] = []
        for line in lines:
            coords = line.flatten()
            if len(coords) < 4:
                continue
            x1, y1, x2, y2 = coords[0], coords[1], coords[2], coords[3]
            dx = float(x2 - x1)
            dy = float(y2 - y1)
            if dx == 0:
                continue
            ang = np.degrees(np.arctan2(dy, dx))
            # Only consider small skew angles within [-max_angle, max_angle]
            if abs(ang) <= max_angle:
                angles.append(ang)

        if not angles:
            return 0.0

        median_angle = float(np.median(angles))
        return median_angle

    @classmethod
    def deskew(cls, image: np.ndarray, angle: float) -> np.ndarray:
        """Rotate image by negative angle to restore upright horizontal alignment."""
        if abs(angle) < 0.05:
            return image

        h, w = image.shape[:2]
        center = (w / 2.0, h / 2.0)
        m = cv2.getRotationMatrix2D(center, angle, 1.0)
        deskewed = cv2.warpAffine(
            image,
            m,
            (w, h),
            flags=cv2.INTER_CUBIC,
            borderMode=cv2.BORDER_REPLICATE,
        )
        return deskewed

    @classmethod
    def normalize_contrast(cls, gray_image: np.ndarray) -> np.ndarray:
        """Normalize dynamic range using min-max stretching to [0, 255]."""
        min_val = float(np.min(gray_image))
        max_val = float(np.max(gray_image))

        if max_val - min_val < 1e-5:
            return gray_image

        stretched = (gray_image.astype(np.float64) - min_val) / (max_val - min_val) * 255.0
        return np.clip(stretched, 0, 255).astype(np.uint8)

    @classmethod
    def align_dimensions(cls, image: np.ndarray, multiple: int = 16) -> np.ndarray:
        """Ensure height and width are exact multiples of specified factor (e.g. 16 for DWT+DCT)."""
        h, w = image.shape[:2]
        target_h = (h // multiple) * multiple
        target_w = (w // multiple) * multiple

        if h == target_h and w == target_w:
            return image

        # Crop or resize cleanly to aligned dimensions
        return image[:target_h, :target_w]

    @classmethod
    def normalize_page(
        cls,
        image: np.ndarray,
        target_shape: Optional[Tuple[int, int]] = None,
        deskew_enabled: bool = True,
        contrast_norm: bool = False,
    ) -> Tuple[np.ndarray, Dict[str, Any]]:
        """Execute full forensic normalization pipeline on a single image page.

        Returns:
            Tuple of (normalized_2d_uint8_array, metadata_dict).
        """
        metadata: Dict[str, Any] = {"original_shape": image.shape}

        # 1. Grayscale
        gray = cls.to_grayscale(image)

        # 2. Deskew
        skew_angle = 0.0
        if deskew_enabled:
            skew_angle = cls.estimate_skew_angle(gray)
            if abs(skew_angle) >= 0.1:
                gray = cls.deskew(gray, skew_angle)
        metadata["detected_skew_angle"] = skew_angle

        # 3. Target scaling
        if target_shape is not None:
            if gray.shape != target_shape:
                gray = cv2.resize(gray, (target_shape[1], target_shape[0]), interpolation=cv2.INTER_AREA)

        # 4. Dimension alignment (multiple of 16 for DWT & 8x8 DCT)
        aligned = cls.align_dimensions(gray, multiple=16)

        # 5. Contrast normalization (optional)
        if contrast_norm:
            normalized = cls.normalize_contrast(aligned)
        else:
            normalized = aligned

        metadata["final_shape"] = normalized.shape
        return normalized, metadata
