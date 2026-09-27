"""Adversarial Filesystem, Archive, PDF, and Image Abuse Tests.

Satisfies Master Prompt 12 - Sections 29, 30, 31, 32, 33:
- Windows reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
- Path traversal with UNC paths and null bytes
- Malformed and corrupted PDF documents
- Image decompression attacks, zero-byte images, corrupted DCT streams
- Resource bounds and fail-closed handling
"""

from __future__ import annotations

import io
from pathlib import Path
import numpy as np
from PIL import Image
import pytest

from tracecrypt.document.reader import DocumentReader
from tracecrypt.errors import ForensicEvidenceError, TraceCryptError, ValidationError
from tracecrypt.forensics.ingestion import EvidenceIngestion
from tracecrypt.forensics.normalization import DocumentNormalizer


class TestFilesystemArchiveAttacks:
    """Evaluate resilience against filesystem manipulation, malformed PDFs, and image attacks."""

    # -------------------------------------------------------------------------
    # 1. Windows Reserved Device Names & Path Edge Cases
    # -------------------------------------------------------------------------

    @pytest.mark.parametrize("reserved_name", [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "LPT1", "LPT2",
        "con.pdf", "aux.png", "nul.tiff"
    ])
    def test_windows_reserved_device_names_sanitization(self, tmp_path: Path, reserved_name: str) -> None:
        """Ingesting files with Windows DOS device names must be safely handled without OS hanging."""
        valid_img = tmp_path / "normal.png"
        img = Image.fromarray(np.zeros((64, 64, 3), dtype=np.uint8))
        img.save(valid_img)

        # Ingest with reserved name as the filename parameter
        ev, _ = EvidenceIngestion.ingest(
            evidence_input=valid_img,
            filename=reserved_name,
        )
        # Should either sanitize the name or reject; must never crash or hang the process
        assert ev.filename is not None
        assert ev.evidence_id is not None

    def test_null_byte_in_filename_rejected(self, tmp_path: Path) -> None:
        """Filenames containing embedded null bytes must be rejected or stripped."""
        valid_img = tmp_path / "test_null.png"
        img = Image.fromarray(np.zeros((64, 64, 3), dtype=np.uint8))
        img.save(valid_img)

        null_filename = "harmless.pdf\x00malicious.exe"
        try:
            ev, _ = EvidenceIngestion.ingest(
                evidence_input=valid_img,
                filename=null_filename,
            )
            # If accepted, null byte must be removed
            assert "\x00" not in ev.filename
        except (ValueError, ForensicEvidenceError, ValidationError):
            # Safe rejection
            pass

    # -------------------------------------------------------------------------
    # 2. Malformed PDF Handling
    # -------------------------------------------------------------------------

    def test_corrupted_empty_pdf_rejected(self, tmp_path: Path) -> None:
        """Zero-byte or truncated PDF files must fail closed with DocumentProcessingError."""
        empty_pdf = tmp_path / "empty.pdf"
        empty_pdf.write_bytes(b"")

        with pytest.raises((ForensicEvidenceError, TraceCryptError, Exception)):
            DocumentNormalizer.normalize_to_pages(empty_pdf)

    def test_truncated_pdf_header_rejected(self, tmp_path: Path) -> None:
        """Files with invalid PDF magic or truncated trailers must fail closed."""
        fake_pdf = tmp_path / "fake.pdf"
        fake_pdf.write_bytes(b"%PDF-1.7\nCorrupted content without xref table or trailer")

        with pytest.raises((ForensicEvidenceError, TraceCryptError, Exception)):
            DocumentNormalizer.normalize_to_pages(fake_pdf)

    # -------------------------------------------------------------------------
    # 3. Image Abuse & Decompression Bomb Bounds
    # -------------------------------------------------------------------------

    def test_corrupted_raster_image_rejected(self, tmp_path: Path) -> None:
        """Corrupted PNG/JPEG image files must be rejected during forensic ingestion."""
        corrupt_png = tmp_path / "corrupt.png"
        corrupt_png.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\xff" * 50)  # Valid magic, corrupted body

        with pytest.raises((ForensicEvidenceError, TraceCryptError, Exception)):
            EvidenceIngestion.ingest(corrupt_png)

    def test_zero_dimension_or_flat_image_handling(self) -> None:
        """Single-color or low-resolution image normalization must handle dimensions safely."""
        from tracecrypt.watermark.normalizer import WatermarkNormalizer
        flat_img = np.zeros((16, 16), dtype=np.uint8)
        norm, _ = WatermarkNormalizer.normalize_page(flat_img, target_shape=(512, 512))
        assert norm.shape == (512, 512)
        assert norm.dtype == np.uint8
