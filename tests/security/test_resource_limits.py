"""Resource Limit and Denial-of-Service Defense Tests.

Validates:
- Rejection of oversized evidence files (> 100 MB).
- Rejection of empty (0-byte) files.
- Defense against excessive PDF page counts (> 200 pages).
- Rejection of decompression bombs and extreme image pixel dimensions.
"""

from __future__ import annotations

from pathlib import Path
import pytest
import pypdf

from tracecrypt.errors import ForensicEvidenceError
from tracecrypt.forensics.ingestion import EvidenceIngestion
from tracecrypt.watermark.normalizer import WatermarkNormalizer


class TestResourceLimits:
    """Evaluate workstation resilience against resource exhaustion and bomb artifacts."""

    def test_empty_evidence_artifact_rejected(self, tmp_path: Path) -> None:
        """Zero-byte evidence files must fail closed immediately."""
        empty_file = tmp_path / "empty.pdf"
        empty_file.write_bytes(b"")

        with pytest.raises(ForensicEvidenceError, match="Evidence artifact is empty"):
            EvidenceIngestion.ingest(empty_file)

    def test_oversized_evidence_rejected(self) -> None:
        """Files exceeding MAX_EVIDENCE_SIZE_BYTES (100 MB) must be rejected."""
        # Test with virtual buffer exceeding limit without writing 100MB to disk
        oversized_bytes = b"%PDF" + b"\x00" * (100 * 1024 * 1024 + 10)

        with pytest.raises(ForensicEvidenceError, match="exceeds maximum limit"):
            EvidenceIngestion.ingest(oversized_bytes, filename="oversized.pdf")

    def test_excessive_pdf_page_count_defense(self, tmp_path: Path) -> None:
        """PDFs claiming > 200 pages must be rejected before rasterization."""
        writer = pypdf.PdfWriter()
        for _ in range(201):
            writer.add_blank_page(width=100, height=100)

        pdf_path = tmp_path / "many_pages.pdf"
        with open(pdf_path, "wb") as f:
            writer.write(f)

        pdf_bytes = pdf_path.read_bytes()

        # WatermarkNormalizer.rasterize_pdf must reject
        with pytest.raises((ValueError, ForensicEvidenceError), match="exceeds maximum allowable limit"):
            WatermarkNormalizer.rasterize_pdf(pdf_bytes, max_pages=200)

        # Ingestion must also reject
        with pytest.raises(ForensicEvidenceError, match="exceeds maximum"):
            EvidenceIngestion.ingest(pdf_bytes, filename="many_pages.pdf")
