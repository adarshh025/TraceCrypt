"""Unit tests for Forensic Evidence Ingestion layer."""

from __future__ import annotations

from pathlib import Path
from PIL import Image
import pytest

from tracecrypt.crypto.hashing import HashAlgorithm, Hasher
from tracecrypt.errors import ForensicEvidenceError
from tracecrypt.forensics.ingestion import EvidenceIngestion
from tests.forensics.conftest import make_test_pdf_bytes


class TestEvidenceIngestion:
    """Validate immutable, read-only evidence ingestion and SHA3-256 fingerprinting."""

    def test_ingest_pdf(self, tmp_path: Path) -> None:
        pdf_data = make_test_pdf_bytes(num_pages=3)
        pdf_path = tmp_path / "test_doc.pdf"
        pdf_path.write_bytes(pdf_data)

        orig_stat = pdf_path.stat()
        evidence, pages = EvidenceIngestion.ingest(pdf_path)

        assert evidence.filename == "test_doc.pdf"
        assert evidence.mime_type == "application/pdf"
        assert evidence.page_count == 3
        assert len(pages) == 3
        assert evidence.size_bytes == len(pdf_data)

        # Verify SHA3-256
        expected_hash = Hasher.digest_bytes(pdf_data, HashAlgorithm.SHA3_256.value).formatted
        assert evidence.sha3_256 == expected_hash

        # Verify read-only: file was not modified
        new_stat = pdf_path.stat()
        assert new_stat.st_mtime == orig_stat.st_mtime
        assert pdf_path.read_bytes() == pdf_data

    def test_ingest_png_image(self, tmp_path: Path) -> None:
        img = Image.new("L", (256, 256), color=128)
        img_path = tmp_path / "evidence_scan.png"
        img.save(img_path, format="PNG")

        evidence, pages = EvidenceIngestion.ingest(img_path)
        assert evidence.mime_type == "image/png"
        assert evidence.page_count == 1
        assert len(pages) == 1
        assert pages[0].shape == (256, 256)

    def test_ingest_jpeg_image(self, tmp_path: Path) -> None:
        img = Image.new("RGB", (320, 240), color=(100, 150, 200))
        img_path = tmp_path / "photo.jpg"
        img.save(img_path, format="JPEG")

        evidence, pages = EvidenceIngestion.ingest(img_path)
        assert evidence.mime_type == "image/jpeg"
        assert evidence.page_count == 1
        # Should be converted to 2D grayscale
        assert pages[0].ndim == 2

    def test_ingest_from_bytes(self) -> None:
        pdf_data = make_test_pdf_bytes(num_pages=1)
        evidence, pages = EvidenceIngestion.ingest(pdf_data, filename="in_memory.pdf")
        assert evidence.page_count == 1
        assert len(pages) == 1
        assert evidence.mime_type == "application/pdf"

    def test_ingest_missing_file_raises(self, tmp_path: Path) -> None:
        missing = tmp_path / "non_existent.pdf"
        with pytest.raises(FileNotFoundError):
            EvidenceIngestion.ingest(missing)

    def test_ingest_corrupted_file_raises(self, tmp_path: Path) -> None:
        corrupted = tmp_path / "bad.pdf"
        corrupted.write_bytes(b"NOT A VALID PDF FILE AT ALL")
        with pytest.raises(ForensicEvidenceError):
            EvidenceIngestion.ingest(corrupted)

    def test_ingest_unsupported_format_raises(self, tmp_path: Path) -> None:
        txt_file = tmp_path / "test.txt"
        txt_file.write_text("Hello world plain text")
        with pytest.raises(ForensicEvidenceError):
            EvidenceIngestion.ingest(txt_file)

    def test_ingest_empty_file_raises(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty.png"
        empty.write_bytes(b"")
        with pytest.raises(ForensicEvidenceError):
            EvidenceIngestion.ingest(empty)
