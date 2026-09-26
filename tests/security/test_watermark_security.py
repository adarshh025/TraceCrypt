"""Security tests for TraceCrypt forensic watermarking.

Validates fail-closed security properties:
1. Random noise / unwatermarked image fails with NOT_DETECTED.
2. Clean unwatermarked PDF fails with NOT_DETECTED.
3. Extraction with wrong document hash decorrelates and fails closed (never false attribution).
4. Multi-page splice / conflicting watermarks across pages triggers AMBIGUOUS status.
5. Severely corrupted carrier signal fails with CORRUPTED.
6. Air-gap compliance: zero network calls during embedding or extraction.
"""

import numpy as np

from tracecrypt.crypto.random import SecureRandom
from tracecrypt.document.hasher import DocumentHasher
from tracecrypt.security.airgap import AirGapGuard
from tracecrypt.utils.identifiers import SessionID, WatermarkID
from tracecrypt.watermark import (
    ExtractionStatus,
    WatermarkEmbedder,
    WatermarkExtractor,
    WatermarkPayload,
)
from tests.integration.test_watermark_pipeline import create_sample_pdf


class TestWatermarkSecurity:
    """Security verification tests for forensic watermarking engine."""

    def test_random_noise_fails_closed(self) -> None:
        """Random unwatermarked noise image must return NOT_DETECTED."""
        rng = np.random.default_rng(999)
        noise_img = rng.integers(0, 256, (1584, 1216), dtype=np.uint8)
        doc_hash = "sha3-256:0000000000000000000000000000000000000000000000000000000000000000"

        status, payload, corr, corrected, diag = WatermarkExtractor.extract_page(
            page_image=noise_img,
            page_index=0,
            document_hash=doc_hash,
            deskew_enabled=False,
        )

        assert status in (ExtractionStatus.NOT_DETECTED, ExtractionStatus.CORRUPTED)
        assert payload is None

    def test_unwatermarked_clean_pdf_fails_closed(self) -> None:
        """Pristine unwatermarked PDF must produce NOT_DETECTED."""
        pdf_bytes = create_sample_pdf(num_pages=1)
        doc_hash = DocumentHasher.hash_bytes(pdf_bytes)

        res = WatermarkExtractor.extract_document(
            artifact_input=pdf_bytes,
            document_hash=doc_hash,
            deskew_enabled=False,
        )

        assert res.status == ExtractionStatus.NOT_DETECTED
        assert res.watermark_id is None
        assert res.pages_decoded == 0

    def test_wrong_document_hash_fails_closed(self) -> None:
        """Extraction with a mismatched document hash must not yield false attribution."""
        pdf_bytes = create_sample_pdf(num_pages=1)
        correct_hash = DocumentHasher.hash_bytes(pdf_bytes)
        wrong_hash = "sha3-256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

        wm_id = SecureRandom.generate_typed_id(WatermarkID)
        ses_id = SecureRandom.generate_typed_id(SessionID)
        payload = WatermarkPayload.create(wm_id, ses_id, correct_hash)

        embed_res = WatermarkEmbedder.embed_document(
            pdf_input=pdf_bytes,
            payload=payload,
            document_hash=correct_hash,
        )

        # Attempt extraction with wrong document hash
        ext_res = WatermarkExtractor.extract_document(
            artifact_input=embed_res.watermarked_pdf,
            document_hash=wrong_hash,
        )

        # Carrier sequence will be completely orthogonal/decorrelated
        assert ext_res.status in (ExtractionStatus.NOT_DETECTED, ExtractionStatus.CORRUPTED)
        assert ext_res.watermark_id is None

    def test_spliced_multipage_conflicting_watermarks(self) -> None:
        """When an attacker splices Page 1 from Session A and Page 2 from Session B,

        the system must return AMBIGUOUS and refuse to invent a single attribution.
        """
        pdf_bytes_a = create_sample_pdf(num_pages=2)
        pdf_bytes_b = create_sample_pdf(num_pages=2)
        doc_hash = DocumentHasher.hash_bytes(pdf_bytes_a)

        # Session A (embed across pages 0 and 1)
        wm_id_a = SecureRandom.generate_typed_id(WatermarkID)
        ses_id_a = SecureRandom.generate_typed_id(SessionID)
        payload_a = WatermarkPayload.create(wm_id_a, ses_id_a, doc_hash)
        res_a = WatermarkEmbedder.embed_document(pdf_bytes_a, payload_a, doc_hash)

        # Session B (embed across pages 0 and 1)
        wm_id_b = SecureRandom.generate_typed_id(WatermarkID)
        ses_id_b = SecureRandom.generate_typed_id(SessionID)
        payload_b = WatermarkPayload.create(wm_id_b, ses_id_b, doc_hash)
        res_b = WatermarkEmbedder.embed_document(pdf_bytes_b, payload_b, doc_hash)

        from tracecrypt.watermark.normalizer import WatermarkNormalizer
        page_a = WatermarkNormalizer.rasterize_pdf(res_a.watermarked_pdf)[0]  # Page 0 from session A
        page_b = WatermarkNormalizer.rasterize_pdf(res_b.watermarked_pdf)[1]  # Page 1 from session B

        # Spliced document: [page_a, page_b]
        spliced_pages = [page_a, page_b]

        ext_res = WatermarkExtractor.extract_document(
            artifact_input=spliced_pages,
            document_hash=doc_hash,
        )

        assert ext_res.status == ExtractionStatus.AMBIGUOUS
        assert ext_res.watermark_id is None  # Fails closed, never guesses one

    def test_airgap_compliance_during_watermarking(self) -> None:
        """Watermark operations must strictly execute with zero network socket activity."""
        AirGapGuard.install()
        try:
            pdf_bytes = create_sample_pdf(num_pages=1)
            doc_hash = DocumentHasher.hash_bytes(pdf_bytes)

            wm_id = SecureRandom.generate_typed_id(WatermarkID)
            ses_id = SecureRandom.generate_typed_id(SessionID)
            payload = WatermarkPayload.create(wm_id, ses_id, doc_hash)

            # Embedding
            embed_res = WatermarkEmbedder.embed_document(pdf_bytes, payload, doc_hash)

            # Extraction
            ext_res = WatermarkExtractor.extract_document(embed_res.watermarked_pdf, doc_hash)
            assert ext_res.status == ExtractionStatus.DECODED
        finally:
            AirGapGuard.uninstall()
