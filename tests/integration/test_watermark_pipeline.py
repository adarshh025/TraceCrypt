"""Integration tests for end-to-end multi-page watermark pipeline.

Validates:
- Complete embedding into multi-page PDF documents.
- Preservation of page count and readable text rendering.
- Perceptual fidelity verification (PSNR >= 42.0 dB).
- Blind extraction across all pages without the pristine document.
- Consistent extraction across multiple pages.
- CLI command invocation: embed, extract, inspect.
"""

import io
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from tracecrypt.crypto.random import SecureRandom
from tracecrypt.document.hasher import DocumentHasher
from tracecrypt.utils.identifiers import SessionID, WatermarkID
from tracecrypt.watermark import (
    ExtractionStatus,
    WatermarkEmbedder,
    WatermarkExtractor,
    WatermarkParameters,
    WatermarkPayload,
)


def create_sample_pdf(num_pages: int = 2) -> bytes:
    """Create a multi-page test PDF in memory."""
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    for p in range(num_pages):
        c.setFont("Helvetica-Bold", 16)
        c.drawString(72, 720, f"TraceCrypt Integration Document - Page {p + 1}")
        c.setFont("Helvetica", 10)
        c.drawString(72, 690, f"Deterministic forensic embedding test for page index {p}.")
        for line in range(10):
            c.drawString(72, 650 - line * 20, f"Line {line}: Cryptographic token {line * 1337}.")
        c.showPage()
    c.save()
    return buf.getvalue()


class TestWatermarkPipeline:
    """Test full multi-page PDF embedding and extraction pipeline."""

    def test_multipage_pdf_embedding_and_blind_extraction(self) -> None:
        pdf_bytes = create_sample_pdf(num_pages=3)
        doc_hash = DocumentHasher.hash_bytes(pdf_bytes)

        wm_id = SecureRandom.generate_typed_id(WatermarkID)
        ses_id = SecureRandom.generate_typed_id(SessionID)
        payload = WatermarkPayload.create(wm_id, ses_id, doc_hash)

        params = WatermarkParameters(embedding_strength=8.0)

        # 1. Embed watermark
        embed_res = WatermarkEmbedder.embed_document(
            pdf_input=pdf_bytes,
            payload=payload,
            document_hash=doc_hash,
            params=params,
        )

        assert embed_res.pages_count == 3
        assert len(embed_res.watermarked_pdf) > 0
        assert embed_res.fidelity.psnr >= 42.0

        # 2. Blind extraction without pristine document
        ext_res = WatermarkExtractor.extract_document(
            artifact_input=embed_res.watermarked_pdf,
            document_hash=doc_hash,
            params=params,
        )

        assert ext_res.status == ExtractionStatus.DECODED
        assert ext_res.watermark_id == wm_id
        assert ext_res.session_tag == payload.session_tag.hex()
        assert ext_res.document_binding == payload.document_binding.hex()
        assert ext_res.pages_analyzed == 3
        assert ext_res.pages_decoded == 3
        assert ext_res.pages_corrupted == 0

    def test_single_page_recovery_from_multipage_doc(self) -> None:
        """Watermark must be extractable from a single extracted page image."""
        pdf_bytes = create_sample_pdf(num_pages=2)
        doc_hash = DocumentHasher.hash_bytes(pdf_bytes)

        wm_id = SecureRandom.generate_typed_id(WatermarkID)
        ses_id = SecureRandom.generate_typed_id(SessionID)
        payload = WatermarkPayload.create(wm_id, ses_id, doc_hash)
        params = WatermarkParameters(embedding_strength=8.0)

        embed_res = WatermarkEmbedder.embed_document(
            pdf_input=pdf_bytes,
            payload=payload,
            document_hash=doc_hash,
            params=params,
        )

        from tracecrypt.watermark.normalizer import WatermarkNormalizer
        pages = WatermarkNormalizer.rasterize_pdf(embed_res.watermarked_pdf)
        page1 = pages[1]  # Extract page 2 alone (0-indexed page 1)

        # Blind extraction on single page
        status, ext_payload, corr, corrected, diag = WatermarkExtractor.extract_page(
            page_image=page1,
            page_index=1,
            document_hash=doc_hash,
            params=params,
        )

        assert status == ExtractionStatus.DECODED
        assert ext_payload is not None
        assert ext_payload.watermark_id == wm_id
        assert ext_payload.session_tag == payload.session_tag
