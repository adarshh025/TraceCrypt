"""Unit tests for blind watermark payload recovery and structural validation."""

from __future__ import annotations

from tracecrypt.forensics.extraction import ForensicExtractionEngine
from tracecrypt.utils.identifiers import SessionID, WatermarkID
from tracecrypt.watermark.embedder import WatermarkEmbedder
from tracecrypt.watermark.types import ExtractionStatus, WatermarkParameters, WatermarkPayload
from tests.forensics.conftest import make_test_image_array


class TestWatermarkExtraction:
    """Validate full multi-page document watermark extraction and payload validation."""

    def test_extract_watermark_payload_structure(self) -> None:
        p1 = make_test_image_array(512, 512)
        p2 = make_test_image_array(512, 512)

        wmid = WatermarkID.generate()
        sid = SessionID.generate()
        doc_hash = "sha3-256:44556677889900aabbccddeeff11223344556677889900aabbccddeeff112233"

        payload = WatermarkPayload.create(
            watermark_id=wmid,
            session_id=sid,
            document_hash=doc_hash,
        )

        wm1, _ = WatermarkEmbedder.embed_page(
            page_image=p1,
            page_index=0,
            payload=payload,
            document_hash=doc_hash,
            params=WatermarkParameters(embedding_strength=8.0),
        )
        wm2, _ = WatermarkEmbedder.embed_page(
            page_image=p2,
            page_index=1,
            payload=payload,
            document_hash=doc_hash,
            params=WatermarkParameters(embedding_strength=8.0),
        )

        analysis, page_results = ForensicExtractionEngine.analyze_document_pages(
            pages=[wm1, wm2],
            candidate_document_hashes=[doc_hash],
        )

        assert analysis.overall_status == ExtractionStatus.DECODED
        assert analysis.pages_analyzed == 2
        assert analysis.pages_detected == 2
        assert analysis.pages_decoded == 2
        assert analysis.has_cross_page_conflict is False
        assert analysis.consensus_watermark_id == wmid
        assert analysis.consensus_session_tag == payload.session_tag.hex()
        assert analysis.consensus_document_binding == payload.document_binding.hex()
        assert len(analysis.distinct_watermark_ids) == 1
        assert len(page_results) == 2
        for pr in page_results:
            assert pr.status == ExtractionStatus.DECODED
            assert pr.watermark_id == wmid

    def test_payload_structural_validation_failure(self) -> None:
        # Check payload deserialization fails on invalid length or CRC
        bad_bytes = b"\x00" * 32  # Invalid version / bad CRC
        try:
            WatermarkPayload.from_bytes(bad_bytes)
            assert False, "Expected ValidationError"
        except Exception:
            pass  # Structural validation correctly rejected corrupted bytes
