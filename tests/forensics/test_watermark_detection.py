"""Unit tests for blind watermark detection and frequency-domain correlation."""

from __future__ import annotations

from tracecrypt.forensics.extraction import ForensicExtractionEngine
from tracecrypt.utils.identifiers import SessionID, WatermarkID
from tracecrypt.watermark.embedder import WatermarkEmbedder
from tracecrypt.watermark.types import ExtractionStatus, WatermarkParameters, WatermarkPayload
from tests.forensics.conftest import make_test_image_array


class TestWatermarkDetection:
    """Validate 2D Haar DWT + DCT mid-frequency blind watermark detection."""

    def test_detection_on_watermarked_image(self) -> None:
        raw_img = make_test_image_array(512, 512)
        wmid = WatermarkID.generate()
        sid = SessionID.generate()
        doc_hash = "sha3-256:11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"

        payload = WatermarkPayload.create(
            watermark_id=wmid,
            session_id=sid,
            document_hash=doc_hash,
        )

        wm_img, fidelity = WatermarkEmbedder.embed_page(
            page_image=raw_img,
            page_index=0,
            payload=payload,
            document_hash=doc_hash,
            params=WatermarkParameters(embedding_strength=8.0),
        )

        assert fidelity.psnr >= 40.0

        # Blind detection using candidate document hash
        page_res = ForensicExtractionEngine.extract_single_page(
            page_image=wm_img,
            page_index=0,
            candidate_document_hashes=[doc_hash],
        )

        assert page_res.detected is True
        assert page_res.decoded is True
        assert page_res.status == ExtractionStatus.DECODED
        assert page_res.watermark_id == str(wmid)
        assert page_res.correlation_score > 0.0

    def test_detection_on_unwatermarked_image_fails_safely(self) -> None:
        raw_img = make_test_image_array(512, 512)
        doc_hash = "sha3-256:11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"

        page_res = ForensicExtractionEngine.extract_single_page(
            page_image=raw_img,
            page_index=0,
            candidate_document_hashes=[doc_hash],
        )

        assert page_res.decoded is False
        assert page_res.watermark_id is None
        assert page_res.session_tag is None
        assert page_res.status in (
            ExtractionStatus.NOT_DETECTED,
            ExtractionStatus.CORRUPTED,
        )

    def test_detection_with_multiple_candidate_hashes(self) -> None:
        raw_img = make_test_image_array(512, 512)
        wmid = WatermarkID.generate()
        sid = SessionID.generate()
        correct_hash = "sha3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        decoy_hash = "sha3-256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

        payload = WatermarkPayload.create(
            watermark_id=wmid,
            session_id=sid,
            document_hash=correct_hash,
        )

        wm_img, _ = WatermarkEmbedder.embed_page(
            page_image=raw_img,
            page_index=0,
            payload=payload,
            document_hash=correct_hash,
            params=WatermarkParameters(embedding_strength=8.0),
        )

        page_res = ForensicExtractionEngine.extract_single_page(
            page_image=wm_img,
            page_index=0,
            candidate_document_hashes=[decoy_hash, correct_hash],
        )

        assert page_res.detected is True
        assert page_res.decoded is True
        assert page_res.status == ExtractionStatus.DECODED
        assert page_res.watermark_id == str(wmid)
