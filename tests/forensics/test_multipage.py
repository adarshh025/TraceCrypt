"""Unit tests for multi-page forensic analysis, corroboration, and ambiguity detection."""

from __future__ import annotations

from tracecrypt.forensics.extraction import ForensicExtractionEngine
from tracecrypt.forensics.verdict import VerdictEvaluator
from tracecrypt.utils.identifiers import SessionID, WatermarkID
from tracecrypt.watermark.embedder import WatermarkEmbedder
from tracecrypt.watermark.types import ExtractionStatus, WatermarkParameters, WatermarkPayload
from tests.forensics.conftest import make_test_image_array


class TestMultiPageForensics:
    """Validate cross-page consistency, corroboration, and splice detection."""

    def test_consistent_multipage_corroboration(self) -> None:
        p1 = make_test_image_array(512, 512)
        p2 = make_test_image_array(512, 512)
        p3 = make_test_image_array(512, 512)

        wmid = WatermarkID.generate()
        sid = SessionID.generate()
        doc_hash = "sha3-256:1111222233334444555566667777888811112222333344445555666677778888"

        payload = WatermarkPayload.create(
            watermark_id=wmid,
            session_id=sid,
            document_hash=doc_hash,
        )

        wm_pages = []
        for idx, page in enumerate([p1, p2, p3]):
            wm, _ = WatermarkEmbedder.embed_page(
                page_image=page,
                page_index=idx,
                payload=payload,
                document_hash=doc_hash,
                params=WatermarkParameters(embedding_strength=8.0),
            )
            wm_pages.append(wm)

        analysis, page_results = ForensicExtractionEngine.analyze_document_pages(
            pages=wm_pages,
            candidate_document_hashes=[doc_hash],
        )

        assert analysis.overall_status == ExtractionStatus.DECODED
        assert analysis.pages_analyzed == 3
        assert analysis.pages_detected == 3
        assert analysis.pages_decoded == 3
        assert analysis.has_cross_page_conflict is False
        assert len(analysis.distinct_watermark_ids) == 1
        assert analysis.consensus_watermark_id == wmid

    def test_conflicting_watermarks_produce_ambiguity(self) -> None:
        """Attack I: If pages recover conflicting WatermarkIDs, must be flagged AMBIGUOUS."""
        p1 = make_test_image_array(512, 512)
        p2 = make_test_image_array(512, 512)

        wmid_alice = WatermarkID.generate()
        sid_alice = SessionID.generate()

        wmid_bob = WatermarkID.generate()
        sid_bob = SessionID.generate()

        doc_hash = "sha3-256:1111222233334444555566667777888811112222333344445555666677778888"

        payload_alice = WatermarkPayload.create(
            watermark_id=wmid_alice,
            session_id=sid_alice,
            document_hash=doc_hash,
        )
        payload_bob = WatermarkPayload.create(
            watermark_id=wmid_bob,
            session_id=sid_bob,
            document_hash=doc_hash,
        )

        # Page 0 has Alice's watermark
        wm1, _ = WatermarkEmbedder.embed_page(
            page_image=p1,
            page_index=0,
            payload=payload_alice,
            document_hash=doc_hash,
            params=WatermarkParameters(embedding_strength=8.0),
        )
        # Page 1 has Bob's watermark (spliced document leak)
        wm2, _ = WatermarkEmbedder.embed_page(
            page_image=p2,
            page_index=1,
            payload=payload_bob,
            document_hash=doc_hash,
            params=WatermarkParameters(embedding_strength=8.0),
        )

        analysis, page_results = ForensicExtractionEngine.analyze_document_pages(
            pages=[wm1, wm2],
            candidate_document_hashes=[doc_hash],
        )

        assert analysis.has_cross_page_conflict is True
        assert analysis.overall_status == ExtractionStatus.AMBIGUOUS
        assert len(analysis.distinct_watermark_ids) == 2
        assert str(wmid_alice) in analysis.distinct_watermark_ids
        assert str(wmid_bob) in analysis.distinct_watermark_ids
        assert analysis.consensus_watermark_id is None

        # Verify that verdict evaluator enforces AMBIGUOUS precedence
        verdict, rank, trace = VerdictEvaluator.evaluate(
            analysis=analysis,
            ledger_details=None,
            identity_details=None,
            binding_details=None,
        )
        from tracecrypt.forensics.types import ForensicVerdict

        assert verdict == ForensicVerdict.AMBIGUOUS
        assert any("AMBIGUOUS" in msg for msg in trace)
