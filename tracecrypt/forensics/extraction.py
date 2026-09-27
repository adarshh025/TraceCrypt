"""Forensic Blind Watermark Extraction and Multi-Page Analysis Engine.

Implements blind extraction without requiring access to the original unwatermarked document:
1. 2D Haar DWT + Block 2D DCT subband analysis.
2. Blind spread-spectrum correlation and carrier synchronization.
3. Reed-Solomon RS(32, 16) error correction & syndrome calculation.
4. Payload structural integrity validation (CRC-16-CCITT, version, byte length).
5. Multi-page consistency analysis: detects multi-recipient splicing / ambiguity.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple
import numpy as np

from tracecrypt.errors import ValidationError
from tracecrypt.forensics.types import PageForensicResult, WatermarkForensicAnalysis
from tracecrypt.watermark.ecc import ReedSolomonError, WatermarkPayloadEncoder
from tracecrypt.watermark.embedder import WatermarkEmbedder
from tracecrypt.watermark.normalizer import WatermarkNormalizer
from tracecrypt.watermark.spread_spectrum import SpreadSpectrumEngine
from tracecrypt.watermark.transform import dct2_image_blocks, haar_dwt2
from tracecrypt.watermark.types import (
    ExtractionStatus,
    WatermarkParameters,
    WatermarkPayload,
)


class ForensicExtractionEngine:
    """Production forensic watermark extractor analyzing normalized image pages."""

    CORRELATION_NOISE_THRESHOLD: float = 1.0  # Statistical floor for signal presence

    @classmethod
    def _extract_page_with_hash(
        cls,
        norm_img: np.ndarray,
        page_index: int,
        document_hash: str,
        params: WatermarkParameters,
    ) -> Tuple[ExtractionStatus, Optional[WatermarkPayload], float, int, Dict[str, Any]]:
        """Attempt watermark extraction using a specific candidate document hash carrier."""
        diagnostics: Dict[str, Any] = {
            "page_index": page_index,
            "document_hash": document_hash,
        }
        img_float = norm_img.astype(np.float64)

        # 1. 2D Haar DWT
        _, lh, hl, _ = haar_dwt2(img_float)

        # 2. Block DCT on HL and LH subbands
        dct_hl = dct2_image_blocks(hl, block_size=params.block_size)
        dct_lh = dct2_image_blocks(lh, block_size=params.block_size)

        # 3. Mid-frequency site map
        h_sb, w_sb = hl.shape
        site_map = WatermarkEmbedder._build_site_map(h_sb, w_sb, block_size=params.block_size)

        # 4. Reconstruct page carrier sequence
        carrier_seed = WatermarkEmbedder.derive_page_seed(document_hash, page_index)
        perm, signs = SpreadSpectrumEngine.generate_carrier_sequence(carrier_seed, len(site_map))

        # 5. Spread-spectrum correlation
        ext_bits, mean_corr, _ = SpreadSpectrumEngine.extract_bits(
            dct_subbands={"HL": dct_hl, "LH": dct_lh},
            site_map=site_map,
            permutation=perm,
            signs=signs,
            num_bits=512,
        )
        diagnostics["mean_correlation"] = mean_corr

        if mean_corr < cls.CORRELATION_NOISE_THRESHOLD:
            return ExtractionStatus.NOT_DETECTED, None, mean_corr, 0, diagnostics

        # 6. Reed-Solomon RS(32, 16) error correction
        ext_bytes = np.packbits(ext_bits).tobytes()
        encoder = WatermarkPayloadEncoder()

        try:
            dec_payload_bytes, corrected_symbols = encoder.decode_payload(ext_bytes)
            diagnostics["corrected_symbols"] = corrected_symbols
        except ReedSolomonError as e:
            diagnostics["rs_error"] = str(e)
            return ExtractionStatus.CORRUPTED, None, mean_corr, 0, diagnostics

        # 7. Checksum and structural payload validation
        try:
            payload = WatermarkPayload.from_bytes(dec_payload_bytes)
            return ExtractionStatus.DECODED, payload, mean_corr, corrected_symbols, diagnostics
        except ValidationError as e:
            diagnostics["payload_error"] = str(e)
            return ExtractionStatus.INVALID, None, mean_corr, corrected_symbols, diagnostics

    @classmethod
    def extract_single_page(
        cls,
        page_image: np.ndarray,
        page_index: int,
        candidate_document_hashes: Sequence[str],
        params: Optional[WatermarkParameters] = None,
        deskew_enabled: bool = True,
    ) -> PageForensicResult:
        """Extract watermark from a single page by testing candidate carriers and orientations."""
        p = params or WatermarkParameters()
        page_number = page_index + 1

        # Angles to test for synchronization
        angles = [0.0]
        if deskew_enabled:
            detected_angle = WatermarkNormalizer.estimate_skew_angle(
                WatermarkNormalizer.to_grayscale(page_image)
            )
            if abs(detected_angle) >= 0.5:
                angles.append(detected_angle)
            for a in [-3.0, -2.0, -1.0, 1.0, 2.0, 3.0]:
                if not any(abs(a - existing) < 0.25 for existing in angles):
                    angles.append(a)

        best_status = ExtractionStatus.NOT_DETECTED
        best_payload: Optional[WatermarkPayload] = None
        best_corr = 0.0
        best_corrected = 0
        best_diag: Dict[str, Any] = {}

        for angle in angles:
            rotated = (
                page_image if abs(angle) < 0.05 else WatermarkNormalizer.deskew(page_image, angle)
            )
            norm_img, norm_meta = WatermarkNormalizer.normalize_page(rotated, deskew_enabled=False)

            for doc_hash in candidate_document_hashes:
                status, payload, corr, corrected, diag = cls._extract_page_with_hash(
                    norm_img, page_index, doc_hash, p
                )
                diag["tested_angle"] = angle
                diag["normalization"] = norm_meta

                if status == ExtractionStatus.DECODED and payload is not None:
                    return PageForensicResult(
                        page_number=page_number,
                        status=status,
                        detected=True,
                        decoded=True,
                        correlation_score=corr,
                        ecc_corrections=corrected,
                        watermark_id=payload.watermark_id,
                        session_tag=payload.session_tag.hex(),
                        document_binding=payload.document_binding.hex(),
                        diagnostics=diag,
                    )

                if corr > best_corr:
                    best_status = status
                    best_payload = payload
                    best_corr = corr
                    best_corrected = corrected
                    best_diag = diag

        detected = best_corr >= cls.CORRELATION_NOISE_THRESHOLD
        decoded = best_status == ExtractionStatus.DECODED and best_payload is not None

        return PageForensicResult(
            page_number=page_number,
            status=best_status,
            detected=detected,
            decoded=decoded,
            correlation_score=best_corr,
            ecc_corrections=best_corrected,
            watermark_id=best_payload.watermark_id if best_payload else None,
            session_tag=best_payload.session_tag.hex() if best_payload else None,
            document_binding=best_payload.document_binding.hex() if best_payload else None,
            diagnostics=best_diag,
        )

    @classmethod
    def analyze_document_pages(
        cls,
        pages: List[np.ndarray],
        candidate_document_hashes: Sequence[str],
        params: Optional[WatermarkParameters] = None,
        deskew_enabled: bool = True,
    ) -> Tuple[WatermarkForensicAnalysis, List[PageForensicResult]]:
        """Extract and analyze watermarks across all pages of the evidence artifact."""
        if not pages:
            analysis = WatermarkForensicAnalysis(
                overall_status=ExtractionStatus.NOT_DETECTED,
                pages_analyzed=0,
                pages_detected=0,
                pages_decoded=0,
                pages_corrupted=0,
                diagnostics={"error": "No pages provided for analysis"},
            )
            return analysis, []

        page_results: List[PageForensicResult] = []
        for idx, page in enumerate(pages):
            res = cls.extract_single_page(
                page_image=page,
                page_index=idx,
                candidate_document_hashes=candidate_document_hashes,
                params=params,
                deskew_enabled=deskew_enabled,
            )
            page_results.append(res)

        pages_analyzed = len(page_results)
        pages_detected = sum(1 for r in page_results if r.detected)
        pages_decoded = sum(1 for r in page_results if r.decoded)
        pages_corrupted = sum(
            1 for r in page_results if r.status in (ExtractionStatus.CORRUPTED, ExtractionStatus.INVALID)
        )
        total_ecc = sum(r.ecc_corrections for r in page_results)
        avg_corr = (
            float(np.mean([r.correlation_score for r in page_results])) if page_results else 0.0
        )

        decoded_results = [r for r in page_results if r.decoded and r.watermark_id is not None]
        distinct_wm_ids = sorted(list({str(r.watermark_id) for r in decoded_results}))
        distinct_sessions = sorted(list({str(r.session_tag) for r in decoded_results if r.session_tag}))

        # Multi-page consistency / ambiguity detection
        has_conflict = len(distinct_wm_ids) > 1 or len(distinct_sessions) > 1

        if has_conflict:
            overall_status = ExtractionStatus.AMBIGUOUS
            consensus_wm = None
            consensus_ses = None
            consensus_doc = None
        elif pages_decoded > 0:
            overall_status = ExtractionStatus.DECODED
            consensus_wm = decoded_results[0].watermark_id
            consensus_ses = decoded_results[0].session_tag
            consensus_doc = decoded_results[0].document_binding
        elif pages_corrupted > 0:
            # Check if any was INVALID vs CORRUPTED
            if any(r.status == ExtractionStatus.INVALID for r in page_results):
                overall_status = ExtractionStatus.INVALID
            else:
                overall_status = ExtractionStatus.CORRUPTED
            consensus_wm = None
            consensus_ses = None
            consensus_doc = None
        else:
            overall_status = ExtractionStatus.NOT_DETECTED
            consensus_wm = None
            consensus_ses = None
            consensus_doc = None

        analysis = WatermarkForensicAnalysis(
            overall_status=overall_status,
            pages_analyzed=pages_analyzed,
            pages_detected=pages_detected,
            pages_decoded=pages_decoded,
            pages_corrupted=pages_corrupted,
            total_ecc_corrections=total_ecc,
            average_correlation=avg_corr,
            consensus_watermark_id=consensus_wm,
            consensus_session_tag=consensus_ses,
            consensus_document_binding=consensus_doc,
            distinct_watermark_ids=distinct_wm_ids,
            has_cross_page_conflict=has_conflict,
            diagnostics={
                "distinct_sessions": distinct_sessions,
                "pages_detected_count": pages_detected,
                "pages_decoded_count": pages_decoded,
            },
        )

        return analysis, page_results
