"""Blind forensic watermark extractor for TraceCrypt leaked documents.

Executes blind extraction without requiring access to the original unwatermarked document.

Pipeline:
1. Forensic normalization (deskew, resolution alignment, contrast stretching)
2. 2D Haar DWT + Block 2D DCT decomposition
3. Spread-spectrum correlation using deterministic document-anchored carrier
4. Reed-Solomon RS(32, 16) error correction & syndrome verification
5. Checksum and structural payload validation
6. Multi-page consistency analysis (detecting spliced or conflicting pages)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import cv2
import numpy as np

from tracecrypt.errors import ValidationError
from tracecrypt.watermark.ecc import ReedSolomonError, WatermarkPayloadEncoder
from tracecrypt.watermark.embedder import WatermarkEmbedder
from tracecrypt.watermark.normalizer import WatermarkNormalizer
from tracecrypt.watermark.spread_spectrum import SpreadSpectrumEngine
from tracecrypt.watermark.transform import dct2_image_blocks, haar_dwt2
from tracecrypt.watermark.types import (
    ExtractionStatus,
    WatermarkExtractionResult,
    WatermarkParameters,
    WatermarkPayload,
)


class WatermarkExtractor:
    """Forensic extractor analyzing leaked PDFs and image artifacts."""

    CORRELATION_NOISE_THRESHOLD: float = 1.0  # Above this, signal is present

    @classmethod
    def _extract_from_normalized_image(
        cls,
        norm_img: np.ndarray,
        page_index: int,
        document_hash: str,
        params: WatermarkParameters,
    ) -> Tuple[ExtractionStatus, Optional[WatermarkPayload], float, int, Dict[str, Any]]:
        """Internal worker extracting watermark from an already normalized image."""
        diagnostics: Dict[str, Any] = {"page_index": page_index}
        img_float = norm_img.astype(np.float64)

        # 1. 2D Haar DWT
        _, lh, hl, _ = haar_dwt2(img_float)

        # 2. 8x8 Block DCT on HL and LH detail subbands
        dct_hl = dct2_image_blocks(hl, block_size=params.block_size)
        dct_lh = dct2_image_blocks(lh, block_size=params.block_size)

        # 3. Reconstruct site map
        h_sb, w_sb = hl.shape
        site_map = WatermarkEmbedder._build_site_map(h_sb, w_sb, block_size=params.block_size)

        # 4. Reconstruct page carrier sequence
        carrier_seed = WatermarkEmbedder.derive_page_seed(document_hash, page_index)
        perm, signs = SpreadSpectrumEngine.generate_carrier_sequence(carrier_seed, len(site_map))

        # 5. Blind spread-spectrum correlation
        ext_bits, mean_corr, _ = SpreadSpectrumEngine.extract_bits(
            dct_subbands={"HL": dct_hl, "LH": dct_lh},
            site_map=site_map,
            permutation=perm,
            signs=signs,
            num_bits=512,
        )
        diagnostics["mean_correlation"] = mean_corr
        diagnostics["raw_bits"] = ext_bits.tolist()

        if mean_corr < cls.CORRELATION_NOISE_THRESHOLD:
            return ExtractionStatus.NOT_DETECTED, None, mean_corr, 0, diagnostics

        # 6. Reed-Solomon RS(32, 16) Forward Error Correction
        ext_bytes = np.packbits(ext_bits).tobytes()
        encoder = WatermarkPayloadEncoder()

        try:
            dec_payload_bytes, corrected_symbols = encoder.decode_payload(ext_bytes)
            diagnostics["corrected_symbols"] = corrected_symbols
        except ReedSolomonError as e:
            diagnostics["rs_error"] = str(e)
            return ExtractionStatus.CORRUPTED, None, mean_corr, 0, diagnostics

        # 7. Checksum and structure validation
        try:
            payload = WatermarkPayload.from_bytes(dec_payload_bytes)
            return ExtractionStatus.DECODED, payload, mean_corr, corrected_symbols, diagnostics
        except ValidationError as e:
            diagnostics["payload_error"] = str(e)
            return ExtractionStatus.CORRUPTED, None, mean_corr, corrected_symbols, diagnostics

    @classmethod
    def extract_page(
        cls,
        page_image: np.ndarray,
        page_index: int,
        document_hash: str,
        params: Optional[WatermarkParameters] = None,
        deskew_enabled: bool = True,
    ) -> Tuple[ExtractionStatus, Optional[WatermarkPayload], float, int, Dict[str, Any]]:
        """Blindly extract watermark payload from a single image page.

        Two-stage process:
        Stage 1: Evaluates upright orientation (theta = 0) without rotation blur.
        Stage 2: If Stage 1 is inconclusive and deskew_enabled is True, evaluates
                 rotation angles to compensate for scanned / rotated artifacts.

        Returns:
            Tuple of (status, payload_or_none, correlation_score, corrected_errors, diagnostics).
        """
        p = params or WatermarkParameters()

        # Stage 1: Fast upright evaluation
        norm_img, norm_meta = WatermarkNormalizer.normalize_page(page_image, deskew_enabled=False)
        status, payload, corr, corrected, diag = cls._extract_from_normalized_image(
            norm_img, page_index, document_hash, p
        )
        diag["normalization"] = norm_meta

        if status == ExtractionStatus.DECODED:
            return status, payload, corr, corrected, diag

        # Stage 2: Deskew search if enabled and upright was not decoded
        if deskew_enabled:
            # Check detected angle first
            est_angle = WatermarkNormalizer.estimate_skew_angle(WatermarkNormalizer.to_grayscale(page_image))
            candidate_angles: List[float] = []
            if abs(est_angle) >= 0.25:
                for sign in [1.0, -1.0]:
                    signed_angle = sign * abs(est_angle)
                    if not any(abs(signed_angle - ca) < 0.05 for ca in candidate_angles):
                        candidate_angles.append(signed_angle)
                    round_angle = sign * round(abs(est_angle))
                    if 0.5 <= abs(round_angle) <= 5.0 and not any(abs(round_angle - ca) < 0.05 for ca in candidate_angles):
                        candidate_angles.append(round_angle)

            # Ensure small standard forensic rotation angles are evaluated
            for a in [-3.0, -2.0, -1.0, 1.0, 2.0, 3.0]:
                if not any(abs(a - ca) < 0.05 for ca in candidate_angles):
                    candidate_angles.append(a)

            best_status = status
            best_payload = payload
            best_corr = corr
            best_corrected = corrected
            best_diag = diag

            for angle in candidate_angles:
                deskewed_img = WatermarkNormalizer.deskew(page_image, angle)
                d_norm_img, d_meta = WatermarkNormalizer.normalize_page(deskewed_img, deskew_enabled=False)
                d_status, d_payload, d_corr, d_corrected, d_diag = cls._extract_from_normalized_image(
                    d_norm_img, page_index, document_hash, p
                )
                d_diag["tested_angle"] = angle
                d_diag["normalization"] = d_meta

                if d_status == ExtractionStatus.DECODED:
                    return d_status, d_payload, d_corr, d_corrected, d_diag

                if d_corr > best_corr:
                    best_status = d_status
                    best_payload = d_payload
                    best_corr = d_corr
                    best_corrected = d_corrected
                    best_diag = d_diag

            return best_status, best_payload, best_corr, best_corrected, best_diag

        return status, payload, corr, corrected, diag

    @classmethod
    def extract_document(
        cls,
        artifact_input: bytes | Path | str | List[np.ndarray],
        document_hash: str,
        params: Optional[WatermarkParameters] = None,
        deskew_enabled: bool = True,
    ) -> WatermarkExtractionResult:
        """Execute forensic extraction across all pages of a leaked PDF or image artifact.

        Analyzes multi-page consistency and fails closed if conflicting signals are detected.
        """
        p = params or WatermarkParameters()

        # 1. Load pages
        if isinstance(artifact_input, list):
            pages = artifact_input
        elif isinstance(artifact_input, (str, Path)) and not str(artifact_input).lower().endswith(".pdf"):
            # Single image file
            loaded = cv2.imread(str(artifact_input), cv2.IMREAD_GRAYSCALE)
            if loaded is None:
                raise ValueError(f"Failed to read image artifact: {artifact_input}")
            pages = [loaded]
        else:
            # PDF bytes or file path
            try:
                pages = WatermarkNormalizer.rasterize_pdf(artifact_input, scale=p.render_scale)
            except Exception:
                # Fallback to image loading if bytes represent an image format
                if isinstance(artifact_input, bytes):
                    np_buf = np.frombuffer(artifact_input, np.uint8)
                    loaded = cv2.imdecode(np_buf, cv2.IMREAD_GRAYSCALE)
                    if loaded is not None:
                        pages = [loaded]
                    else:
                        raise ValueError("Failed to parse artifact as PDF or image")
                else:
                    raise

        if not pages:
            return WatermarkExtractionResult(
                status=ExtractionStatus.NOT_DETECTED,
                pages_analyzed=0,
                diagnostics={"error": "No pages available for analysis"},
            )

        decoded_payloads: List[WatermarkPayload] = []
        statuses: List[ExtractionStatus] = []
        corr_scores: List[float] = []
        total_corrected = 0
        page_diagnostics: List[Dict[str, Any]] = []

        # 2. Process each page
        for page_idx, page in enumerate(pages):
            status, payload, corr, corrected, diag = cls.extract_page(
                page_image=page,
                page_index=page_idx,
                document_hash=document_hash,
                params=p,
                deskew_enabled=deskew_enabled,
            )
            statuses.append(status)
            corr_scores.append(corr)
            page_diagnostics.append(diag)
            if payload is not None:
                decoded_payloads.append(payload)
                total_corrected += corrected

        avg_corr = float(np.mean(corr_scores)) if corr_scores else 0.0
        pages_decoded = len(decoded_payloads)
        pages_corrupted = statuses.count(ExtractionStatus.CORRUPTED)

        # 3. Multi-page consistency analysis
        if pages_decoded > 0:
            distinct_wm_ids = {str(p.watermark_id) for p in decoded_payloads}
            distinct_sessions = {p.session_tag.hex() for p in decoded_payloads}

            # Check for conflict: multiple different valid watermark IDs across pages
            if len(distinct_wm_ids) > 1 or len(distinct_sessions) > 1:
                return WatermarkExtractionResult(
                    status=ExtractionStatus.AMBIGUOUS,
                    correlation_score=avg_corr,
                    corrected_errors=total_corrected,
                    pages_analyzed=len(pages),
                    pages_decoded=pages_decoded,
                    pages_corrupted=pages_corrupted,
                    diagnostics={
                        "conflict": "Multiple conflicting watermark IDs detected across pages",
                        "distinct_watermark_ids": list(distinct_wm_ids),
                        "page_diagnostics": page_diagnostics,
                    },
                )

            # Consistent attribution across pages!
            consensus_payload = decoded_payloads[0]
            return WatermarkExtractionResult(
                status=ExtractionStatus.DECODED,
                watermark_version=consensus_payload.version,
                watermark_id=consensus_payload.watermark_id,
                session_tag=consensus_payload.session_tag.hex(),
                document_binding=consensus_payload.document_binding.hex(),
                correlation_score=avg_corr,
                corrected_errors=total_corrected,
                pages_analyzed=len(pages),
                pages_decoded=pages_decoded,
                pages_corrupted=pages_corrupted,
                diagnostics={"page_diagnostics": page_diagnostics},
            )

        if pages_corrupted > 0:
            return WatermarkExtractionResult(
                status=ExtractionStatus.CORRUPTED,
                correlation_score=avg_corr,
                pages_analyzed=len(pages),
                pages_decoded=0,
                pages_corrupted=pages_corrupted,
                diagnostics={"page_diagnostics": page_diagnostics},
            )

        return WatermarkExtractionResult(
            status=ExtractionStatus.NOT_DETECTED,
            correlation_score=avg_corr,
            pages_analyzed=len(pages),
            pages_decoded=0,
            pages_corrupted=0,
            diagnostics={"page_diagnostics": page_diagnostics},
        )
