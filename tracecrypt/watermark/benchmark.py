"""Automated benchmarking and robustness attack matrix suite for TraceCrypt.

Measures:
- Latency: PDF rendering, embedding, extraction, normalization
- Invisibility: PSNR (target >= 42 dB) and SSIM (target >= 0.995)
- Robustness: JPEG compression, downsampling, rotation, cropping, noise, blur, combined attacks
- Bit Error Rate (BER) and Reed-Solomon correction counts
"""

from __future__ import annotations

import io
from pathlib import Path
import time
from typing import Any, Dict, List, Optional
import cv2
import numpy as np
from PIL import Image

from tracecrypt.crypto.random import SecureRandom
from tracecrypt.utils.identifiers import SessionID, WatermarkID
from tracecrypt.watermark.ecc import WatermarkPayloadEncoder
from tracecrypt.watermark.embedder import WatermarkEmbedder
from tracecrypt.watermark.extractor import WatermarkExtractor
from tracecrypt.watermark.fidelity import calculate_ber
from tracecrypt.watermark.normalizer import WatermarkNormalizer
from tracecrypt.watermark.types import (
    ExtractionStatus,
    WatermarkParameters,
    WatermarkPayload,
)


class WatermarkBenchmark:
    """Empirical benchmarking engine measuring latency, fidelity, and attack survivability."""

    @classmethod
    def run_performance_benchmark(
        cls,
        pdf_input: bytes | Path | str,
        document_hash: str,
        params: Optional[WatermarkParameters] = None,
    ) -> Dict[str, Any]:
        """Measure local execution latencies for rendering, embedding, normalization, and extraction."""
        p = params or WatermarkParameters()

        if isinstance(pdf_input, (str, Path)):
            pdf_bytes = Path(pdf_input).read_bytes()
        else:
            pdf_bytes = pdf_input

        # 1. Measure PDF rasterization latency
        t0 = time.perf_counter_ns()
        pages = WatermarkNormalizer.rasterize_pdf(pdf_bytes, scale=p.render_scale)
        t_raster = (time.perf_counter_ns() - t0) / 1e6  # ms
        pages_count = len(pages)
        ms_per_page_raster = t_raster / pages_count if pages_count else 0.0

        # 2. Setup payload
        wm_id = SecureRandom.generate_typed_id(WatermarkID)
        ses_id = SecureRandom.generate_typed_id(SessionID)
        payload = WatermarkPayload.create(wm_id, ses_id, document_hash)

        # 3. Measure embedding latency
        t0 = time.perf_counter_ns()
        embed_res = WatermarkEmbedder.embed_document(pdf_bytes, payload, document_hash, params=p)
        t_embed = (time.perf_counter_ns() - t0) / 1e6  # ms
        ms_per_page_embed = t_embed / pages_count if pages_count else 0.0

        # 4. Measure extraction latency
        t0 = time.perf_counter_ns()
        ext_res = WatermarkExtractor.extract_document(
            embed_res.watermarked_pdf, document_hash, params=p, deskew_enabled=True
        )
        t_extract = (time.perf_counter_ns() - t0) / 1e6  # ms
        ms_per_page_extract = t_extract / pages_count if pages_count else 0.0

        return {
            "pages_count": pages_count,
            "render_ms_total": round(t_raster, 2),
            "render_ms_per_page": round(ms_per_page_raster, 2),
            "embed_ms_total": round(t_embed, 2),
            "embed_ms_per_page": round(ms_per_page_embed, 2),
            "extract_ms_total": round(t_extract, 2),
            "extract_ms_per_page": round(ms_per_page_extract, 2),
            "fidelity": embed_res.fidelity.model_dump(),
            "extraction_status": ext_res.status.value,
            "meets_target_3_5s": (ms_per_page_extract / 1000.0) <= 3.5,
        }

    @classmethod
    def run_attack_matrix(
        cls,
        pdf_input: bytes | Path | str,
        document_hash: str,
        params: Optional[WatermarkParameters] = None,
    ) -> List[Dict[str, Any]]:
        """Execute automated robustness attack simulations against the watermarked document."""
        p = params or WatermarkParameters(embedding_strength=10.0)

        if isinstance(pdf_input, (str, Path)):
            pdf_bytes = Path(pdf_input).read_bytes()
        else:
            pdf_bytes = pdf_input

        # Create reference payload and embed
        wm_id = SecureRandom.generate_typed_id(WatermarkID)
        ses_id = SecureRandom.generate_typed_id(SessionID)
        payload = WatermarkPayload.create(wm_id, ses_id, document_hash)

        embed_res = WatermarkEmbedder.embed_document(pdf_bytes, payload, document_hash, params=p)
        raw_coded_bytes = WatermarkPayloadEncoder().encode_payload(payload.to_bytes())
        ref_bits = np.unpackbits(np.frombuffer(raw_coded_bytes, dtype=np.uint8))

        # Rasterize first watermarked page for image-level attack simulations
        pages = WatermarkNormalizer.rasterize_pdf(embed_res.watermarked_pdf, scale=p.render_scale)
        wm_page = pages[0]
        h, w = wm_page.shape

        results: List[Dict[str, Any]] = []

        def _evaluate_attack(attack_name: str, attacked_img: np.ndarray, deskew: bool = False) -> None:
            ext = WatermarkExtractor.extract_document([attacked_img], document_hash, params=p, deskew_enabled=deskew)
            diag = ext.diagnostics.get("page_diagnostics", [{}])[0]
            corr = float(diag.get("mean_correlation", ext.correlation_score))
            corr_symbols = int(diag.get("corrected_symbols", ext.corrected_errors))
            raw_bits = diag.get("raw_bits")
            raw_ber = calculate_ber(ref_bits, np.array(raw_bits, dtype=np.uint8)) if raw_bits else 1.0

            matched = (ext.status == ExtractionStatus.DECODED and ext.watermark_id == wm_id)

            results.append({
                "attack": attack_name,
                "status": ext.status.value,
                "raw_ber": round(raw_ber, 4),
                "correlation": round(corr, 4),
                "corrected_symbols": corr_symbols,
                "payload_matched": matched,
            })

        # 1. Baseline
        _evaluate_attack("Baseline (Watermarked PDF)", wm_page)

        # 2. JPEG Compression (Q=95, 85, 75, 65)
        for q in [95, 85, 75, 65]:
            buf = io.BytesIO()
            Image.fromarray(wm_page).save(buf, format="JPEG", quality=q)
            jpg_img = np.array(Image.open(buf).convert("L"), dtype=np.uint8)
            _evaluate_attack(f"JPEG (Q={q})", jpg_img)

        # 3. Downsampling (150 DPI -> 75 DPI -> 150 DPI)
        down = cv2.resize(wm_page, (w // 2, h // 2), interpolation=cv2.INTER_AREA)
        up = cv2.resize(down, (w, h), interpolation=cv2.INTER_CUBIC)
        _evaluate_attack("Downsampling (2x reduction)", up)

        # 4. Rotation (+/- 1, 2, 3 degrees)
        for deg in [-3.0, -2.0, -1.0, 1.0, 2.0, 3.0]:
            rot = WatermarkNormalizer.deskew(wm_page, -deg)
            _evaluate_attack(f"Rotation ({deg:+.0f}°)", rot, deskew=True)

        # 5. Cropping (5%, 10%, 15%)
        for crop_p in [0.05, 0.10, 0.15]:
            cropped = np.copy(wm_page)
            ch = int(h * crop_p)
            cw = int(w * crop_p)
            cropped[:ch, :] = 255
            cropped[-ch:, :] = 255
            cropped[:, :cw] = 255
            cropped[:, -cw:] = 255
            _evaluate_attack(f"Cropping ({int(crop_p*100)}%)", cropped)

        # 6. Gaussian Noise (std=3.0, 5.0)
        for std in [3.0, 5.0]:
            noise = np.clip(wm_page.astype(float) + np.random.normal(0, std, (h, w)), 0, 255).astype(np.uint8)
            _evaluate_attack(f"Gaussian Noise (std={std})", noise)

        # 7. Gaussian Blur (k=3)
        blur = cv2.GaussianBlur(wm_page, (3, 3), 0.5)
        _evaluate_attack("Gaussian Blur (3x3)", blur)

        # 8. Brightness / Contrast
        dark = np.clip(wm_page.astype(float) - 20.0, 0, 255).astype(np.uint8)
        _evaluate_attack("Brightness (-20)", dark)

        contrast = np.clip(wm_page.astype(float) * 0.85, 0, 255).astype(np.uint8)
        _evaluate_attack("Contrast (0.85x)", contrast)

        # 9. Combined Attacks
        # Combined A: Rotation (+2 deg) + JPEG (Q=85)
        rot2 = WatermarkNormalizer.deskew(wm_page, -2.0)
        buf = io.BytesIO()
        Image.fromarray(rot2).save(buf, format="JPEG", quality=85)
        comb_a = np.array(Image.open(buf).convert("L"), dtype=np.uint8)
        _evaluate_attack("Combined: Rotation (+2°) + JPEG (Q=85)", comb_a, deskew=True)

        # Combined B: Cropping (10%) + JPEG (Q=85)
        c10 = np.copy(wm_page)
        c10[:int(h*0.1), :] = 255
        c10[-int(h*0.1):, :] = 255
        buf = io.BytesIO()
        Image.fromarray(c10).save(buf, format="JPEG", quality=85)
        comb_b = np.array(Image.open(buf).convert("L"), dtype=np.uint8)
        _evaluate_attack("Combined: Crop (10%) + JPEG (Q=85)", comb_b)

        # Combined C: Blur + JPEG (Q=85)
        blur_jpg = cv2.GaussianBlur(wm_page, (3, 3), 0.4)
        buf = io.BytesIO()
        Image.fromarray(blur_jpg).save(buf, format="JPEG", quality=85)
        comb_c = np.array(Image.open(buf).convert("L"), dtype=np.uint8)
        _evaluate_attack("Combined: Blur + JPEG (Q=85)", comb_c)

        return results
