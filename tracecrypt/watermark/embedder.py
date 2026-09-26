"""Transform-domain watermark embedder for TraceCrypt PDF documents.

Embeds 256-bit logical watermark payloads into multi-page PDF documents using:
- 2D Haar Discrete Wavelet Transform (DWT-2D)
- Block 2D Discrete Cosine Transform (DCT-2D)
- Mid-frequency spread-spectrum modulation
- Reed-Solomon RS(32, 16) Forward Error Correction

Ensures perceptual transparency (PSNR >= 42 dB) while maintaining robust
recoverability from individual pages.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Tuple
import numpy as np
from pydantic import BaseModel, ConfigDict

from tracecrypt.crypto.hashing import HashAlgorithm, Hasher
from tracecrypt.watermark.ecc import WatermarkPayloadEncoder
from tracecrypt.watermark.fidelity import evaluate_fidelity
from tracecrypt.watermark.normalizer import WatermarkNormalizer
from tracecrypt.watermark.spread_spectrum import SpreadSpectrumEngine
from tracecrypt.watermark.transform import (
    dct2_image_blocks,
    get_zigzag_indices,
    haar_dwt2,
    haar_idwt2,
    idct2_image_blocks,
)
from tracecrypt.watermark.types import FidelityMetrics, WatermarkParameters, WatermarkPayload


class WatermarkEmbeddingResult(BaseModel):
    """Result of embedding forensic watermark into a document."""
    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    watermarked_pdf: bytes
    fidelity: FidelityMetrics
    page_fidelities: List[FidelityMetrics]
    pages_count: int
    payload: WatermarkPayload


class WatermarkEmbedder:
    """Production watermark embedding engine for PDF documents and image pages."""

    @classmethod
    def _build_site_map(cls, h: int, w: int, block_size: int = 8) -> List[Tuple[str, int, int]]:
        """Construct deterministic mid-frequency coordinate map for HL and LH subbands."""
        mid_coords = get_zigzag_indices(block_size)[1:10]
        h_blks = h // block_size
        w_blks = w // block_size
        num_blks = h_blks * w_blks

        site_map: List[Tuple[str, int, int]] = []
        for sb in ["HL", "LH"]:
            for blk_idx in range(num_blks):
                bi = blk_idx // w_blks
                bj = blk_idx % w_blks
                for cr, cc in mid_coords:
                    site_map.append((sb, bi * block_size + cr, bj * block_size + cc))

        return site_map

    @classmethod
    def derive_page_seed(cls, document_hash: str, page_index: int) -> bytes:
        """Derive deterministic carrier seed for a specific document page."""
        ctx = (
            b"TraceCrypt-Watermark-Carrier:v1:"
            + document_hash.lower().encode("ascii")
            + b":page:"
            + str(page_index).encode("ascii")
        )
        return Hasher.digest_bytes(ctx, HashAlgorithm.SHA3_256.value).raw_bytes

    @classmethod
    def embed_page(
        cls,
        page_image: np.ndarray,
        page_index: int,
        payload: WatermarkPayload,
        document_hash: str,
        params: Optional[WatermarkParameters] = None,
    ) -> Tuple[np.ndarray, FidelityMetrics]:
        """Embed watermark payload into a single 2D grayscale image page.

        Returns:
            Tuple of (watermarked_2d_uint8_array, fidelity_metrics).
        """
        p = params or WatermarkParameters()

        # 1. Align dimensions to multiple of 16 (for DWT and 8x8 DCT)
        norm_img, _ = WatermarkNormalizer.normalize_page(page_image, deskew_enabled=False)
        orig_float = norm_img.astype(np.float64)

        # 2. Encode 32-byte (256-bit) payload to 64-byte (512-bit) RS(32, 16) coded stream
        encoder = WatermarkPayloadEncoder()
        coded_bytes = encoder.encode_payload(payload.to_bytes())
        coded_bits = np.unpackbits(np.frombuffer(coded_bytes, dtype=np.uint8))

        # 3. 2D Haar DWT
        ll, lh, hl, hh = haar_dwt2(orig_float)

        # 4. 8x8 Block DCT on HL and LH detail subbands
        dct_hl = dct2_image_blocks(hl, block_size=p.block_size)
        dct_lh = dct2_image_blocks(lh, block_size=p.block_size)

        # 5. Build site map
        h_sb, w_sb = hl.shape
        site_map = cls._build_site_map(h_sb, w_sb, block_size=p.block_size)

        # 6. Generate deterministic pseudo-random carrier sequence for this page
        carrier_seed = cls.derive_page_seed(document_hash, page_index)
        perm, signs = SpreadSpectrumEngine.generate_carrier_sequence(carrier_seed, len(site_map))

        # 7. Spread-spectrum modulation
        mod_subbands = SpreadSpectrumEngine.embed_bits(
            dct_subbands={"HL": dct_hl, "LH": dct_lh},
            site_map=site_map,
            coded_bits=coded_bits,
            permutation=perm,
            signs=signs,
            alpha=p.embedding_strength,
        )

        # 8. Inverse 2D DCT on modified subbands
        sp_hl = idct2_image_blocks(mod_subbands["HL"], block_size=p.block_size)
        sp_lh = idct2_image_blocks(mod_subbands["LH"], block_size=p.block_size)

        # 9. Inverse 2D Haar DWT
        wm_float = haar_idwt2(ll, sp_lh, sp_hl, hh)
        wm_uint8 = np.clip(np.round(wm_float), 0, 255).astype(np.uint8)

        # 10. Measure fidelity against original normalized input
        fidelity = evaluate_fidelity(norm_img, wm_uint8)

        return wm_uint8, fidelity

    @classmethod
    def embed_document(
        cls,
        pdf_input: bytes | Path | str,
        payload: WatermarkPayload,
        document_hash: str,
        params: Optional[WatermarkParameters] = None,
    ) -> WatermarkEmbeddingResult:
        """Embed watermark into all pages of a PDF document.

        Returns:
            WatermarkEmbeddingResult containing the watermarked PDF bytes and metrics.
        """
        p = params or WatermarkParameters()

        # 1. Rasterize all pages
        pages = WatermarkNormalizer.rasterize_pdf(pdf_input, scale=p.render_scale)
        if not pages:
            raise ValueError("Input PDF contains no renderable pages")

        wm_pages: List[np.ndarray] = []
        page_fidelities: List[FidelityMetrics] = []

        # 2. Embed into each page independently
        for page_idx, page in enumerate(pages):
            wm_page, fidelity = cls.embed_page(
                page_image=page,
                page_index=page_idx,
                payload=payload,
                document_hash=document_hash,
                params=p,
            )
            wm_pages.append(wm_page)
            page_fidelities.append(fidelity)

        # 3. Compute aggregate fidelity metrics
        avg_psnr = float(np.mean([f.psnr for f in page_fidelities]))
        avg_ssim = float(np.mean([f.ssim for f in page_fidelities]))
        avg_mse = float(np.mean([f.mse for f in page_fidelities]))
        overall_fidelity = FidelityMetrics(psnr=avg_psnr, ssim=avg_ssim, mse=avg_mse)

        # 4. Reconstruct watermarked PDF
        watermarked_pdf = WatermarkNormalizer.pages_to_pdf(wm_pages, dpi=72.0 * p.render_scale)

        return WatermarkEmbeddingResult(
            watermarked_pdf=watermarked_pdf,
            fidelity=overall_fidelity,
            page_fidelities=page_fidelities,
            pages_count=len(wm_pages),
            payload=payload,
        )
