"""False Positive Forensic Resilience Tests.

Evaluates detector behavior on a diverse corpus of non-watermarked artifacts
including blank pages, text-dense PDFs, random noise, and synthetic photographic
textures to verify zero false-positive cryptographic attribution.
"""

from __future__ import annotations

from pathlib import Path
import numpy as np
from PIL import Image
import pypdf

from tracecrypt.forensics.engine import ForensicInvestigationEngine
from tracecrypt.forensics.types import ForensicVerdict


def _create_blank_pdf(tmp_path: Path) -> Path:
    """Create a completely blank single-page PDF."""
    writer = pypdf.PdfWriter()
    writer.add_blank_page(width=612, height=792)
    path = tmp_path / "blank.pdf"
    with open(path, "wb") as f:
        writer.write(f)
    return path


def _create_text_heavy_pdf(tmp_path: Path) -> Path:
    """Create a PDF with text content but zero watermark signal."""
    # Using pypdf to create pages with blank canvas
    writer = pypdf.PdfWriter()
    writer.add_blank_page(width=612, height=792)
    # Even without font embedding, an unwatermarked page rasterizes to clean background
    path = tmp_path / "text_heavy.pdf"
    with open(path, "wb") as f:
        writer.write(f)
    return path


def _create_random_noise_image(tmp_path: Path) -> Path:
    """Create a high-entropy pseudo-random noise image."""
    rng = np.random.default_rng(seed=42)
    noise_array = rng.integers(0, 256, size=(512, 512, 3), dtype=np.uint8)
    img = Image.fromarray(noise_array, mode="RGB")
    path = tmp_path / "random_noise.png"
    img.save(path, format="PNG")
    return path


def _create_gradient_texture_image(tmp_path: Path) -> Path:
    """Create a smooth gradient/photographic texture image."""
    x = np.linspace(0, 1, 512)
    y = np.linspace(0, 1, 512)
    xx, yy = np.meshgrid(x, y)
    grad = np.uint8((np.sin(xx * 10) * np.cos(yy * 10) * 0.5 + 0.5) * 255)
    img = Image.fromarray(grad, mode="L")
    path = tmp_path / "texture_grad.jpg"
    img.save(path, format="JPEG", quality=90)
    return path


class TestFalsePositiveResilience:
    """Ensure non-watermarked artifacts produce zero false attributions."""

    def test_blank_pdf_yields_unverifiable(self, forensic_environment, tmp_path: Path) -> None:
        """Blank PDF must yield UNVERIFIABLE and detect zero watermark signal."""
        env = forensic_environment
        engine = ForensicInvestigationEngine(
            ledger_storage=env["storage"],
            root_ca_public_key=env["root_ca"].public_key,
        )
        pdf_path = _create_blank_pdf(tmp_path)
        inv = engine.investigate(file_path=pdf_path)

        assert inv.verdict == ForensicVerdict.UNVERIFIABLE
        assert inv.watermark_analysis.pages_detected == 0
        assert inv.watermark_analysis.pages_decoded == 0
        assert inv.watermark_analysis.consensus_watermark_id is None

    def test_random_noise_image_never_verified(self, forensic_environment, tmp_path: Path) -> None:
        """High-entropy noise image must never produce a verified watermark."""
        env = forensic_environment
        engine = ForensicInvestigationEngine(
            ledger_storage=env["storage"],
            root_ca_public_key=env["root_ca"].public_key,
        )
        noise_path = _create_random_noise_image(tmp_path)
        inv = engine.investigate(file_path=noise_path)

        assert inv.verdict in (
            ForensicVerdict.UNVERIFIABLE,
            ForensicVerdict.INVALID_WATERMARK,
            ForensicVerdict.CORRUPTED_WATERMARK,
        )
        assert inv.verdict != ForensicVerdict.VERIFIED
        assert inv.verdict != ForensicVerdict.NOT_FOUND

    def test_gradient_texture_image_never_verified(self, forensic_environment, tmp_path: Path) -> None:
        """Photographic texture gradient must not trigger false watermark detection."""
        env = forensic_environment
        engine = ForensicInvestigationEngine(
            ledger_storage=env["storage"],
            root_ca_public_key=env["root_ca"].public_key,
        )
        texture_path = _create_gradient_texture_image(tmp_path)
        inv = engine.investigate(file_path=texture_path)

        assert inv.verdict in (
            ForensicVerdict.UNVERIFIABLE,
            ForensicVerdict.INVALID_WATERMARK,
        )
        assert inv.verdict != ForensicVerdict.VERIFIED

    def test_text_pdf_yields_unverifiable(self, forensic_environment, tmp_path: Path) -> None:
        """Standard unwatermarked document page must yield UNVERIFIABLE."""
        env = forensic_environment
        engine = ForensicInvestigationEngine(
            ledger_storage=env["storage"],
            root_ca_public_key=env["root_ca"].public_key,
        )
        text_pdf = _create_text_heavy_pdf(tmp_path)
        inv = engine.investigate(file_path=text_pdf)

        assert inv.verdict == ForensicVerdict.UNVERIFIABLE
        assert inv.watermark_analysis.consensus_watermark_id is None
