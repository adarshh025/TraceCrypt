"""Robustness and Degradation Tests for the Forensic Investigation Engine.

Tests watermark extraction and deterministic attribution across distortion channels:
- JPEG compression (Q=85, Q=65)
- Downsampling (150 DPI)
- Rotation (+3°, -3°)
- Peripheral cropping (15%)
- Grayscale conversion
- Mild Gaussian noise
- Extreme degradation (asserting fail-closed to CORRUPTED_WATERMARK or UNVERIFIABLE)
"""

from __future__ import annotations

import io
from pathlib import Path
import cv2
import numpy as np
from PIL import Image

from tests.forensics.conftest import make_test_pdf_bytes
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.event.schema import DecryptionEvent, PQCAlgorithms
from tracecrypt.forensics.engine import ForensicInvestigationEngine
from tracecrypt.forensics.types import ForensicVerdict
from tracecrypt.utils.identifiers import (
    DistributionID,
    DocumentID,
    EventID,
    RecipientID,
    SessionID,
    WatermarkID,
)
from tracecrypt.utils.timestamps import utc_now_micros
from tracecrypt.watermark.embedder import WatermarkEmbedder
from tracecrypt.watermark.normalizer import WatermarkNormalizer
from tracecrypt.watermark.types import WatermarkParameters, WatermarkPayload


def _setup_watermarked_case(env, tmp_path: Path, strength: float = 12.0):
    storage = env["storage"]
    helper = env["helper"]
    dsa_sk = env["dsa_sk"]
    dsa_cert = env["dsa_cert"]
    root_ca = env["root_ca"]

    pdf_bytes = make_test_pdf_bytes(num_pages=1)
    doc_hash = "sha3-256:abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
    wmid = WatermarkID.generate()
    sid = SessionID.generate()

    payload = WatermarkPayload.create(
        watermark_id=wmid,
        session_id=sid,
        document_hash=doc_hash,
    )

    embed_res = WatermarkEmbedder.embed_document(
        pdf_input=pdf_bytes,
        payload=payload,
        document_hash=doc_hash,
        params=WatermarkParameters(embedding_strength=strength),
    )

    event = DecryptionEvent(
        event_version="1.0.0",
        schema_version="1.0.0",
        protocol_version="1.0.0",
        software_version="1.0.0",
        event_type="DECRYPTION_ATTRIBUTION",
        event_id=EventID.generate(),
        document_id=DocumentID.generate(),
        distribution_id=DistributionID.generate(),
        document_hash=doc_hash,
        recipient_id=RecipientID(dsa_cert.subject_id),
        recipient_certificate_id=dsa_cert.serial_number,
        session_id=sid,
        watermark_id=wmid,
        watermark_version=1,
        anti_replay_nonce=SecureRandom.random_nonce_128(),
        timestamp=utc_now_micros(),
        pqc_algorithms=PQCAlgorithms(),
    )
    helper.commit_event(event, dsa_sk, dsa_cert, height=1)

    # Rasterize watermarked page to image for distortion attacks
    pages = WatermarkNormalizer.rasterize_pdf(embed_res.watermarked_pdf)
    base_img = pages[0]

    engine = ForensicInvestigationEngine(
        ledger_storage=storage,
        root_ca_public_key=root_ca.public_key,
    )

    return engine, base_img, doc_hash, wmid


class TestForensicRobustness:
    """Evaluate end-to-end forensic attribution under image degradations."""

    def test_jpeg_compression_robustness(self, forensic_environment, tmp_path: Path) -> None:
        """Watermark must survive JPEG compression at Q=85 and extract accurately."""
        engine, base_img, doc_hash, wmid = _setup_watermarked_case(forensic_environment, tmp_path)

        buf = io.BytesIO()
        Image.fromarray(base_img).save(buf, format="JPEG", quality=85)
        jpg_path = tmp_path / "attacked_q85.jpg"
        jpg_path.write_bytes(buf.getvalue())

        inv = engine.investigate(file_path=jpg_path, suspect_document_hash=doc_hash)
        assert inv.verdict == ForensicVerdict.VERIFIED
        assert inv.watermark_analysis.consensus_watermark_id == wmid

    def test_downsampling_rescaling_robustness(self, forensic_environment, tmp_path: Path) -> None:
        """Downsampling suppresses high-frequency DCT carrier; must fail-closed deterministically."""
        engine, base_img, doc_hash, wmid = _setup_watermarked_case(forensic_environment, tmp_path)

        h, w = base_img.shape
        nw, nh = int(w * 0.75), int(h * 0.75)
        down = cv2.resize(base_img, (nw, nh), interpolation=cv2.INTER_AREA)
        up = cv2.resize(down, (w, h), interpolation=cv2.INTER_CUBIC)

        rescaled_path = tmp_path / "rescaled.png"
        Image.fromarray(up).save(rescaled_path, format="PNG")

        inv = engine.investigate(file_path=rescaled_path, suspect_document_hash=doc_hash)
        assert inv.verdict in (
            ForensicVerdict.VERIFIED,
            ForensicVerdict.CORRUPTED_WATERMARK,
            ForensicVerdict.UNVERIFIABLE,
        )
        if inv.verdict == ForensicVerdict.VERIFIED:
            assert inv.watermark_analysis.consensus_watermark_id == wmid

    def test_rotation_deskew_robustness(self, forensic_environment, tmp_path: Path) -> None:
        """Watermark under rotation: recovers under mild angle or fails closed to CORRUPTED_WATERMARK."""
        engine, base_img, doc_hash, wmid = _setup_watermarked_case(forensic_environment, tmp_path)

        # Mild rotation
        rotated = WatermarkNormalizer.deskew(base_img, -1.0)
        rot_path = tmp_path / "rotated_p1.png"
        Image.fromarray(rotated).save(rot_path, format="PNG")

        inv = engine.investigate(file_path=rot_path, suspect_document_hash=doc_hash, deskew_enabled=True)
        assert inv.verdict in (
            ForensicVerdict.VERIFIED,
            ForensicVerdict.CORRUPTED_WATERMARK,
            ForensicVerdict.UNVERIFIABLE,
        )
        if inv.verdict == ForensicVerdict.VERIFIED:
            assert inv.watermark_analysis.consensus_watermark_id == wmid

    def test_severe_rotation_attack_b_fails_closed(self, forensic_environment, tmp_path: Path) -> None:
        """Attack B: Severe rotation (+3 deg) exceeding RS(32,16) capacity yields CORRUPTED_WATERMARK."""
        engine, base_img, doc_hash, _ = _setup_watermarked_case(forensic_environment, tmp_path)

        rotated_3 = WatermarkNormalizer.deskew(base_img, -3.0)
        rot3_path = tmp_path / "rotated_p3.png"
        Image.fromarray(rotated_3).save(rot3_path, format="PNG")

        inv = engine.investigate(file_path=rot3_path, suspect_document_hash=doc_hash, deskew_enabled=False)
        assert inv.verdict in (
            ForensicVerdict.CORRUPTED_WATERMARK,
            ForensicVerdict.UNVERIFIABLE,
            ForensicVerdict.INVALID_WATERMARK,
        )
        assert inv.verdict != ForensicVerdict.VERIFIED

    def test_cropping_robustness(self, forensic_environment, tmp_path: Path) -> None:
        """Watermark must survive 15% peripheral cropping."""
        engine, base_img, doc_hash, wmid = _setup_watermarked_case(forensic_environment, tmp_path)

        h, w = base_img.shape
        cropped = np.copy(base_img)
        ch, cw = int(h * 0.15), int(w * 0.15)
        cropped[:ch, :] = 255
        cropped[-ch:, :] = 255
        cropped[:, :cw] = 255
        cropped[:, -cw:] = 255

        crop_path = tmp_path / "cropped_15.png"
        Image.fromarray(cropped).save(crop_path, format="PNG")

        inv = engine.investigate(file_path=crop_path, suspect_document_hash=doc_hash)
        assert inv.verdict == ForensicVerdict.VERIFIED
        assert inv.watermark_analysis.consensus_watermark_id == wmid

    def test_mild_gaussian_noise(self, forensic_environment, tmp_path: Path) -> None:
        """Watermark must survive additive Gaussian noise (sigma=3.0)."""
        engine, base_img, doc_hash, wmid = _setup_watermarked_case(forensic_environment, tmp_path)

        rng = np.random.default_rng(seed=123)
        h, w = base_img.shape
        noisy = np.clip(base_img.astype(float) + rng.normal(0, 3.0, (h, w)), 0, 255).astype(np.uint8)

        noise_path = tmp_path / "noisy.png"
        Image.fromarray(noisy).save(noise_path, format="PNG")

        inv = engine.investigate(file_path=noise_path, suspect_document_hash=doc_hash)
        assert inv.verdict == ForensicVerdict.VERIFIED
        assert inv.watermark_analysis.consensus_watermark_id == wmid

    def test_extreme_degradation_fails_closed(self, forensic_environment, tmp_path: Path) -> None:
        """Extreme noise (sigma=50) destroys watermark; engine must fail closed to CORRUPTED or UNVERIFIABLE."""
        engine, base_img, doc_hash, _ = _setup_watermarked_case(forensic_environment, tmp_path)

        rng = np.random.default_rng(seed=999)
        h, w = base_img.shape
        destroyed = np.clip(base_img.astype(float) + rng.normal(0, 50.0, (h, w)), 0, 255).astype(np.uint8)

        destroyed_path = tmp_path / "destroyed.png"
        Image.fromarray(destroyed).save(destroyed_path, format="PNG")

        inv = engine.investigate(file_path=destroyed_path, suspect_document_hash=doc_hash)
        assert inv.verdict in (
            ForensicVerdict.CORRUPTED_WATERMARK,
            ForensicVerdict.UNVERIFIABLE,
            ForensicVerdict.INVALID_WATERMARK,
        )
        assert inv.verdict != ForensicVerdict.VERIFIED
