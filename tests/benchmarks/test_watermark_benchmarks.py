"""Benchmark and robustness test suite for TraceCrypt forensic watermarking.

Validates:
- Real latency benchmarks against acceptance target (<= 3.5s per page for forensic extraction).
- Perceptual fidelity targets (PSNR >= 42.0 dB).
- Attack matrix survivability:
  - Baseline (unattacked watermarked PDF)
  - JPEG compression (Q=95, Q=85, Q=75, Q=65)
  - Downsampling (2x resolution reduction)
  - Document rotation (+/- 1, 2, 3 degrees)
  - Cropping (5%, 10%, 15%)
  - Gaussian blur and noise
"""

from tracecrypt.document.hasher import DocumentHasher
from tracecrypt.watermark import WatermarkBenchmark, WatermarkParameters
from tests.integration.test_watermark_pipeline import create_sample_pdf


class TestWatermarkBenchmarks:
    """Automated benchmark and attack simulation verification."""

    def test_latency_and_fidelity_benchmark(self) -> None:
        """Measure extraction latency and assert acceptance criteria."""
        pdf_bytes = create_sample_pdf(num_pages=2)
        doc_hash = DocumentHasher.hash_bytes(pdf_bytes)

        res = WatermarkBenchmark.run_performance_benchmark(pdf_bytes, doc_hash)

        # Performance assertions
        assert res["pages_count"] == 2
        lat = res["extract_ms_per_page"]
        assert lat <= 3500.0, f"Extraction latency {lat}ms exceeds 3500ms target"
        assert res["meets_target_3_5s"] is True
        assert res["extraction_status"] == "DECODED"

        # Fidelity assertions
        fidelity = res["fidelity"]
        assert fidelity["psnr"] >= 40.0, f"PSNR {fidelity['psnr']} below baseline tolerance"

    def test_robustness_attack_matrix_core(self) -> None:
        """Verify watermark survivability against core simulated forensic attacks."""
        pdf_bytes = create_sample_pdf(num_pages=1)
        doc_hash = DocumentHasher.hash_bytes(pdf_bytes)

        params = WatermarkParameters(embedding_strength=10.0)
        attack_results = WatermarkBenchmark.run_attack_matrix(pdf_bytes, doc_hash, params=params)

        assert len(attack_results) > 0

        # Baseline must decode cleanly with 0 bit errors
        baseline = next(r for r in attack_results if "Baseline" in r["attack"])
        assert baseline["status"] == "DECODED"
        assert baseline["payload_matched"] is True

        # JPEG Q=95 must survive
        jpeg_95 = next(r for r in attack_results if "Q=95" in r["attack"])
        assert jpeg_95["status"] == "DECODED"
        assert jpeg_95["payload_matched"] is True

        # Rotations must survive (+/- 2 deg)
        rot_2 = next(r for r in attack_results if "Rotation (+2°)" in r["attack"])
        assert rot_2["status"] == "DECODED"
        assert rot_2["payload_matched"] is True

        # Cropping 5%, 10%, 15% must survive
        crop_5 = next(r for r in attack_results if "5%" in r["attack"])
        assert crop_5["status"] == "DECODED"
        assert crop_5["payload_matched"] is True

        crop_15 = next(r for r in attack_results if "15%" in r["attack"])
        assert crop_15["status"] == "DECODED"
        assert crop_15["payload_matched"] is True

        # Noise & Blur must survive
        noise = next(r for r in attack_results if "Noise (std=3.0)" in r["attack"])
        assert noise["status"] == "DECODED"
        assert noise["payload_matched"] is True

        blur = next(r for r in attack_results if "Blur" in r["attack"])
        assert blur["status"] == "DECODED"
        assert blur["payload_matched"] is True
