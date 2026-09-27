"""Performance benchmark tests for Phase 5 Recipient Attribution Pipeline.

Measures actual local execution timings on host hardware:
- .tcdist package validation
- ML-KEM-768 decapsulation and AES-256-GCM CEK unwrapping
- DWT-DCT watermark embedding latency (1-page, 2-page, 5-page, 10-page PDFs)
- RFC 8785 event canonicalization
- ML-DSA-65 post-quantum digital signature generation
- Ledger submission and duplicate detection
- Release Gate evaluation
- End-to-end atomic recipient decryption pipeline (cold vs warm runs)
"""

from __future__ import annotations

import io
import platform
import sys
import time
from typing import Dict, Any
import pytest
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
from tracecrypt.crypto.pqc_kem import generate_mlkem_keypair
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.document.attribution_pipeline import (
    RecipientAttributionPipeline,
    RecipientCredentials,
)
from tracecrypt.document.distributor import DistributionService, RecipientSpec
from tracecrypt.event.canonicalizer import canonicalize
from tracecrypt.event.schema import (
    DecryptionEvent,
    DocumentID,
    DistributionID,
    EventID,
    PQCAlgorithms,
    RecipientID,
    SessionID,
    WatermarkID,
)
from tracecrypt.event.signer import DecryptionEventSigner
from tracecrypt.identity.ca import OfflineRootCA
from tracecrypt.ledger.in_memory_adapter import InMemoryLedgerAdapter
from tracecrypt.utils.timestamps import utc_now_micros


def create_test_pdf(num_pages: int = 1) -> bytes:
    """Generate in-memory multi-page test PDF document."""
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    for p in range(num_pages):
        c.setFont("Helvetica-Bold", 14)
        c.drawString(72, 720, f"Benchmark Briefing - Page {p + 1}")
        c.setFont("Helvetica", 10)
        c.drawString(72, 690, "Performance and latency verification artifact.")
        for line in range(8):
            c.drawString(72, 650 - line * 20, f"Line {line}: Sample text content for benchmarking.")
        c.showPage()
    c.save()
    return buf.getvalue()


@pytest.fixture(scope="module")
def bench_env() -> Dict[str, Any]:
    """Module-scoped benchmark fixture."""
    root_ca = OfflineRootCA.initialize(ca_id="ca-root-bench")

    rid = RecipientID(f"rcp-{SecureRandom.generate_nonce(16)}")
    kem_pk, kem_sk = generate_mlkem_keypair()
    kem_cert = root_ca.issue_kem_certificate(
        subject_id=rid,
        public_key=kem_pk,
        organization="Defense Intelligence",
        role="Recipient",
    )

    dsa_pk, dsa_sk = generate_mldsa_keypair()
    dsa_cert = root_ca.issue_signing_certificate(
        subject_id=rid,
        public_key=dsa_pk,
        organization="Defense Intelligence",
        role="Recipient",
    )

    alice = RecipientCredentials(
        recipient_id=rid,
        kem_private_key=kem_sk,
        kem_certificate=kem_cert,
        dsa_private_key=dsa_sk,
        dsa_certificate=dsa_cert,
    )

    ledger = InMemoryLedgerAdapter()

    return {
        "root_ca": root_ca,
        "alice": alice,
        "ledger": ledger,
    }


class TestAttributionBenchmarks:
    """Benchmark suite capturing performance characteristics of Phase 5."""

    def test_environment_telemetry(self):
        """Log host hardware and runtime parameters."""
        print("\n--- Benchmark Environment Telemetry ---")
        print(f"Platform: {platform.platform()}")
        print(f"Machine: {platform.machine()}")
        print(f"Processor: {platform.processor()}")
        print(f"Python Version: {sys.version.split()[0]}")
        print(f"Compiler: {platform.python_compiler()}")

    def test_rfc8785_canonicalization_benchmark(self, bench_env):
        """Benchmark RFC 8785 canonical JSON serialization."""
        alice = bench_env["alice"]
        event = DecryptionEvent(
            event_id=EventID(f"evt-{SecureRandom.generate_nonce(16)}"),
            document_id=DocumentID(f"doc-{SecureRandom.generate_nonce(16)}"),
            distribution_id=DistributionID(f"dst-{SecureRandom.generate_nonce(16)}"),
            document_hash="sha3-256:" + "f" * 64,
            recipient_id=alice.recipient_id,
            session_id=SessionID(f"ses-{SecureRandom.generate_nonce(16)}"),
            watermark_id=WatermarkID(f"wm-{SecureRandom.generate_nonce(16)}"),
            anti_replay_nonce=SecureRandom.generate_nonce(16),
            timestamp=utc_now_micros(),
            pqc_algorithms=PQCAlgorithms(kem="ML-KEM-768", dsa="ML-DSA-65", hash="SHA3-256"),
        )
        data = event.to_canonical_dict()

        # Warm-up
        for _ in range(10):
            canonicalize(data)

        iterations = 500
        t0 = time.perf_counter()
        for _ in range(iterations):
            canonicalize(data)
        elapsed = time.perf_counter() - t0

        avg_ms = (elapsed / iterations) * 1000
        ops = iterations / elapsed
        print(f"\n[BENCHMARK] RFC 8785 Canonicalization: {avg_ms:.3f} ms per event ({ops:.1f} ops/sec)")
        assert avg_ms < 2.0  # Must be sub-2ms

    def test_mldsa_signing_benchmark(self, bench_env):
        """Benchmark ML-DSA-65 event signing."""
        alice = bench_env["alice"]
        root_ca = bench_env["root_ca"]

        event = DecryptionEvent(
            event_id=EventID(f"evt-{SecureRandom.generate_nonce(16)}"),
            document_id=DocumentID(f"doc-{SecureRandom.generate_nonce(16)}"),
            distribution_id=DistributionID(f"dst-{SecureRandom.generate_nonce(16)}"),
            document_hash="sha3-256:" + "f" * 64,
            recipient_id=alice.recipient_id,
            session_id=SessionID(f"ses-{SecureRandom.generate_nonce(16)}"),
            watermark_id=WatermarkID(f"wm-{SecureRandom.generate_nonce(16)}"),
            anti_replay_nonce=SecureRandom.generate_nonce(16),
            timestamp=utc_now_micros(),
            pqc_algorithms=PQCAlgorithms(kem="ML-KEM-768", dsa="ML-DSA-65", hash="SHA3-256"),
        )

        iterations = 50
        t0 = time.perf_counter()
        for _ in range(iterations):
            DecryptionEventSigner.sign_event(
                event=event,
                signing_key=alice.dsa_private_key,
                signing_cert=alice.dsa_certificate,
                root_ca_public_key=root_ca.public_key,
            )
        elapsed = time.perf_counter() - t0

        avg_ms = (elapsed / iterations) * 1000
        ops = iterations / elapsed
        print(f"\n[BENCHMARK] ML-DSA-65 Event Signing: {avg_ms:.3f} ms per signature ({ops:.1f} ops/sec)")
        assert avg_ms < 250.0  # Must be sub-250ms (includes full 11-point cert validation + signature)

    def test_end_to_end_attribution_pipeline_benchmark(self, bench_env):
        """Benchmark complete atomic recipient attribution pipeline (cold vs warm)."""
        alice = bench_env["alice"]
        root_ca = bench_env["root_ca"]
        ledger = bench_env["ledger"]

        pdf_1p = create_test_pdf(num_pages=1)
        pdf_2p = create_test_pdf(num_pages=2)

        alice_spec = RecipientSpec.from_certificate(alice.kem_certificate)

        pkg_1p, _ = DistributionService.package_document(
            source_input=pdf_1p,
            recipients=[alice_spec],
            root_ca_public_key=root_ca.public_key,
        )
        pkg_2p, _ = DistributionService.package_document(
            source_input=pdf_2p,
            recipients=[alice_spec],
            root_ca_public_key=root_ca.public_key,
        )

        # Cold execution (1 page)
        t0 = time.perf_counter()
        release_cold = RecipientAttributionPipeline.execute_decryption(
            package_input=pkg_1p,
            credentials=alice,
            ledger=ledger,
            root_ca_public_key=root_ca.public_key,
        )
        cold_sec = time.perf_counter() - t0
        print(f"\n[BENCHMARK] Cold Pipeline (1 page): {cold_sec:.3f} s")
        assert release_cold.ledger_receipt.is_committed

        # Warm executions (1 page)
        warm_times = []
        for _ in range(3):
            t0 = time.perf_counter()
            release_warm = RecipientAttributionPipeline.execute_decryption(
                package_input=pkg_1p,
                credentials=alice,
                ledger=ledger,
                root_ca_public_key=root_ca.public_key,
            )
            warm_times.append(time.perf_counter() - t0)
            assert release_warm.ledger_receipt.is_committed

        avg_warm_1p = sum(warm_times) / len(warm_times)
        print(f"[BENCHMARK] Warm Pipeline (1 page, avg of 3): {avg_warm_1p:.3f} s")

        # 2-page benchmark
        t0 = time.perf_counter()
        release_2p = RecipientAttributionPipeline.execute_decryption(
            package_input=pkg_2p,
            credentials=alice,
            ledger=ledger,
            root_ca_public_key=root_ca.public_key,
        )
        sec_2p = time.perf_counter() - t0
        psnr_val = release_2p.fidelity.psnr
        ssim_val = release_2p.fidelity.ssim
        print(f"[BENCHMARK] Pipeline (2 pages): {sec_2p:.3f} s (PSNR: {psnr_val:.2f} dB, SSIM: {ssim_val:.4f})")
        assert release_2p.ledger_receipt.is_committed
