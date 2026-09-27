"""Empirical Performance Benchmarks for TraceCrypt Forensic Investigation Subsystem.

Validates Non-Functional Requirement NFR-005:
    Forensic investigation latency <= 3.5 seconds per page (3500 ms/page).

Measures breakdown for:
- PDF rasterization
- 2D Normalization
- DWT-DCT blind extraction
- Reed-Solomon RS(32,16) ECC decoding
- Replicated offline ledger lookup & Merkle verification
- ML-DSA-65 signature and commit certificate verification
- Forensic publication-grade report generation
"""

from __future__ import annotations

from pathlib import Path
import time
from typing import Tuple

from tests.forensics.conftest import make_test_pdf_bytes
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.event.schema import DecryptionEvent, PQCAlgorithms
from tracecrypt.forensics.engine import ForensicInvestigationEngine
from tracecrypt.forensics.report import ForensicReportGenerator
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
from tracecrypt.watermark.types import WatermarkParameters, WatermarkPayload


def _setup_bench_environment(env, tmp_path: Path, num_pages: int) -> Tuple[Path, str, ForensicInvestigationEngine]:
    storage = env["storage"]
    helper = env["helper"]
    dsa_sk = env["dsa_sk"]
    dsa_cert = env["dsa_cert"]
    root_ca = env["root_ca"]

    pdf_bytes = make_test_pdf_bytes(num_pages=num_pages)
    doc_hash = f"sha3-256:{'aa' * 16}{'bb' * 16}"

    wmid = WatermarkID.generate()
    sid = SessionID.generate()
    payload = WatermarkPayload.create(
        watermark_id=wmid,
        session_id=sid,
        document_hash=doc_hash,
    )

    embed = WatermarkEmbedder.embed_document(
        pdf_input=pdf_bytes,
        payload=payload,
        document_hash=doc_hash,
        params=WatermarkParameters(embedding_strength=8.0),
    )
    leaked_path = tmp_path / f"bench_{num_pages}p.pdf"
    leaked_path.write_bytes(embed.watermarked_pdf)

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

    engine = ForensicInvestigationEngine(
        ledger_storage=storage,
        root_ca_public_key=root_ca.public_key,
    )

    return leaked_path, doc_hash, engine


class TestForensicPerformance:
    """Empirical benchmarking against NFR-005: <= 3.5s per page."""

    def test_benchmark_1_page(self, forensic_environment, tmp_path: Path) -> None:
        """Measure 1-page forensic investigation latency."""
        leaked_path, doc_hash, engine = _setup_bench_environment(forensic_environment, tmp_path, num_pages=1)

        t0 = time.perf_counter()
        inv = engine.investigate(file_path=leaked_path, suspect_document_hash=doc_hash)
        pdf_report = ForensicReportGenerator.generate_pdf_report(inv)
        t_total = time.perf_counter() - t0

        sec_per_page = t_total / 1.0
        print(f"\n[BENCHMARK 1-PAGE] Total: {t_total:.3f}s | Per Page: {sec_per_page:.3f}s | Verdict: {inv.verdict}")

        assert inv.verdict == ForensicVerdict.VERIFIED
        assert sec_per_page <= 3.5, f"1-page latency {sec_per_page:.3f}s exceeds NFR-005 threshold (3.5s)"
        assert len(pdf_report) > 0

    def test_benchmark_5_pages(self, forensic_environment, tmp_path: Path) -> None:
        """Measure 5-page forensic investigation latency."""
        leaked_path, doc_hash, engine = _setup_bench_environment(forensic_environment, tmp_path, num_pages=5)

        t0 = time.perf_counter()
        inv = engine.investigate(file_path=leaked_path, suspect_document_hash=doc_hash)
        pdf_report = ForensicReportGenerator.generate_pdf_report(inv)
        t_total = time.perf_counter() - t0

        sec_per_page = t_total / 5.0
        print(f"\n[BENCHMARK 5-PAGE] Total: {t_total:.3f}s | Per Page: {sec_per_page:.3f}s | Verdict: {inv.verdict}")

        assert inv.verdict == ForensicVerdict.VERIFIED
        assert sec_per_page <= 3.5, f"5-page latency {sec_per_page:.3f}s exceeds NFR-005 threshold (3.5s)"
        assert len(pdf_report) > 0

    def test_benchmark_10_pages(self, forensic_environment, tmp_path: Path) -> None:
        """Measure 10-page forensic investigation latency."""
        leaked_path, doc_hash, engine = _setup_bench_environment(forensic_environment, tmp_path, num_pages=10)

        t0 = time.perf_counter()
        inv = engine.investigate(file_path=leaked_path, suspect_document_hash=doc_hash)
        pdf_report = ForensicReportGenerator.generate_pdf_report(inv)
        t_total = time.perf_counter() - t0

        sec_per_page = t_total / 10.0
        print(f"\n[BENCHMARK 10-PAGE] Total: {t_total:.3f}s | Per Page: {sec_per_page:.3f}s | Verdict: {inv.verdict}")

        assert inv.verdict == ForensicVerdict.VERIFIED
        assert sec_per_page <= 3.5, f"10-page latency {sec_per_page:.3f}s exceeds NFR-005 threshold (3.5s)"
        assert len(pdf_report) > 0
