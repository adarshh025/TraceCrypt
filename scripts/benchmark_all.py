#!/usr/bin/env python3
"""TraceCrypt Reproducible Offline Benchmark Runner.

Executes offline benchmarks across all core subsystems:
1. Decryption & Watermarking Pipeline (ML-KEM-768, AES-256-GCM, DWT-DCT, ML-DSA-65)
2. Forensic Extraction & Attribution Engine
3. 4-Node BFT Ledger Engine (Consensus, Commit Finality, Mempool, Merkle Proofs)
4. Perceptual Fidelity & Watermark Robustness Matrix (PSNR, SSIM, Attacks)

Outputs machine-readable JSON (`benchmark_results.json`) and formatted terminal tables.
Zero network access. 100% offline and reproducible.
"""

from __future__ import annotations

import json
import os
import platform
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

import numpy as np

# Ensure root repository directory is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
from tracecrypt.crypto.pqc_kem import generate_mlkem_keypair
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.document.attribution_pipeline import (
    RecipientAttributionPipeline,
    RecipientCredentials,
)
from tracecrypt.document.distributor import DistributionService, RecipientSpec
from tracecrypt.document.hasher import DocumentHasher
from tracecrypt.document.key_wrap import KeyWrapEngine
from tracecrypt.document.encryption import ContentEncryption
from tracecrypt.document.release_gate import DocumentReleaseGate
from tracecrypt.event.schema import DecryptionEvent, PQCAlgorithms
from tracecrypt.event.signer import DecryptionEventSigner
from tracecrypt.forensics.engine import ForensicInvestigationEngine
from tracecrypt.forensics.types import ForensicVerdict
from tracecrypt.identity.ca import OfflineRootCA
from tracecrypt.ledger.in_memory_adapter import InMemoryLedgerAdapter
from tracecrypt.ledger.merkle import MerkleTree
from tracecrypt.ledger.types import CommitStatus, LedgerTransactionReceipt
from tests.integration.test_ledger_cluster import create_cluster
from tests.benchmarks.test_ledger_benchmarks import generate_batch_transactions
from tracecrypt.utils.identifiers import (
    DistributionID,
    DocumentID,
    EventID,
    RecipientID,
    SessionID,
    ValidatorID,
    WatermarkID,
)
from tracecrypt.utils.timestamps import utc_now_micros
from tracecrypt.watermark.benchmark import WatermarkBenchmark
from tracecrypt.watermark.embedder import WatermarkEmbedder
from tracecrypt.watermark.extractor import WatermarkExtractor
from tracecrypt.watermark.normalizer import WatermarkNormalizer
from tracecrypt.watermark.types import WatermarkParameters, WatermarkPayload
from tests.integration.test_watermark_pipeline import create_sample_pdf


def run_decryption_benchmark(num_runs: int = 5) -> Dict[str, Any]:
    """Measure recipient decryption, KEM decapsulation, AES-GCM decryption, watermarking, and signing."""
    print("[-] Benchmarking Decryption & Packaging Pipeline...")
    pdf_bytes = create_sample_pdf(num_pages=2)
    doc_hash = DocumentHasher.hash_bytes(pdf_bytes)

    root_ca = OfflineRootCA.initialize(ca_id="ca-benchmark")
    rec_id = RecipientID.generate()
    kem_pk, kem_sk = generate_mlkem_keypair()
    kem_cert = root_ca.issue_kem_certificate(
        subject_id=rec_id,
        public_key=kem_pk,
        organization="Benchmarking Org",
        role="RECIPIENT",
    )
    dsa_pk, dsa_sk = generate_mldsa_keypair()
    dsa_cert = root_ca.issue_signing_certificate(
        subject_id=rec_id,
        public_key=dsa_pk,
        organization="Benchmarking Org",
        role="RECIPIENT",
    )

    creds = RecipientCredentials(
        recipient_id=rec_id,
        kem_private_key=kem_sk,
        kem_certificate=kem_cert,
        dsa_private_key=dsa_sk,
        dsa_certificate=dsa_cert,
    )

    rec_spec = RecipientSpec.from_certificate(kem_cert)
    pkg, _ = DistributionService.package_document(
        source_input=pdf_bytes,
        recipients=[rec_spec],
        root_ca_public_key=root_ca.public_key,
    )

    ledger = InMemoryLedgerAdapter()

    timings: List[float] = []
    for _ in range(num_runs):
        t0 = time.perf_counter()
        release = RecipientAttributionPipeline.execute_decryption(
            package_input=pkg,
            credentials=creds,
            ledger=ledger,
            root_ca_public_key=root_ca.public_key,
            watermark_params=WatermarkParameters(embedding_strength=8.0),
        )
        t_tot = (time.perf_counter() - t0) * 1000.0
        assert release.watermarked_pdf is not None
        assert release.ledger_receipt.status == CommitStatus.COMMITTED
        timings.append(t_tot)

    mean_ms = round(float(np.mean(timings)), 2)
    median_ms = round(float(np.median(timings)), 2)
    p95_ms = round(float(np.percentile(timings, 95)), 2)
    min_ms = round(float(np.min(timings)), 2)
    max_ms = round(float(np.max(timings)), 2)

    return {
        "total_ms": {
            "mean_ms": mean_ms,
            "median_ms": median_ms,
            "p95_ms": p95_ms,
            "min_ms": min_ms,
            "max_ms": max_ms,
        },
        "meets_nfr_004": mean_ms <= 1800.0,
    }



def run_forensic_benchmark(num_pages: int = 2) -> Dict[str, Any]:
    """Measure forensic extraction, normalizer latency, and verification per page."""
    print(f"[-] Benchmarking Forensic Investigation Engine ({num_pages} pages)...")
    pdf_bytes = create_sample_pdf(num_pages=num_pages)
    doc_hash = DocumentHasher.hash_bytes(pdf_bytes)

    res = WatermarkBenchmark.run_performance_benchmark(
        pdf_bytes, doc_hash, params=WatermarkParameters(embedding_strength=8.0)
    )
    return res


def run_ledger_benchmark(num_transactions: int = 25) -> Dict[str, Any]:
    """Benchmark mempool, 4-node consensus finality, Merkle root computation, and storage."""
    print(f"[-] Benchmarking Ledger Consensus & State Persistence ({num_transactions} txs)...")
    import tempfile
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        nodes, genesis, ca = create_cluster(tmp_path, 4)
        tx_batch = generate_batch_transactions(ca, num_transactions)

        for tx, cert in tx_batch:
            nodes[0].mempool.add_transaction(tx)

        # Merkle tree creation benchmark
        tx_bytes = [tx.to_canonical_bytes() for tx, _ in tx_batch]
        t0 = time.perf_counter()
        tree = MerkleTree(tx_bytes)
        root = tree.root_hash
        t_merkle = (time.perf_counter() - t0) * 1000.0

        # Step 4-node BFT consensus round
        t0 = time.perf_counter()
        block = nodes[0].step_consensus_round(peer_nodes=nodes[1:])
        t_commit = (time.perf_counter() - t0) * 1000.0

        for n in nodes:
            n.storage.close()

        tx_count = len(block.transactions) if block else 0
        tps = round(tx_count / (t_commit / 1000.0), 2) if t_commit > 0 else 0.0

        return {
            "transactions_generated": num_transactions,
            "transactions_committed": tx_count,
            "merkle_tree_compute_ms": round(t_merkle, 4),
            "consensus_finality_ms": round(t_commit, 2),
            "measured_python_tps": tps,
            "meets_nfr_006_finality_target": t_commit <= 1000.0,
            "meets_nfr_006_tps_target": tps >= 250.0,
        }


def run_fidelity_and_robustness_benchmark() -> Dict[str, Any]:
    """Measure SSIM, PSNR across embedding strengths and execute attack matrix."""
    print("[-] Benchmarking Perceptual Fidelity & Attack Survivability...")
    pdf_bytes = create_sample_pdf(num_pages=1)
    doc_hash = DocumentHasher.hash_bytes(pdf_bytes)

    # 1. Fidelity across embedding strengths
    fidelity_by_strength = {}
    for st in [4.0, 6.0, 8.0, 10.0, 12.0]:
        p = WatermarkParameters(embedding_strength=st)
        wmid = WatermarkID.generate()
        sid = SessionID.generate()
        payload = WatermarkPayload.create(wmid, sid, doc_hash)
        emb = WatermarkEmbedder.embed_document(pdf_bytes, payload, doc_hash, params=p)
        ext = WatermarkExtractor.extract_document(emb.watermarked_pdf, doc_hash, params=p)
        fidelity_by_strength[str(st)] = {
            "psnr_db": emb.fidelity.psnr,
            "ssim": emb.fidelity.ssim,
            "extraction_status": ext.status.value,
            "meets_psnr_target": emb.fidelity.psnr >= 42.0,
            "meets_ssim_target": emb.fidelity.ssim >= 0.995,
        }

    # 2. Attack matrix at standard strength 10.0
    attack_matrix = WatermarkBenchmark.run_attack_matrix(
        pdf_bytes, doc_hash, params=WatermarkParameters(embedding_strength=10.0)
    )

    return {
        "fidelity_sweep": fidelity_by_strength,
        "attack_matrix": attack_matrix,
    }


def main() -> int:
    """Execute complete reproducible benchmark suite and write results."""
    print("=" * 70)
    print("TraceCrypt — Full-System Offline Reproducible Benchmarks")
    print(f"Host: {platform.node()} ({platform.system()} {platform.release()})")
    print(f"Python: {platform.python_version()} | Architecture: {platform.machine()}")
    print("=" * 70)

    t_all0 = time.perf_counter()

    results: Dict[str, Any] = {
        "metadata": {
            "timestamp": utc_now_micros(),
            "hostname": platform.node(),
            "os": f"{platform.system()} {platform.release()}",
            "python_version": platform.python_version(),
            "architecture": platform.machine(),
            "protocol_version": "1.0.0",
        },
        "decryption_pipeline": run_decryption_benchmark(num_runs=5),
        "forensic_extraction": run_forensic_benchmark(num_pages=2),
        "ledger_consensus": run_ledger_benchmark(num_transactions=50),
        "fidelity_and_robustness": run_fidelity_and_robustness_benchmark(),
    }

    t_total_suite = round(time.perf_counter() - t_all0, 2)
    results["metadata"]["total_benchmark_duration_sec"] = t_total_suite

    out_path = REPO_ROOT / "docs" / "benchmarks" / "benchmark_results.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")

    # Also output to root benchmark_results.json
    (REPO_ROOT / "benchmark_results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")

    print("\n" + "=" * 70)
    print("BENCHMARK EXECUTION SUMMARY")
    print("=" * 70)
    print(f"Decryption Total Mean Latency:   {results['decryption_pipeline']['total_ms']['mean_ms']} ms (Target: <= 1800 ms)")
    print(f"Forensic Extraction Mean / Page: {results['forensic_extraction']['extract_ms_per_page']} ms (Target: <= 3500 ms)")
    print(f"Ledger Consensus Finality:       {results['ledger_consensus']['consensus_finality_ms']} ms (Target: <= 1000 ms)")
    print(f"Ledger Measured Python TPS:      {results['ledger_consensus']['measured_python_tps']} tx/s")
    print(f"Fidelity @ Strength 4.0:         PSNR={results['fidelity_and_robustness']['fidelity_sweep']['4.0']['psnr_db']} dB, SSIM={results['fidelity_and_robustness']['fidelity_sweep']['4.0']['ssim']}")
    print(f"Fidelity @ Strength 10.0:        PSNR={results['fidelity_and_robustness']['fidelity_sweep']['10.0']['psnr_db']} dB, SSIM={results['fidelity_and_robustness']['fidelity_sweep']['10.0']['ssim']}")
    print(f"Attack Matrix Scenarios Tested:  {len(results['fidelity_and_robustness']['attack_matrix'])} attacks")
    print(f"Total Benchmark Duration:        {t_total_suite} seconds")
    print(f"Saved machine-readable results:  {out_path}")
    print("=" * 70)

    return 0


if __name__ == "__main__":
    sys.exit(main())
