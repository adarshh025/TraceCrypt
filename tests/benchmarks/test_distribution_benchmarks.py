"""Performance benchmark infrastructure for the Encrypted Document Distribution Subsystem.

Measures actual local execution timings on current host hardware:
- SHA3-256 source document hashing
- Single AES-256-GCM content encryption
- ML-KEM-768 key encapsulation per recipient
- Full .tcdist package creation (1, 5, 10 recipients)
- .tcdist binary serialization
- 17-point offline package validation
- Full recipient decapsulation, unwrapping, decryption, and hash verification
"""

from __future__ import annotations

from pathlib import Path
import time
import pytest

from tracecrypt.crypto.pqc_kem import generate_mlkem_keypair
from tracecrypt.crypto.random import SecureRandom
from tracecrypt.document.distributor import DistributionService, RecipientSpec
from tracecrypt.document.encryption import ContentEncryption
from tracecrypt.document.hasher import DocumentHasher
from tracecrypt.document.key_wrap import KeyWrapEngine
from tracecrypt.document.validator import PackageValidator
from tracecrypt.identity.ca import OfflineRootCA
from tracecrypt.utils.identifiers import DistributionID, RecipientID


@pytest.fixture(scope="module")
def bench_setup():
    """Initialize CA and certified recipient pool for benchmarking."""
    ca = OfflineRootCA.initialize(ca_id="ca-bench-01")

    # Pre-generate 10 recipients
    recipients = []
    for i in range(10):
        rid = SecureRandom.generate_typed_id(RecipientID)
        pk, sk = generate_mlkem_keypair()
        cert = ca.issue_kem_certificate(
            subject_id=str(rid),
            public_key=pk,
            organization="Benchmarking Cell",
            role="RECIPIENT",
            validity_days=30,
        )
        spec = RecipientSpec(
            recipient_id=rid,
            public_key=pk,
            certificate=cert,
            key_id=f"key-bench-{i}-kem",
        )
        recipients.append({"id": rid, "pk": pk, "sk": sk, "cert": cert, "spec": spec})

    doc_64kb = b"%PDF-1.7\n" + (b"A" * 64 * 1024)
    doc_1mb = b"%PDF-1.7\n" + (b"B" * 1024 * 1024)

    return {
        "ca": ca,
        "recipients": recipients,
        "doc_64kb": doc_64kb,
        "doc_1mb": doc_1mb,
    }


def test_benchmark_document_hashing(bench_setup) -> None:
    """Benchmark SHA3-256 document hashing throughput."""
    doc_64kb = bench_setup["doc_64kb"]
    doc_1mb = bench_setup["doc_1mb"]

    # 64 KB
    t0 = time.perf_counter()
    iterations = 20
    for _ in range(iterations):
        DocumentHasher.hash_bytes(doc_64kb)
    t_64kb = (time.perf_counter() - t0) / iterations * 1000  # ms

    # 1 MB
    t0 = time.perf_counter()
    iterations_1mb = 10
    for _ in range(iterations_1mb):
        DocumentHasher.hash_bytes(doc_1mb)
    t_1mb = (time.perf_counter() - t0) / iterations_1mb * 1000  # ms

    print(f"\n[BENCHMARK] SHA3-256 Hash (64 KB): {t_64kb:.3f} ms")
    print(f"[BENCHMARK] SHA3-256 Hash (1 MB):  {t_1mb:.3f} ms")
    assert t_64kb > 0
    assert t_1mb > 0


def test_benchmark_content_encryption(bench_setup) -> None:
    """Benchmark AES-256-GCM content encryption."""
    doc_1mb = bench_setup["doc_1mb"]
    cek = ContentEncryption.generate_cek()
    aad = b"sample_canonical_aad_bytes_for_testing"

    iterations = 20
    t0 = time.perf_counter()
    for _ in range(iterations):
        ContentEncryption.encrypt_document(doc_1mb, cek, aad)
    t_enc = (time.perf_counter() - t0) / iterations * 1000  # ms

    print(f"[BENCHMARK] AES-256-GCM Encrypt (1 MB): {t_enc:.3f} ms")
    assert t_enc > 0


def test_benchmark_mlkem_encapsulation_per_recipient(bench_setup) -> None:
    """Benchmark ML-KEM-768 encapsulation + HKDF + AES-GCM key wrapping."""
    rec = bench_setup["recipients"][0]
    dist_id = SecureRandom.generate_typed_id(DistributionID)
    cek = ContentEncryption.generate_cek()

    iterations = 20
    t0 = time.perf_counter()
    for _ in range(iterations):
        KeyWrapEngine.wrap_cek_for_recipient(
            cek=cek,
            recipient_pk=rec["pk"],
            distribution_id=dist_id,
            recipient_id=rec["id"],
            key_id=rec["spec"].key_id,
            certificate_serial=rec["cert"].serial_number,
        )
    t_wrap = (time.perf_counter() - t0) / iterations * 1000  # ms

    print(f"[BENCHMARK] ML-KEM-768 Encapsulation + CEK Wrap (per recipient): {t_wrap:.3f} ms")
    assert t_wrap > 0


def test_benchmark_package_creation_scaling(bench_setup, tmp_path: Path) -> None:
    """Benchmark complete package creation scaling with 1, 5, and 10 recipients."""
    ca = bench_setup["ca"]
    doc_64kb = bench_setup["doc_64kb"]
    recs = bench_setup["recipients"]

    for count in (1, 5, 10):
        target_recs = [r["spec"] for r in recs[:count]]
        out_file = tmp_path / f"pkg_{count}.tcdist"

        t0 = time.perf_counter()
        pkg, _ = DistributionService.package_document(
            source_input=doc_64kb,
            recipients=target_recs,
            output_path=out_file,
            root_ca_public_key=ca.public_key,
        )
        duration_ms = (time.perf_counter() - t0) * 1000

        label = f"{count} recipient{'s' if count > 1 else ''}"
        print(f"[BENCHMARK] Package Creation ({label}, 64 KB doc): {duration_ms:.3f} ms")
        assert len(pkg.header.recipient_envelopes) == count
        assert out_file.is_file()


def test_benchmark_package_validation(bench_setup, tmp_path: Path) -> None:
    """Benchmark 17-point offline package validation."""
    ca = bench_setup["ca"]
    doc_64kb = bench_setup["doc_64kb"]
    target_recs = [bench_setup["recipients"][0]["spec"]]
    out_file = tmp_path / "bench_val.tcdist"

    DistributionService.package_document(
        source_input=doc_64kb,
        recipients=target_recs,
        output_path=out_file,
        root_ca_public_key=ca.public_key,
    )

    raw_bytes = out_file.read_bytes()
    iterations = 20
    t0 = time.perf_counter()
    for _ in range(iterations):
        PackageValidator.validate(raw_bytes)
    t_val = (time.perf_counter() - t0) / iterations * 1000  # ms

    print(f"[BENCHMARK] 17-Point Package Validation: {t_val:.3f} ms")
    assert t_val > 0


def test_benchmark_recipient_decryption(bench_setup, tmp_path: Path) -> None:
    """Benchmark end-to-end recipient decryption pipeline."""
    ca = bench_setup["ca"]
    doc_64kb = bench_setup["doc_64kb"]
    rec = bench_setup["recipients"][0]
    out_file = tmp_path / "bench_decrypt.tcdist"

    DistributionService.package_document(
        source_input=doc_64kb,
        recipients=[rec["spec"]],
        output_path=out_file,
        root_ca_public_key=ca.public_key,
    )

    iterations = 20
    t0 = time.perf_counter()
    for _ in range(iterations):
        with DistributionService.decrypt_package(
            package_input=out_file,
            recipient_id=rec["id"],
            recipient_sk=rec["sk"],
            recipient_cert=rec["cert"],
            root_ca_public_key=ca.public_key,
        ) as buf:
            assert len(buf.raw_bytes) == len(doc_64kb)
    t_dec = (time.perf_counter() - t0) / iterations * 1000  # ms

    print(f"[BENCHMARK] Full Recipient Decryption (ML-KEM + AES-GCM + Hash Check): {t_dec:.3f} ms")
    assert t_dec > 0
