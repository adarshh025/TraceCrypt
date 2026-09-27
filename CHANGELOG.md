# Changelog

All notable technical changes to the TraceCrypt forensic document attribution platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0-rc1] - 2026-09-27

### Added
- **NIST FIPS 203 Post-Quantum KEM**: Integrated standardized ML-KEM-768 key encapsulation mechanism for multi-recipient document encryption key distribution (`tracecrypt.crypto.pqc_kem`).
- **NIST FIPS 204 Post-Quantum Digital Signatures**: Integrated standardized ML-DSA-65 digital signature provider for Root CA certificate issuance, validator consensus voting, and canonical event attribution signing (`tracecrypt.crypto.pqc_dsa`).
- **Offline Root Certificate Authority**: Air-gapped master identity authority issuing tamper-evident certificates with role-based extensions (RECIPIENT, VALIDATOR, INVESTIGATOR) and 12-point offline verification (`tracecrypt.identity.ca`).
- **Authenticated Document Packaging (.tcdist)**: Versioned binary container implementing AES-256-GCM authenticated encryption, multi-recipient ML-KEM key wrapping, and 17-point structural offline validation (`tracecrypt.document.package`).
- **DWT-DCT Frequency-Domain Watermarking**: Multi-band discrete wavelet transform (Haar DWT) combined with block-level discrete cosine transform (DCT) and Reed-Solomon RS(32,16) forward error correction (`tracecrypt.watermark.embedder`).
- **Deterministic 9-Verdict Forensic Engine**: Centralized canonical verdict state model (`VERIFIED`, `NOT_FOUND`, `INVALID_WATERMARK`, `SIGNATURE_INVALID`, `LEDGER_INVALID`, `DOCUMENT_MISMATCH`, `CORRUPTED_WATERMARK`, `AMBIGUOUS`, `UNVERIFIABLE`) with blind signal extraction and document binding verification (`tracecrypt.forensics.engine`).
- **Portable Cryptographic Proof Bundles (.tcproof)**: Tamper-evident standalone evidence containers embedding canonical event, Merkle inclusion proof, commit certificate, and Root CA certificate chain, verifiable independently (`tracecrypt.forensics.proof_bundle`).
- **Permissioned BFT Distributed Ledger**: 4-node Byzantine fault-tolerant consensus state machine with monotonic block height, parent hash chaining, Merkle tree root commitments, and SQLite WAL persistence (`tracecrypt.ledger.consensus`).
- **Air-Gap Operational Security Guard**: `AirGapGuard` runtime socket interception preventing external DNS, HTTP, HTTPS, or remote network socket calls (`tracecrypt.security.airgap`).
- **System Doctor & Diagnostics**: CLI `tracecrypt doctor` and `tracecrypt validate` diagnostic commands verifying local toolchain, packages, and cryptographic sanity.
- **Reproducible Offline Benchmark Harness**: Automated benchmark suite (`scripts/benchmark_all.py`) measuring decryption latency, forensic extraction throughput, BFT consensus finality, perceptual visual fidelity (PSNR/SSIM), and attack survivability matrix.
- **Offline Windows Deployment Suite**: Automated scripts (`scripts/offline_install.bat`, `scripts/offline_verify.bat`, `scripts/release_gate.bat`) for zero-internet enclave provisioning.

### Changed
- Refined deskew candidate search in watermark extraction to include bidirectional angles and integer rotation candidates, ensuring reliable recovery across rotation distortions.
- Enforced strict package discovery in `pyproject.toml` to prevent setuptools scanning non-code directories.

### Security Hardening
- Replay attack defenses across mempool and consensus state indices.
- Secret zeroization and regex-based redaction filter (`LogFilter`) across all log levels.
- Monotonic disk-level checkpointing preventing SQLite database rollback attacks.
