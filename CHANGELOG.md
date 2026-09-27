# Changelog

All notable changes to the TraceCrypt project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-09-28

### Initial Production Release (Air-Gapped Forensic Document Attribution)

#### Added
- **Post-Quantum Cryptographic Primaries:**
  - NIST FIPS 203 ML-KEM-768 for quantum-resistant key encapsulation and document key wrapping.
  - NIST FIPS 204 ML-DSA-65 for quantum-resistant digital signatures across canonical decryption events.
  - AES-256-GCM authenticated document encryption with unique 96-bit nonces.
  - SHA3-256 and SHA-256 dual cryptographic hashing pipelines.
- **Offline PKI Engine:**
  - Air-gapped Root Certificate Authority with offline key generation and certificate issuance.
  - Strict `KeyPurpose` enforcement (`KEY_ENCAPSULATION`, `DIGITAL_SIGNATURE`, `CA_SIGNING`).
  - CRL generation, revocation tracking, and cryptographic certificate chain validation.
- **Frequency-Domain Forensic Watermarking:**
  - 2-level DWT-DCT luminance-channel embedding algorithm.
  - Reed-Solomon $(N, K)$ error correction coding over $GF(2^8)$ for noise and distortion resilience.
  - High fidelity preservation exceeding 38 dB PSNR and 0.98 SSIM.
  - Blind extraction pipeline operating without access to original un-watermarked documents.
- **Immutable Ledger & BFT Consensus:**
  - Byzantine Fault Tolerant (PBFT) consensus engine supporting $n=4, f=1$ validator nodes.
  - RFC 8785 JSON Canonicalization Scheme (JCS) deterministic event formatting.
  - Cryptographic block header chaining with binary Merkle transaction trees.
  - Merkle inclusion audit path generation and verification.
- **Forensic Attribution Engine:**
  - Formally validated 9-state forensic verdict matrix (`V1` Affirmative Attribution to `V9` Insufficient Evidence).
  - Court-admissible forensic PDF and JSON evidence reports with complete chain of custody.
  - Self-contained portable evidence verifier (`tracecrypt.forensics.standalone_verifier`) executable from offline storage.
- **Production Packaging & Disaster Recovery:**
  - `DatabaseMigrationManager` for transactional SQLite schema versioning.
  - `BackupManager` creating verified `.tcbackup` archives with dual-hash manifests and path-traversal protection.
  - `UpgradeManager` with automated pre-upgrade snapshots, migration application, and rollback.
  - Complete CLI suite with `tracecrypt doctor` and `tracecrypt smoke-test` (11 stages).
  - Role-separated deployment blueprints for CA, Sender, Recipient, Validator, and Investigator.
  - Automated 4-node cluster bootstrapper (`scripts/bootstrap_four_node_ledger.py`).
  - Formal air-gap compliance verifier (`scripts/verify_airgap.py`).
  - End-to-end 23-step demonstration script (`scripts/demo_full_workflow.py`).
  - Portable release zip archives and dual-hash manifests (`release/SHA256SUMS`, `release/SHA3SUMS`).

#### Security
- Zero network egress verified by static AST analysis and dynamic socket interception.
- Strict isolation of private key stores across deployment roles.
- Safe uninstaller preventing unintended data loss of evidence or ledger databases.
- Memory zeroization for sensitive key buffers.
