# TraceCrypt v1.0.0 Release Traceability Matrix

**Document Version:** 1.0.0  
**Status:** Certified Release Baseline  
**Scope:** Functional Requirements (FR), Non-Functional Requirements (NFR), Security Requirements (SEC), Implementation Rules (R), and Test Verification (T).

---

## 1. Functional Requirements Traceability (FR-001 to FR-016)

| Req ID | Requirement Description | Implementation Module | Test File / Evidence | Status |
| :--- | :--- | :--- | :--- | :---: |
| **FR-001** | Offline Root CA & Certificate Lifecycle | `tracecrypt/crypto/pki.py` | `tests/unit/test_pki.py` | **PASS** |
| **FR-002** | NIST FIPS 203 ML-KEM-768 Encapsulation | `tracecrypt/crypto/pqc.py` | `tests/unit/test_pqc.py` | **PASS** |
| **FR-003** | NIST FIPS 204 ML-DSA-65 Digital Signatures | `tracecrypt/crypto/pqc.py` | `tests/unit/test_pqc.py` | **PASS** |
| **FR-004** | Document Encryption with AES-256-GCM | `tracecrypt/crypto/symmetric.py` | `tests/unit/test_crypto.py` | **PASS** |
| **FR-005** | Document Packaging (`.tcdist` multi-recipient) | `tracecrypt/distribution/packager.py` | `tests/unit/test_distribution.py` | **PASS** |
| **FR-006** | Secure Recipient Decapsulation & Unwrapping | `tracecrypt/distribution/recipient.py` | `tests/unit/test_distribution.py` | **PASS** |
| **FR-007** | DWT-DCT 2-Level Sub-Band Embedding | `tracecrypt/watermark/engine.py` | `tests/forensics/test_watermark.py` | **PASS** |
| **FR-008** | Reed-Solomon Error Correction Coding | `tracecrypt/watermark/ecc.py` | `tests/unit/test_watermark.py` | **PASS** |
| **FR-009** | Blind Watermark Extraction (No Original Required) | `tracecrypt/forensics/extractor.py` | `tests/forensics/test_extraction.py` | **PASS** |
| **FR-010** | RFC 8785 JSON Canonicalization (JCS) | `tracecrypt/crypto/canonical.py` | `tests/vectors/test_canonical.py` | **PASS** |
| **FR-011** | BFT Consensus Engine ($n=4, f=1$) | `tracecrypt/ledger/consensus.py` | `tests/unit/test_consensus.py` | **PASS** |
| **FR-012** | Immutable Append-Only Ledger & Merkle Trees | `tracecrypt/ledger/store.py` | `tests/unit/test_ledger.py` | **PASS** |
| **FR-013** | 9-State Forensic Verdict Determination | `tracecrypt/forensics/verdict.py` | `tests/unit/test_forensics.py` | **PASS** |
| **FR-014** | Court-Admissible Forensic PDF/JSON Reports | `tracecrypt/forensics/report.py` | `tests/unit/test_forensics.py` | **PASS** |
| **FR-015** | Standalone Portable Evidence Verifier | `tracecrypt/forensics/standalone_verifier.py` | `tests/unit/test_forensics.py` | **PASS** |
| **FR-016** | Comprehensive CLI Interface & Diagnostic Doctor | `tracecrypt/cli/` | `tracecrypt/smoke_test.py` | **PASS** |

---

## 2. Non-Functional Requirements Traceability (NFR-001 to NFR-007)

| Req ID | Requirement Description | Implementation / Enforcement | Verification Evidence | Status |
| :--- | :--- | :--- | :--- | :---: |
| **NFR-001** | Zero External Network Dependencies | Pure offline architecture, `verify_airgap.py` | `scripts/verify_airgap.py` (0 egress) | **PASS** |
| **NFR-002** | Cryptographic Performance (< 1s per page) | Vectorized NumPy/SciPy DWT-DCT | `tests/unit/test_watermark.py` | **PASS** |
| **NFR-003** | Imperceptibility (PSNR > 38 dB, SSIM > 0.98) | High-fidelity luminance embedding | `tests/forensics/test_watermark.py` | **PASS** |
| **NFR-004** | Forensic Robustness against Image Distortions | DWT-DCT + Reed-Solomon ECC | JPEG, blur, rotation tests | **PASS** |
| **NFR-005** | Ledger Fault Tolerance ($f=1$ byzantine failures) | BFT state machine with 3-phase commits | `scripts/bootstrap_four_node_ledger.py`| **PASS** |
| **NFR-006** | Portable Evidence Verification | Zero-dependency standalone verifier module | `tracecrypt.forensics.standalone_verifier`| **PASS** |
| **NFR-007** | Deterministic Cryptographic Builds | Static dependencies, SHA256 & SHA3 manifests | `release/RELEASE_MANIFEST.json` | **PASS** |

---

## 3. Security Requirements Traceability (SEC-001 to SEC-009)

| Req ID | Security Requirement | Implementation Reference | Validation Evidence | Status |
| :--- | :--- | :--- | :--- | :---: |
| **SEC-001** | Post-Quantum Cryptographic Primaries | `MLKEMEngine`, `MLDSAEngine` | NIST KAT vector suites | **PASS** |
| **SEC-002** | Argon2id Key Derivation in Production | `ProductionSecurityProfile` | `tests/security/test_argon2.py` | **PASS** |
| **SEC-003** | Cryptographic Zeroization of Sensitive Buffers | `tracecrypt/crypto/zeroize.py` | `tests/security/test_zeroize.py` | **PASS** |
| **SEC-004** | Air-Gapped Key Custody & Directory Isolation | `deployment/` role-separated trees | `docs/SECURITY.md` | **PASS** |
| **SEC-005** | Non-Repudiation via Hardware/Identity Binding | Canonical `DecryptionEvent` with ML-DSA-65 | `tests/unit/test_forensics.py` | **PASS** |
| **SEC-006** | Merkle Audit Path Integrity | Cryptographic proof generation | `tests/unit/test_ledger.py` | **PASS** |
| **SEC-007** | Certificate Purpose Enforcement (`KeyPurpose`) | `CertificateValidator.validate_purpose` | `tests/unit/test_pki.py` | **PASS** |
| **SEC-008** | Path Traversal & Injection Defense | Strict path sanitization in backup/restore | `tracecrypt/storage/backup.py` | **PASS** |
| **SEC-009** | Dual-Hash Integrity Signatures (SHA256 & SHA3) | Dual digest generation in release manifests | `tools/create_offline_bundle.py` | **PASS** |

---

## 4. Implementation Rules & Technical Constraints (R-001 to R-020)

| Rule ID | Rule Description | Compliance Implementation | Status |
| :--- | :--- | :--- | :---: |
| **R-001** | No runtime telemetry or outbound sockets | AST & runtime socket interception | **COMPLIANT** |
| **R-002** | NIST FIPS 203 ML-KEM-768 for public key encapsulation | Native ML-KEM implementation | **COMPLIANT** |
| **R-003** | NIST FIPS 204 ML-DSA-65 for digital signatures | Native ML-DSA implementation | **COMPLIANT** |
| **R-004** | AES-256-GCM authenticated encryption for documents | Cryptography primitives | **COMPLIANT** |
| **R-005** | Offline PKI hierarchy with role-separated certificates | `PKIEngine` with `KeyPurpose` | **COMPLIANT** |
| **R-006** | Frequency-domain DWT-DCT watermark embedding | Mid-frequency sub-band quantization | **COMPLIANT** |
| **R-007** | Reed-Solomon ECC for forensic robustness | GF($2^8$) Galois field codec | **COMPLIANT** |
| **R-008** | RFC 8785 Canonical JSON Serialization (JCS) | Deterministic UTF-8 byte serialization | **COMPLIANT** |
| **R-009** | Byzantine Fault Tolerant consensus engine | 4-node PBFT with $f=1$ tolerance | **COMPLIANT** |
| **R-010** | Immutable block headers with SHA3-256 hashing | Block header chaining | **COMPLIANT** |
| **R-011** | Merkle transaction inclusion proofs | Complete binary Merkle trees | **COMPLIANT** |
| **R-012** | 9-verdict forensic decision engine | Formally validated decision tree | **COMPLIANT** |
| **R-013** | Standalone zero-dependency evidence verifier | Self-contained verifier entry point | **COMPLIANT** |
| **R-014** | Transactional database schema migrations | `DatabaseMigrationManager` | **COMPLIANT** |
| **R-015** | Verifiable `.tcbackup` archive system | Zip archive with dual-hash manifests | **COMPLIANT** |
| **R-016** | Comprehensive CLI command suite | Typer/Click command definitions | **COMPLIANT** |
| **R-017** | Automated diagnostic health check (`doctor`) | Multi-subsystem validation | **COMPLIANT** |
| **R-018** | End-to-end multi-stage smoke testing | 11-stage smoke test harness | **COMPLIANT** |
| **R-019** | Strict protocol and schema versioning | `tracecrypt/version.py` constants | **COMPLIANT** |
| **R-020** | Offline portable deployment bundle | Packaged wheel dependencies and zip bundles | **COMPLIANT** |

---

## 5. Test Suite Verification Mapping (T1 to T25)

| Test ID | Test Scenario | Verified By | Result |
| :--- | :--- | :--- | :---: |
| **T1** | Root CA generation and X.509 structure | `tests/unit/test_pki.py::test_ca_creation` | **PASS** |
| **T2** | ML-KEM-768 key encapsulation/decapsulation | `tests/unit/test_pqc.py::test_ml_kem_roundtrip` | **PASS** |
| **T3** | ML-DSA-65 signing and verification | `tests/unit/test_pqc.py::test_ml_dsa_roundtrip` | **PASS** |
| **T4** | AES-256-GCM document encryption/decryption | `tests/unit/test_crypto.py::test_symmetric_encryption` | **PASS** |
| **T5** | Multi-recipient package generation (.tcdist) | `tests/unit/test_distribution.py::test_package_creation`| **PASS** |
| **T6** | Recipient decapsulation with invalid key | `tests/unit/test_distribution.py::test_decapsulation_invalid`| **PASS** |
| **T7** | DWT-DCT watermark embedding PSNR/SSIM | `tests/forensics/test_watermark.py::test_fidelity` | **PASS** |
| **T8** | Reed-Solomon bit-flip correction | `tests/unit/test_watermark.py::test_rs_ecc` | **PASS** |
| **T9** | Blind watermark recovery from clean image | `tests/forensics/test_extraction.py::test_clean_extract` | **PASS** |
| **T10** | Watermark extraction under JPEG compression | `tests/forensics/test_extraction.py::test_jpeg_robustness`| **PASS** |
| **T11** | Watermark extraction under Gaussian blur | `tests/forensics/test_extraction.py::test_blur_robustness` | **PASS** |
| **T12** | Watermark extraction under geometric crop | `tests/forensics/test_extraction.py::test_crop_robustness` | **PASS** |
| **T13** | RFC 8785 canonical JSON sorting and floats | `tests/vectors/test_canonical.py::test_rfc8785` | **PASS** |
| **T14** | BFT 4-node consensus round completion | `tests/unit/test_consensus.py::test_bft_round` | **PASS** |
| **T15** | BFT consensus with 1 faulty node ($f=1$) | `tests/unit/test_consensus.py::test_bft_fault` | **PASS** |
| **T16** | Ledger block header hashing and chaining | `tests/unit/test_ledger.py::test_block_chaining` | **PASS** |
| **T17** | Merkle inclusion proof verification | `tests/unit/test_ledger.py::test_merkle_proof` | **PASS** |
| **T18** | Forensic Verdict V1 (Affirmative Attribution) | `tests/unit/test_forensics.py::test_verdict_v1` | **PASS** |
| **T19** | Forensic Verdict V3 (Signature Invalid) | `tests/unit/test_forensics.py::test_verdict_v3` | **PASS** |
| **T20** | Forensic Verdict V4 (Revoked Prior to Event) | `tests/unit/test_forensics.py::test_verdict_v4` | **PASS** |
| **T21** | Forensic Verdict V6 (Watermark Corrupted) | `tests/unit/test_forensics.py::test_verdict_v6` | **PASS** |
| **T22** | Forensic Verdict V7 (Unregistered Watermark) | `tests/unit/test_forensics.py::test_verdict_v7` | **PASS** |
| **T23** | Standalone proof verification from JSON | `tests/unit/test_forensics.py::test_standalone_verifier`| **PASS** |
| **T24** | Automated 11-stage smoke test suite | `tracecrypt smoke-test` | **PASS** |
| **T25** | Complete end-to-end 23-step demonstration | `scripts/demo_full_workflow.py` | **PASS** |
