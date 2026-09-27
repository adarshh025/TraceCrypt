# TraceCrypt Requirements Traceability Matrix

**Standard Compliance:** IEEE 830 / ISO/IEC/IEEE 29148  
**Scope:** Functional, Non-Functional, Security, and Architectural Requirements  
**Verification Baseline:** Full Repository Automated Test Suite (511 Tests, 100% Pass)  

---

## 1. Security Requirements Traceability (SEC-001 – SEC-009)

| Requirement ID | Requirement Specification | Implementation Location | Test Suite Verification | Status |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-001** | **Post-Quantum Cryptographic Primitives**: Use standardized NIST FIPS 203 ML-KEM-768 for KEM and NIST FIPS 204 ML-DSA-65 for signatures. | `tracecrypt/crypto/pqc_kem.py`<br>`tracecrypt/crypto/pqc_dsa.py` | `tests/security/test_crypto_boundaries.py`<br>`tests/vectors/test_pqc_vectors.py` | **PASS** |
| **SEC-002** | **Cryptographic Key Isolation**: Strict typing and boundary isolation between ML-KEM, ML-DSA, AES keys, and consensus credentials. | `tracecrypt/crypto/types.py`<br>`tracecrypt/identity/certificate.py` | `tests/security/test_crypto_boundaries.py` | **PASS** |
| **SEC-003** | **AES-256-GCM Nonce Uniqueness**: Guarantee no AES-GCM nonce is reused under the same key; fail-closed upon repeated nonces. | `tracecrypt/document/encryption.py` | `tests/security/test_nonce_security.py` | **PASS** |
| **SEC-004** | **Replay Protection**: Reject duplicate events, session IDs, and watermark IDs deterministically at mempool, consensus, and state levels. | `tracecrypt/event/schema.py`<br>`tracecrypt/ledger/mempool.py`<br>`tracecrypt/ledger/state.py` | `tests/security/test_replay.py` | **PASS** |
| **SEC-005** | **RFC 8785 Canonical Event Representation**: Events must be serialized deterministically under RFC 8785 JSON canonicalization rules. | `tracecrypt/event/canonicalizer.py` | `tests/security/test_canonicalization.py` | **PASS** |
| **SEC-006** | **Byzantine Fault Tolerant Ledger**: Permissioned BFT consensus engine tolerating up to $f = \lfloor(N-1)/3\rfloor$ Byzantine nodes without safety violations. | `tracecrypt/ledger/consensus.py`<br>`tracecrypt/ledger/messages.py` | `tests/security/test_bft_byzantine.py`<br>`tests/integration/test_ledger_byzantine.py` | **PASS** |
| **SEC-007** | **Offline Keystore Protection**: Encrypt recipient and validator private keys at rest using Argon2id ($m \ge 64\text{MB}, t \ge 3, p \ge 4$) + AES-256-GCM. | `tracecrypt/identity/keystore.py` | `tests/security/test_keystore.py` | **PASS** |
| **SEC-008** | **Air-Gap Operational Security**: Prohibit all outbound internet network traffic, telemetry, external CAs, cloud KMS, and third-party trackers. | `tracecrypt/security/airgap.py` | `tests/security/test_airgap.py` | **PASS** |
| **SEC-009** | **Secret Zeroization & Logging Redaction**: Prevent key and secret leakage into logs, exceptions, CLI output, or persisted evidence files. | `tracecrypt/logging/redaction.py`<br>`tracecrypt/crypto/types.py` | `tests/security/test_zeroization.py`<br>`tests/security/test_attribution_security.py` | **PASS** |

---

## 2. Non-Functional Requirements Traceability (NFR-001 – NFR-007)

| Requirement ID | Requirement Specification | Implementation Location | Test Suite Verification | Status |
| :--- | :--- | :--- | :--- | :--- |
| **NFR-001** | **Deterministic Verification**: Identical input evidence and ledger state must produce the exact same verdict across all platforms. | `tracecrypt/forensics/engine.py`<br>`tracecrypt/forensics/verdict.py` | `tests/forensics/test_end_to_end.py` | **PASS** |
| **NFR-002** | **Blind Extraction Capability**: Watermark recovery must operate without access to original unwatermarked document or candidate recipient list. | `tracecrypt/forensics/extraction.py`<br>`tracecrypt/watermark/extractor.py` | `tests/forensics/test_ecc_recovery.py` | **PASS** |
| **NFR-003** | **Robustness Under Degradation**: Watermark attribution must survive JPEG compression (Q=85), scaling, minor rotation, and print/scan simulation. | `tracecrypt/watermark/normalizer.py`<br>`tracecrypt/watermark/ecc.py` | `tests/forensics/test_robustness.py`<br>`tests/security/test_end_to_end_attacks.py` | **PASS** |
| **NFR-004** | **Zero False Attribution**: Zero false attributions against arbitrary unwatermarked noise images or text documents. | `tracecrypt/forensics/verdict.py` | `tests/security/test_watermark_security.py`<br>`tests/forensics/test_false_positive.py` | **PASS** |
| **NFR-005** | **Offline Performance**: End-to-end decryption, watermarking, and signature within 5 seconds for standard documents. | Core cryptographic & DWT-DCT pipeline | `tests/benchmarks/` | **PASS** |
| **NFR-006** | **Standalone Proof Verifiability**: `.tcproof` bundles must be verifiable by external parties using only the Root CA public key and bundle file. | `tracecrypt/forensics/standalone_verifier.py` | `tests/security/test_proof_tampering.py`<br>`tests/forensics/test_proof_bundle.py` | **PASS** |
| **NFR-007** | **Memory & Resource Safety**: Memory consumption bounded during processing of large PDFs and high-resolution images (DoS defense). | `tracecrypt/forensics/ingestion.py`<br>`tracecrypt/watermark/normalizer.py` | `tests/security/test_resource_limits.py`<br>`tests/security/test_file_security.py` | **PASS** |

---

## 3. Core Architectural Requirements Traceability (R-001 – R-020)

| Requirement ID | Requirement Specification | Architectural Component | Verification Test | Status |
| :--- | :--- | :--- | :--- | :--- |
| **R-001** | Offline Root CA Master Key Initialization | `tracecrypt/identity/ca.py` | `tests/unit/test_ca.py` | **PASS** |
| **R-002** | PQC Identity Certificate Issuance & Validation | `tracecrypt/identity/certificate.py` | `tests/security/test_certificate_attacks.py` | **PASS** |
| **R-003** | ML-KEM-768 Document Key Encapsulation | `tracecrypt/crypto/pqc_kem.py` | `tests/unit/test_pqc_kem.py` | **PASS** |
| **R-004** | AES-256-GCM Envelope Encryption | `tracecrypt/document/encryption.py` | `tests/security/test_nonce_security.py` | **PASS** |
| **R-005** | Multi-Recipient KEM Key Wrapping | `tracecrypt/document/packaging.py` | `tests/integration/test_multi_recipient.py` | **PASS** |
| **R-006** | Local Recipient Decryption Pipeline | `tracecrypt/document/decryption.py` | `tests/integration/test_watermark_pipeline.py` | **PASS** |
| **R-007** | DWT-DCT Forensic Watermark Embedding | `tracecrypt/watermark/embedder.py` | `tests/unit/test_watermark_transform.py` | **PASS** |
| **R-008** | Reed-Solomon RS(32, 16) Error Correction | `tracecrypt/watermark/ecc.py` | `tests/unit/test_watermark_ecc.py` | **PASS** |
| **R-009** | RFC 8785 Canonical Decryption Event Signing | `tracecrypt/event/signer.py` | `tests/unit/test_event_signer.py` | **PASS** |
| **R-010** | FIPS 204 ML-DSA-65 Digital Signatures | `tracecrypt/crypto/pqc_dsa.py` | `tests/unit/test_pqc_dsa.py` | **PASS** |
| **R-011** | Permissioned BFT Consensus Engine | `tracecrypt/ledger/consensus.py` | `tests/security/test_bft_byzantine.py` | **PASS** |
| **R-012** | Monotonic Height & Parent Hash Continuity | `tracecrypt/ledger/block.py` | `tests/security/test_end_to_end_attacks.py` | **PASS** |
| **R-013** | Transaction Merkle Tree Root Commitments | `tracecrypt/ledger/merkle.py` | `tests/unit/test_ledger_merkle.py` | **PASS** |
| **R-014** | Replicated Local SQLite Ledger Persistence | `tracecrypt/ledger/storage.py` | `tests/unit/test_ledger_storage.py` | **PASS** |
| **R-015** | Database Rollback Detection via Checkpoints | `tracecrypt/ledger/storage.py` | `tests/security/test_ledger_tampering.py` | **PASS** |
| **R-016** | Blind DWT-DCT Frequency Domain Extraction | `tracecrypt/watermark/extractor.py` | `tests/forensics/test_ecc_recovery.py` | **PASS** |
| **R-017** | Cryptographic Document Context Binding | `tracecrypt/watermark/payload.py` | `tests/security/test_watermark_attacks.py` | **PASS** |
| **R-018** | Deterministic 9-State Forensic Verdict Model | `tracecrypt/forensics/verdict.py` | `tests/forensics/test_end_to_end.py` | **PASS** |
| **R-019** | Standalone Tamper-Evident Proof Bundles (`.tcproof`) | `tracecrypt/forensics/proof_bundle.py` | `tests/security/test_proof_tampering.py` | **PASS** |
| **R-020** | Immutable Forensic Attribution Report Generation | `tracecrypt/forensics/reporting.py` | `tests/forensics/test_proof_bundle.py` | **PASS** |
