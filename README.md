# TraceCrypt: Offline Forensic Document Attribution Platform

TraceCrypt is an offline, post-quantum, air-gapped document distribution and forensic attribution platform designed for sensitive and classified operational environments.

---

## Core Capabilities & Security Model

1. **Recipient-Specific Invisible Forensic Watermarking:** Every successful document decryption embeds an invisible, unique watermark bound to the specific recipient and the ephemeral decryption session.
2. **Post-Quantum Cryptography:** Built upon NIST post-quantum cryptographic standards:
   * **NIST FIPS 203 (ML-KEM-768):** Key encapsulation for confidential multi-recipient distribution.
   * **NIST FIPS 204 (ML-DSA-65):** Digital signatures over canonical decryption events.
3. **Cryptographically Signed Decryption Events:** Decryption automatically triggers the construction of a canonical event record adhering to **RFC 8785 (JSON Canonicalization Scheme)**, signed by the recipient's certified ML-DSA-65 private key.
4. **Permissioned Distributed Ledger:** Decryption events are permanently committed to an offline Byzantine Fault Tolerant (BFT) permissioned ledger on the local air-gapped LAN.
5. **Deterministic Forensic Attribution:** When a document leaks, an investigator can extract the watermark blindly, locate the corresponding ledger event, mathematically verify the recipient's signature, and output one of 9 deterministic verdicts.
6. **Zero-Trust Air-Gapped Operation:** Designed to operate completely without internet connectivity, external APIs, cloud KMS, public blockchains, or external certificate authorities.

---

## Architecture Overview

```
[Offline Root CA] ────────► Issues ML-DSA-65 Identity Certificates
                                    │
┌────────────────────────┐          │
│   SENDER WORKSTATION   │          ▼
│ Encrypts Doc (AES-GCM) ├────► [.tcdist Package]
│ Encapsulates (ML-KEM)  │          │
└────────────────────────┘          │
                                    ▼
┌────────────────────────────────────────────────────────┐
│                  RECIPIENT WORKSTATION                 │
│ 1. Decapsulate ML-KEM & Decrypt AES-256-GCM            │
│ 2. Embed DWT-DCT Watermark (RS 32,16 ECC)              │
│ 3. Construct RFC 8785 Canonical DecryptionEvent        │
│ 4. Sign Event with Recipient ML-DSA-65 Private Key     │
│ 5. Commit Transaction to Permissioned Ledger           │
│ 6. Render Document & Zeroize Sensitive Buffers        │
└────────────────────────┬───────────────────────────────┘
                         │
                         ▼
┌────────────────────────────────────────────────────────┐
│            AIR-GAPPED BFT LEDGER (4 NODES)             │
│ Validates Signatures, Nonces, and Merkle State Root    │
└────────────────────────┬───────────────────────────────┘
                         │
                         ▼ (Upon Leakage)
┌────────────────────────────────────────────────────────┐
│           FORENSIC INVESTIGATION WORKSTATION           │
│ 1. Normalize Leaked PDF / Scanned Image                │
│ 2. Blind DWT-DCT Extract Watermark Bitstream           │
│ 3. Reed-Solomon Decode Payload (WatermarkID, DocHash)  │
│ 4. Query Ledger & Retrieve Event + Merkle Proof        │
│ 5. Verify ML-DSA-65 Signature & Cert Validity          │
│ 6. Output 1 of 9 Deterministic Verdicts & Proof Report │
└────────────────────────────────────────────────────────┘
```

---

## Current Status
* [x] **Phase 2: Post-Quantum Identity & Key Management Subsystem:**
  * **NIST FIPS 203 (ML-KEM-768):** Key encapsulation ($pk=1,184\text{B}, sk=2,400\text{B}, c=1,088\text{B}, ss=32\text{B}$) with implicit rejection.
  * **NIST FIPS 204 (ML-DSA-65):** Digital signatures ($pk=1,952\text{B}, sk=4,032\text{B}, \sigma=3,309\text{B}$) with deterministic verification.
  * **Strict Role Separation:** Type-safe separation preventing cross-algorithm key substitution.
  * **Offline Root CA:** Air-gapped trust anchor issuing ML-DSA-65 identity certificates.
  * **PQC Identity Certificates:** Versioned RFC 8785 canonical identity envelopes with 12-point offline validation.
  * **Key Lifecycle & Rotation:** Monotonic state machine preventing un-revocation; key rotation preserving historical event verifiability.
  * **Argon2id Keystore:** Password-derived encryption ($m=64\text{MB}, t=3, p=4$) + AES-256-GCM with canonical AAD metadata binding and Windows `icacls` permission hardening.
  * **Device Enrollment:** Workstation enrollment with hardware telemetry collection.
* [x] **Phase 3: Encrypted Document Distribution Subsystem (.tcdist):**
  * **Single-Content Encryption:** Document encrypted ONCE per distribution using AES-256-GCM with fresh 256-bit CEK and 96-bit nonce.
  * **Multi-Recipient ML-KEM-768 Encapsulation:** Independent encapsulation per recipient, derived via HKDF-SHA256 with strict domain separation.
  * **Deterministic .tcdist Binary Container:** `TCDIST01` header, RFC 8785 canonical metadata AAD binding, SHA3-256 body checksum, and `TCDISTEND` footer.
  * **17-Point Offline Validation Pipeline:** Fail-closed validation verifying dimensions, algorithm parameters, and body checksums before any cryptographic operation.
  * **Controlled In-Memory Decryption:** `SecureDocumentBuffer` with active zeroization preventing unwatermarked document leaks to disk.
* [x] **Phase 4: Robust Forensic Watermark Engine:**
  * **2D Haar DWT + 8x8 Block DCT:** Transform-domain embedding across horizontal (HL) and vertical (LH) mid-frequency bands (zigzag indices 1..10) guaranteeing exact invertibility (MSE < 1e-12).
  * **Bipolar Spread-Spectrum Modulation:** Pseudo-random carrier derived from SHA3-256 seed with spreading gain $L = 264\text{ chips/bit}$. Zero reliance on insecure PRNGs.
  * **Systematic Reed-Solomon RS(32,16) over $\text{GF}(2^8)$:** 2-way interleaved blocks encoding 32-byte payload to 64 bytes (512 bits); corrects up to 16 byte errors (bursts up to 16 bytes).
  * **256-Bit Cryptographic Payload:** Exactly 32 bytes ($1\text{B version} + 16\text{B WatermarkID} + 8\text{B session\_tag} + 5\text{B doc\_binding} + 2\text{B CRC-16}$). Zero plaintext PII.
  * **Blind Extraction & Multi-Page Consistency:** Original document is NOT required for extraction. Cross-page conflict detection triggers fail-closed `AMBIGUOUS` state upon page splicing.
  * **Lossless PDF Re-Assembly:** FlateDecode (zlib) streams guarantee 0.0 pixel quantization distortion.
  * **Performance & Fidelity:** Extraction latency $336.72\text{ ms/page}$ ($\le 3.5\text{s}$ target), $\text{PSNR} \ge 44.33\text{ dB}$, $\text{SSIM} \ge 0.978$.
  * **Quality Gates:** 269 passing tests (100%), 0 flake8 errors, automated robustness attack matrix.
* [x] **Phase 5: Recipient-Side Attribution Pipeline & Signed Decryption Events:**
  * **Atomic Decryption Pipeline:** Strict execution order (`DECRYPT` -> `CREATE SESSION` -> `CREATE UNIQUE WATERMARK` -> `EMBED WATERMARK` -> `BUILD CANONICAL EVENT` -> `SIGN EVENT WITH RECIPIENT ML-DSA-65` -> `SUBMIT LEDGER TX` -> `CONFIRM COMMIT` -> `RELEASE GATE` -> `ZEROIZE`).
  * **Zero Unwatermarked Plaintext Leakage:** Plaintext and recovered CEK are processed strictly in controlled memory buffers and zeroized in `finally:` blocks.
  * **Dynamic Ephemeral Identifiers:** Cryptographically independent 128-bit `SessionID` and `WatermarkID` generated per decryption; no reuse across sessions.
  * **RFC 8785 Canonical DecryptionEvent:** Strongly-typed model serialized deterministically with SHA3-256 event digest and Base64-encoded NIST FIPS 204 ML-DSA-65 digital signature.
  * **Cryptographic Identity Anchor:** Decryption events are signed exclusively by the recipient's authorized private key with strict `KeyPurpose.EVENT_SIGNING` enforcement.
  * **DecryptionEventLedger Protocol & In-Memory Adapter:** Strict ledger interface with anti-replay detection on `EventID`, `SessionID`, `WatermarkID`, and `(DocumentID, SessionID)`.
  * **Centralized DocumentReleaseGate:** Fail-closed gate evaluating watermark integrity, event signature, certificate chain, and ledger finality (`RELEASE_ALLOWED` vs `RELEASE_DENIED`).
  * **CLI & API Integration:** Commands for offline package validation, decryption simulation, event inspection, canonicalization, and verification.
* [x] **Phase 6 / 7: Permissioned Distributed Ledger & BFT Consensus Subsystem:**
  * **4-Node BFT Replicated State Machine:** Fault tolerance $n=4, f=1$, generic quorum $Q = 2f+1 = 3$ votes.
  * **Deterministic Consensus Lifecycle:** Tendermint-inspired round progression (`PROPOSE` -> `PREVOTE` -> `PRECOMMIT` -> `COMMIT`).
  * **Deterministic Genesis & Proposer Selection:** Canonical genesis hash (`tracecrypt:genesis:`) and round-robin proposer selection based purely on height, round, and active validator set.
  * **Cryptographic Identity Separation:** Validator consensus keys (`KeyPurpose.CONSENSUS_VALIDATION`) are cryptographically isolated from recipient signing keys (`KeyPurpose.DIGITAL_SIGNATURE`).
  * **Typed & Replay-Protected Messages:** `VoteMessage` and `CommitCertificate` bind `chain_id`, `height`, `round`, `vote_type`, and `block_hash` under explicit domain separators.
  * **Transaction Pool & Anti-Replay:** Authoritative tracking and deduplication on `EventID`, `SessionID`, `WatermarkID`, and `TransactionID`. Deterministic transaction ordering by `(submitted_at, transaction_id)`.
  * **Binary Merkle Transaction Tree:** Deterministic SHA3-256 Merkle tree committing to `transaction_root`. Standalone $O(\log N)$ inclusion proof generation and independent verification without database access.
  * **Canonical State Root:** Recomputed state roots commit to logical state entries, completely decoupled from physical SQLite storage layouts.
  * **SQLite WAL Storage & Tamper Detection:** Persistence with startup chain verification, cross-verifying raw SQL columns against canonical header commitments to detect database modifications.
  * **State Synchronization Catch-Up Protocol:** Lagging or newly restarted nodes synchronize missing blocks with independent cryptographic verification.
  * **Byzantine Fault Handling:** Conflicting proposals and equivocation trigger `ByzantineFaultDetected` and compile self-authenticating `ByzantineEvidence`.
  * **2+2 Partition Safety:** Network splits prevent conflicting finality; consensus resumes upon partition healing.
  * **100% Air-Gapped LAN Networking:** Length-prefixed framing with SHA3-256 checksums over TCP between configured static peers; zero DNS, external RPC, or cloud dependencies.
  * **CLI & API Integration:** Complete `tracecrypt ledger` commands (`init`, `start`, `status`, `blocks`, `block`, `verify`, `tx`, `event`, `watermark`, `proof`, `validators`) and REST endpoints.
  * **Cluster Runner:** `scripts/run_ledger_cluster.py` provisions and manages local 4-validator deployments.
* [x] **Phase 8: Forensic Investigation Engine, Blind Watermark Extraction & Deterministic Attribution:**
  * **Zero-Knowledge Blind Extraction:** Blind 2D Haar DWT + 8x8 block DCT extraction requiring neither the original document nor candidate recipient keys.
  * **Systematic Reed-Solomon RS(32,16) Recovery:** Complete correction of up to 8 symbol errors in GF(2^8) with 16-bit CRC-16 payload integrity verification.
  * **Multi-Page Consistency & Splice Isolation:** Independent per-page extraction with aggregation detecting conflicting splices and triggering fail-closed `AMBIGUOUS` state.
  * **12-Point Cryptographic Verification Pipeline:** Verification of Merkle inclusion proofs, block header hashes, chain linkage, BFT commit certificate quorum, 11-point offline recipient certificate validity, RFC 8785 canonical event digest matching, NIST FIPS 204 ML-DSA-65 signature mathematical verification, and 40-bit document binding.
  * **Exactly 9 Closed Verdict States:** Strict precedence state machine (`AMBIGUOUS`, `UNVERIFIABLE`, `CORRUPTED_WATERMARK`, `INVALID_WATERMARK`, `NOT_FOUND`, `LEDGER_INVALID`, `SIGNATURE_INVALID`, `DOCUMENT_MISMATCH`, `VERIFIED`). Zero subjective confidence scores or probabilistic heuristic overrides.
  * **Standalone Proof Bundle (.tcproof):** Self-contained cryptographic proof container with SHA3-256 canonical digest verifiable independently via `StandaloneProofVerifier` without workstation database access.
  * **Tamper-Evident Forensic Reporting:** Machine-readable canonical JSON and publication-grade PDF reports with per-page evidence tables and explicit non-repudiation boundary disclosure.
  * **Full Subsystem Integration:** Unified CLI commands (`tracecrypt forensic investigate`, `verify`, `extract`) and FastAPI REST endpoints (`POST /api/v1/forensics/investigate`, `POST /api/v1/forensics/verify-proof`).
  * **Empirical NFR-005 Compliance:** Investigation latency $\le 1.01\text{ s/page}$ on benchmarked 1, 5, and 10-page documents (well under the $\le 3.5\text{ s/page}$ limit).

---

## Quickstart (Development & Testing)

### 1. Environment Verification
```bash
python -m tracecrypt doctor
python -m tracecrypt ca status
```

### 2. Initialize Offline Root CA
```bash
python -m tracecrypt ca init --ca-id "ca-root-01" --passphrase "SecretMasterPass123!"
```

### 3. Generate Post-Quantum Identity & Certificate
```bash
python -m tracecrypt identity generate --owner-id "rcp-agent-alpha" --passphrase "AgentKeyPass123!" --ca-passphrase "SecretMasterPass123!"
```

### 4. Package Encrypted Document (.tcdist)
```bash
# Calculate integrity hash
python -m tracecrypt document hash classified_briefing.pdf

# Package document for authorized recipients
python -m tracecrypt document package \
    --input classified_briefing.pdf \
    --output classified_briefing.tcdist \
    --recipient rcp-agent-alpha

# Validate container offline (17-point verification)
python -m tracecrypt document validate classified_briefing.tcdist

# Inspect recipient envelopes in package
python -m tracecrypt document recipients classified_briefing.tcdist
```

### 5. Forensic Invisible Watermarking
```bash
# Embed forensic watermark (test/dev mode)
python -m tracecrypt watermark embed --input sample.pdf --output sample.watermarked.pdf --strength 8.0

# Blindly extract watermark from leaked document (no original needed)
python -m tracecrypt watermark extract sample.watermarked.pdf

# Run local latency and fidelity benchmark
python -m tracecrypt watermark benchmark

# Execute simulated forensic attack matrix
python -m tracecrypt watermark attack-test
```

### 6. Forensic Investigation & Independent Attribution
```bash
# Blindly investigate leaked artifact against committed BFT ledger
python -m tracecrypt forensic investigate leaked_evidence.pdf \
    --suspect-doc-hash "sha3-256:..." \
    --proof-out case_proof.tcproof \
    --pdf-out forensic_report.pdf

# Verify standalone proof bundle (.tcproof) independently from first principles
python -m tracecrypt forensic verify case_proof.tcproof

# Extract raw watermark payload without ledger verification
python -m tracecrypt forensic extract leaked_evidence.pdf
```

### 7. Run Complete Test Suite & Forensic Benchmarks
```bash
# Run complete forensic investigation test suite
python -m pytest tests/forensics/ -v

# Run full project test suite
python -m pytest
```

---

## Governance & Security Rules

All implementation in this repository is strictly bound by [PROJECT_CONTRACT.md](file:///C:/TraceCrypt/PROJECT_CONTRACT.md) and [SECURITY.md](file:///C:/TraceCrypt/SECURITY.md).
