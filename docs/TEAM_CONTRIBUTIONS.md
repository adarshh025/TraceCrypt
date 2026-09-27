# TraceCrypt — Team Contributions & Subsystem Ownership Matrix

**Event:** Smart India Hackathon 2026 (SIH 2026)  
**Team:** Team Laccha Paratha  
**Team ID:** 138638  
**Problem Statement:** Cryptographic Attribution and Immutable Decryption Provenance for Multi-Recipient Encrypted Document Distribution  
**Problem Statement ID:** SIH26237  

---

## Team Roster & Subsystem Ownership

### 1. Adarsh Aher (Team Leader)
* **Architectural Role:** Chief Architect & End-to-End Systems Integration
* **Primary Subsystem Ownership:**
  * System Architecture & Core Pipelines (`tracecrypt/document/attribution_pipeline.py`, `tracecrypt/document/release_gate.py`)
  * Unified Command-Line Interface (`tracecrypt/cli/main.py`)
  * SIH 2026 Demonstration Engine (`tracecrypt/demo/engine.py`, `scripts/generate_demo_dataset.py`)
  * Air-Gap Security Enforcement (`tracecrypt/security/airgap.py`)
* **Key Technical Deliverables:**
  * Designed the **Atomic Release Gate** protocol ensuring decryption is mathematically contingent upon BFT ledger commitment.
  * Architected the end-to-end multi-recipient document lifecycle (`.tcdist` package format).
  * Authored the CLI demo suite providing automated golden path and adversarial security evaluation.

---

### 2. Kashish
* **Architectural Role:** Post-Quantum Cryptographic Engineer
* **Primary Subsystem Ownership:**
  * Post-Quantum Cryptography Suite (`tracecrypt/crypto/pqc_kem.py`, `tracecrypt/crypto/pqc_dsa.py`)
  * Offline Public Key Infrastructure (`tracecrypt/identity/ca.py`, `tracecrypt/identity/certificate.py`)
  * Cryptographic Key Management & Keystores (`tracecrypt/crypto/types.py`, `tracecrypt/identity/keystore.py`)
* **Key Technical Deliverables:**
  * Integrated **NIST FIPS 203 ML-KEM-768** key encapsulation for multi-recipient confidentiality.
  * Integrated **NIST FIPS 204 ML-DSA-65** post-quantum digital signatures for unforgeable provenance.
  * Implemented the **Offline Root CA** issuing X.509-style post-quantum certificates with custom OIDs and role attributes.

---

### 3. Twinkle Belhekar
* **Architectural Role:** Distributed Systems & Consensus Engineer
* **Primary Subsystem Ownership:**
  * Byzantine Fault Tolerant Consensus Protocol (`tracecrypt/ledger/bft/node.py`, `tracecrypt/ledger/bft/types.py`)
  * Consensus Network & Quorum Verification (`tracecrypt/ledger/bft/network.py`, `tracecrypt/ledger/bft/state.py`)
  * Node State Synchronization (`tracecrypt/ledger/bft/sync.py`)
* **Key Technical Deliverables:**
  * Implemented pure-Python PBFT-style state machine replication across $N=4$ validator nodes.
  * Engineered the $2f+1=3$ quorum collection mechanism for Prepare and Commit consensus phases.
  * Built the block synchronizer enabling lagging or recovered nodes to catch up to the latest ledger state.

---

### 4. Pratibha Kumari
* **Architectural Role:** Signal Processing & Watermarking Engineer
* **Primary Subsystem Ownership:**
  * Spread-Spectrum Signal Processing (`tracecrypt/watermark/embedder.py`, `tracecrypt/watermark/dwt_dct.py`)
  * Perceptual Quality Normalization (`tracecrypt/watermark/normalizer.py`, `tracecrypt/watermark/fidelity.py`)
  * Signal Degradation Benchmark Suite (`tracecrypt/watermark/benchmarks.py`)
* **Key Technical Deliverables:**
  * Formulated the multi-resolution **DWT-DCT** spread-spectrum embedding algorithm on PDF luminance channels.
  * Tuned embedding strength $\alpha$ to achieve verified high fidelity (**PSNR > 40 dB**, **SSIM > 0.90**).
  * Implemented page-level dimension normalization ensuring arbitrary PDF page geometries conform to $16 \times 16$ block grids.

---

### 5. Utkarsh Magar
* **Architectural Role:** Forensic Systems & Evidence Engineer
* **Primary Subsystem Ownership:**
  * Blind Watermark Extractor (`tracecrypt/watermark/extractor.py`)
  * Forensic Investigation Engine (`tracecrypt/forensics/engine.py`, `tracecrypt/forensics/verifier.py`)
  * Standalone Proof Bundle Packaging (`tracecrypt/forensics/proof_bundle.py`)
* **Key Technical Deliverables:**
  * Developed the **blind extraction** pipeline extracting embedded payloads without access to the source document.
  * Formulated normalized cross-correlation decision metrics with confidence thresholding ($\tau \ge 4.0$).
  * Engineered the self-contained `.tcproof` bundle exporter enabling independent judicial audit on air-gapped systems.

---

### 6. Akash Rajput
* **Architectural Role:** Security, Ledger Storage & Red-Team Engineer
* **Primary Subsystem Ownership:**
  * Append-Only Ledger Storage Engine (`tracecrypt/ledger/storage.py`, `tracecrypt/storage/sqlite_store.py`)
  * Sparse Merkle Tree (SMT) & Cryptographic Audit Paths (`tracecrypt/ledger/merkle.py`)
  * Adversarial Security & Red-Team Test Suite (`tests/adversarial/`, `tests/security/`)
* **Key Technical Deliverables:**
  * Built SQLite storage with WAL journaling, foreign keys, and atomic monotonic rollback checkpoints.
  * Implemented Sparse Merkle Trees for cryptographic state root computation and transaction inclusion proofs.
  * Authored adversarial test vectors validating the deterministic rejection of identity framing, signature corruption, and replay attacks.
