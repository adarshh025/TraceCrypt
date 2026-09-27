# TraceCrypt — System Architecture Reference

**Hackathon:** Smart India Hackathon 2026 (SIH 2026)  
**Team:** Team Laccha Paratha (Team ID: 138638)  
**Problem Statement:** Cryptographic Attribution and Immutable Decryption Provenance for Multi-Recipient Encrypted Document Distribution (`SIH26237`)  

---

## 1. Architectural Overview

TraceCrypt is designed from first principles as an **offline-first, post-quantum forensic security system**. It operates across five interconnected subsystems, maintaining strict boundaries between untrusted client runtimes, replicated consensus validators, and the offline root trust anchor.

```text
+-----------------------------------------------------------------------------------+
|                        1. Offline Post-Quantum PKI Root                           |
|                      (ML-DSA-65 Root CA, CRL, Key Lifecycle)                       |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+------------------------+   +------------------------+   +-------------------------+
|  2. Document Packaging |   | 3. Atomic Release Gate |   | 4. Replicated BFT Ledger|
|  (AES-GCM + ML-KEM-768 |-->| (DWT-DCT Watermarking  |<--| (4-Node PBFT Consensus, |
|   .tcdist Container)   |   |   ML-DSA-65 Event Sig) |   |  Monotonic Storage, SMT)|
+------------------------+   +------------------------+   +-------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                     5. Blind Forensic Investigation Engine                        |
|             (Wavelet Extraction, Merkle Audit Paths, .tcproof Bundle)             |
+-----------------------------------------------------------------------------------+
```

---

## 2. Subsystem Breakdown

### 2.1. Offline Post-Quantum Public Key Infrastructure (PKI)
* **Root Trust Anchor:** `OfflineRootCA` maintains an ML-DSA-65 root signing key, issuing X.509-style post-quantum certificates with custom OIDs for roles (`Recipient`, `Validator`, `Auditor`).
* **Certificate Validation:** Every entity validates incoming certificates across 12 criteria (signature mathematical validity, validity window, key purpose constraint, critical extension validation, and offline CRL revocation).
* **Key Lifecycle:** Managed by `KeyLifecycleManager`, providing pre-expiry rotation and offline revocation stores.

### 2.2. Multi-Recipient Document Packaging (`.tcdist`)
* **Confidentiality:** Documents are symmetrically encrypted using AES-256-GCM under a single ephemeral Document Encryption Key (DEK).
* **Multi-Recipient Key Wrap:** For each authorized recipient $i \in \{1 \dots K\}$, the DEK is encapsulated with their ML-KEM-768 public key:
  $$c_i, K_i = \text{ML-KEM-768.Encaps}(pk_i)$$
  $$\text{Envelope}_i = \text{AES-KeyWrap}(K_i, \text{DEK})$$
* **17-Point Structural Validation:** Pre-distribution checks ensure magic headers, schema versions, recipient unicity, and authenticated ciphertext bounds before packaging is finalized.

### 2.3. The Atomic Release Gate
* **Core Invariant:** Plaintext document data is **never** released to the recipient's file system until after the corresponding decryption event is confirmed committed by the BFT consensus ledger.
* **Pipeline Sequence:**
  1. Decapsulate DEK in ephemeral memory.
  2. Decrypt ciphertext document into protected RAM.
  3. Render document pages into normalized luminance arrays ($16 \times 16$ block grid).
  4. Embed invisible DWT-DCT spread-spectrum watermark encoding recipient identity and session tags.
  5. Sign canonical decryption event schema using recipient ML-DSA-65 private key.
  6. Submit transaction to BFT ledger cluster and wait for commit certificate.
  7. If quorum certificate is verified: persist watermarked PDF to disk. Otherwise: zeroize memory and abort.

### 2.4. Byzantine Fault Tolerant (BFT) Ledger Cluster
* **Consensus Model:** PBFT state-machine replication over $N=4$ nodes, tolerating $f=1$ faulty or malicious node ($N \ge 3f + 1$).
* **Quorum Mechanics:** $2f+1 = 3$ votes required for Prepare and Commit stages.
* **Tamper-Evident Storage:** Each node maintains an append-only SQLite database in WAL mode with monotonic `.checkpoint` height tracking to detect and reject database rollback attacks.
* **Sparse Merkle Tree (SMT):** Maintains state roots and provides binary inclusion proofs for any transaction.

### 2.5. Blind Forensic Investigation Engine
* **Blind Extraction:** Recovers embedded payloads directly from rasterized evidence pages using 2D Haar DWT + DCT cross-correlation without requiring the original source file.
* **Cryptographic Attestation:** Resolves extracted Watermark ID against the ledger, validates Merkle inclusion proofs to block header, and checks recipient ML-DSA-65 signatures against the Root CA.
* **Portable Proof Bundle (`.tcproof`):** Packages all cryptographic evidence into a standalone archive that can be verified on any air-gapped machine without a database.

---

## 3. Architecture Diagrams

Detailed visual sequence and flow diagrams are maintained under `docs/diagrams/`:
* [01 Complete Architecture](../diagrams/01_complete_architecture.md)
* [02 Encryption Packaging](../diagrams/02_encryption_packaging.md)
* [03 Decryption Release Gate](../diagrams/03_decryption_release_gate.md)
* [04 BFT Consensus](../diagrams/04_bft_consensus.md)
* [05 Forensic Investigation](../diagrams/05_forensic_investigation.md)
* [06 Threat Model](../diagrams/06_threat_model.md)
* [07 Trust Boundaries](../diagrams/07_cryptographic_trust_boundaries.md)
