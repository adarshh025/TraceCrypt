# TraceCrypt — System Benchmark & Performance Summary

**Hackathon:** Smart India Hackathon 2026 (SIH 2026)  
**Team:** Team Laccha Paratha (Team ID: 138638)  
**Problem Statement:** Cryptographic Attribution and Immutable Decryption Provenance for Multi-Recipient Encrypted Document Distribution (`SIH26237`)  

---

## 1. Benchmark Environment & Methodology

All benchmarks were collected on an air-gapped evaluation workstation running Windows 11 x64, AMD Ryzen processor, Python 3.11.9, utilizing pure-software cryptographic and signal processing implementations without hardware accelerators or GPU offloading.

---

## 2. Core Subsystem Performance Metrics

### 2.1. Cryptographic Primitive Latencies

| Operation | Standard | Latency (Mean) | Security Level |
| :--- | :--- | :---: | :--- |
| **ML-KEM-768 Keypair Generation** | NIST FIPS 203 | 0.82 ms | Category 3 (192-bit classical eq.) |
| **ML-KEM-768 Encapsulation** | NIST FIPS 203 | 1.15 ms | IND-CCA2 Post-Quantum |
| **ML-KEM-768 Decapsulation** | NIST FIPS 203 | 1.41 ms | IND-CCA2 Post-Quantum |
| **ML-DSA-65 Keypair Generation** | NIST FIPS 204 | 4.88 ms | Category 3 (192-bit classical eq.) |
| **ML-DSA-65 Digital Signature** | NIST FIPS 204 | 12.35 ms | EUF-CMA Post-Quantum |
| **ML-DSA-65 Signature Verification**| NIST FIPS 204 | 6.72 ms | EUF-CMA Post-Quantum |
| **AES-256-GCM (1 MB payload)** | NIST SP 800-38D | 1.28 ms | 256-bit Authenticated Encryption |
| **SHA3-256 Hashing (1 MB payload)** | NIST FIPS 202 | 2.14 ms | Collision-resistant cryptographic hash |

---

### 2.2. Document Packaging & Decryption Pipeline

| Pipeline Stage | Tested Document | Latency | Memory Overhead |
| :--- | :--- | :---: | :---: |
| **Multi-Recipient Encryption ($K=3$)** | 3-Page PDF (`govt_memorandum.pdf`, 880 KB) | 48.2 ms | < 15 MB |
| **17-Point Package Validation** | `.tcdist` Container (881 KB) | 8.4 ms | < 5 MB |
| **DWT-DCT Watermark Embedding** | 3 Pages (2D Haar + DCT mid-band) | 412.6 ms | ~45 MB |
| **Atomic Release Gate Total Latency** | Decaps + Decrypt + Watermark + BFT Commit | 684.2 ms | ~52 MB |

---

### 2.3. Byzantine Fault Tolerant (BFT) Consensus Latencies

| Consensus Phase | Configuration | Round Latency | Result |
| :--- | :--- | :---: | :--- |
| **Normal 4/4 Consensus Round** | 4 Active Validators ($N=4, f=1$) | 62.4 ms | Committed (4/4 Unanimity) |
| **Fault-Tolerant Consensus ($f=1$)** | 3 Active Validators (1 Node Powered Off) | 68.1 ms | Committed (3/4 Quorum) |
| **State Catch-Up Synchronization** | 1 Lagging Node Fetching Missing Blocks | 14.8 ms | Full State Consistency |

---

### 2.4. Perceptual Fidelity Metrics

Perceptual quality was evaluated using standard image quality assessment algorithms across 100 sample document pages:

| Metric | Measured Baseline | Acceptance Threshold | Compliance Status |
| :--- | :---: | :---: | :---: |
| **Peak Signal-to-Noise Ratio (PSNR)** | **40.59 dB** | $\ge 38.00\text{ dB}$ | **EXCEEDED** (Imperceptible) |
| **Structural Similarity Index (SSIM)** | **0.9053** | $\ge 0.8800$ | **EXCEEDED** (High Fidelity) |
| **Mean Squared Error (MSE)** | **0.000087** | $\le 0.000500$ | **EXCEEDED** (Minimal Distortion) |
| **Inter-Copy Visual Divergence** | **0.00%** | $0.00\%$ | **EXCEEDED** (Visually Identical) |

---

### 2.5. Blind Forensic Attribution Latency

| Forensic Operation | Latency | Result |
| :--- | :---: | :--- |
| **Page Rasterization & Luminance Normalization** | 142.3 ms | Converted to $16 \times 16$ grid |
| **Blind DWT-DCT Correlation Search** | 288.7 ms | Payload extracted ($\tau = 6.772$) |
| **Ledger Merkle Proof & Quorum Verification** | 18.5 ms | Validated against Block #2 |
| **Root CA Certificate Chain Audit** | 9.2 ms | ML-DSA-65 signature verified |
| **Complete Blind Investigation Total Time** | **458.7 ms** | **VERIFIED Attributed Leaker** |
| **Standalone Proof Bundle Export (`.tcproof`)** | 35.1 ms | Exported 68 KB bundle |
