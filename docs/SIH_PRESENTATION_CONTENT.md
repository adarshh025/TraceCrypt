# TraceCrypt — Smart India Hackathon 2026 Master Presentation Content

**Event:** Smart India Hackathon 2026 (SIH 2026)  
**Team:** Team Laccha Paratha  
**Team ID:** 138638  
**Problem Statement:** Cryptographic Attribution and Immutable Decryption Provenance for Multi-Recipient Encrypted Document Distribution  
**Problem Statement ID:** SIH26237  
**Team Leader:** Adarsh Aher  
**Team Members:** Adarsh Aher, Kashish, Twinkle Belhekar, Pratibha Kumari, Utkarsh Magar, Akash Rajput  

---

## 1. Executive Summary & Problem Formulation

In high-assurance governmental, defense, and intelligence operations, classified intelligence dossiers, cabinet memoranda, and tactical blueprints are routinely disseminated to multiple authorized recipients. Modern cryptographic standards excel at safeguarding confidentiality **in transit** and **at rest**. 

However, current systems suffer from a fatal operational vulnerability: **the Decryption Horizon**. Once an authorized recipient decrypts a document, traditional cryptographic safeguards terminate. If an authorized recipient leaks the plaintext document, traditional forensics cannot determine which recipient was the source of the leak because all recipients received identical decrypted content.

**TraceCrypt** solves this national security vulnerability by introducing **Immutable Decryption Provenance**:
* Every decryption operation is indivisibly coupled with an invisible, mathematically imperceptible post-quantum spread-spectrum watermark.
* Plaintext is guarded by an **Atomic Release Gate** that prevents document release until the recipient signs a post-quantum decryption event (ML-DSA-65) and obtains a cryptographic commit receipt from a 4-node Byzantine Fault Tolerant (BFT) replicated ledger.
* In the event of a leak, investigators perform **blind forensic extraction**—attributing the document to the exact recipient without requiring the original document and without access to recipient private keys.

---

## 2. Existing Solution Gaps & The Attribution Crisis

| Distribution Vector | Limitation in Sensitive Operations | Security Consequence |
| :--- | :--- | :--- |
| **Traditional Public Key Encryption (PGP, S/MIME)** | Plaintext decrypted on endpoint is completely identical across all recipients. | Zero forensic attribution; leaker possesses complete deniability. |
| **Centralized Cloud DRM (Enterprise Rights Management)** | Requires persistent online connectivity to central license servers; vulnerable to single-point compromise. | Violates air-gap isolation; completely unusable in classified/defense networks. |
| **Visible Overlay Watermarking** | Obtrusive text banners (e.g., "CONFIDENTIAL - ALICE") overlaid across pages. | Easily removed via PDF text stripping, OCR scraping, or simple image cropping. |
| **Centralized Logging Databases** | Central database administrator can modify, delete, or inject audit records. | Subject to insider admin tampering; rejected as conclusive court evidence. |

---

## 3. Core Architectural Innovation

TraceCrypt establishes a trust triangle uniting **Post-Quantum Cryptography**, **Spread-Spectrum Signal Processing**, and **Replicated Consensus**:

1. **Atomic Release Gate:** Eliminates the gap between decryption and auditing. Decryption key material is held in ephemeral memory; if the ledger commit receipt is not obtained, memory is zeroized and no file is ever released.
2. **DWT-DCT Spread-Spectrum Watermarking:** Converts recipient identity, session tag, and document binding into a pseudo-random noise sequence embedded in the 2D discrete wavelet transform domain, achieving high perceptual fidelity (PSNR > 40 dB, SSIM > 0.90).
3. **Byzantine Fault Tolerant Ledger:** Replicates decryption events across 4 independent validator nodes using state-machine replication. Even if one node suffers total Byzantine compromise or hardware failure ($f=1$), the ledger continues committing transactions and maintains complete audit immutability.
4. **Blind Forensic Attribution:** Extracted watermarks are queried against the ledger and validated across Merkle audit paths, quorum certificates, and X.509-style post-quantum certificate chains to deliver a definitive `VERIFIED` legal verdict.

---

## 4. Cryptographic Primitives & NIST Compliance

TraceCrypt strictly implements finalized, production-grade cryptographic standards without experimental shortcuts or synthetic mocks:

* **NIST FIPS 203 (ML-KEM-768):** Post-quantum Module-Lattice Key Encapsulation Mechanism providing IND-CCA2 security against quantum and classical adversaries.
* **NIST FIPS 204 (ML-DSA-65):** Post-quantum Module-Lattice Digital Signature Algorithm providing EUF-CMA existential unforgeability.
* **NIST SP 800-38D (AES-256-GCM):** Authenticated encryption with associated data providing 256-bit symmetric confidentiality and 128-bit authentication tags.
* **NIST FIPS 202 (SHA3-256 & SHAKE-256):** Cryptographic hashing for document binding and extendable-output pseudo-random sequence expansion.

---

## 5. Multi-Recipient Distribution Architecture (`.tcdist`)

The `.tcdist` distribution format is a single, self-contained binary envelope designed for air-gapped transport:
* **Magic Header:** `0x54434450` ("TCDP").
* **Document Metadata:** Document ID, distribution timestamp, source SHA3-256 hash.
* **Encrypted Payload:** AES-256-GCM encrypted document bytes with a 12-byte initialization vector and 16-byte authentication tag.
* **Recipient Envelopes:** $K$ recipient blocks, each containing:
  * Recipient ID (`rcp-...`)
  * Target Certificate Serial Number & Fingerprint
  * ML-KEM-768 Ciphertext encapsulating the 32-byte Document Encryption Key (DEK)
* **Integrity Gate:** Every package undergoes a strict 17-point structural and cryptographic validation upon packaging and prior to decryption.

---

## 6. Atomic Decryption & Spread-Spectrum Watermarking

Watermarking is performed entirely in memory before disk serialization:
1. **Normalization:** The document pages are rendered into 8-bit luminance matrices normalized to exact block boundaries ($16 \times 16$).
2. **Frequency Domain Transformation:** 2D Discrete Wavelet Transform (Haar DWT) decomposes the image into LL, LH, HL, and HH sub-bands, followed by 2D Discrete Cosine Transform (DCT) on the mid-frequency coefficients.
3. **Orthogonal Sequence Modulation:** The 256-bit watermark payload (Watermark ID + Session Tag + Document Hash + Anti-Replay Nonce) is expanded using SHAKE-256 into bipolar pseudo-noise sequences ($\pm 1$) and modulated into the DCT coefficients with dynamic strength parameter $\alpha$.
4. **Empirical Perceptual Verification:**
   * Alice vs. Original Document: **PSNR = 40.59 dB**, **SSIM = 0.9053**
   * Bob vs. Original Document: **PSNR = 40.59 dB**, **SSIM = 0.9053**
   * Human Visual Difference: **Zero** (completely imperceptible to human readers).

---

## 7. Replicated Byzantine Fault Tolerant Consensus Ledger

TraceCrypt features an integrated, pure-Python Byzantine Fault Tolerant consensus engine operating under a PBFT state machine model:
* **Cluster Dimension:** $N = 4$ validator nodes.
* **Fault Tolerance:** Tolerates $f = 1$ Byzantine, malicious, or crashed node ($N \ge 3f + 1$).
* **Quorum Threshold:** $2f + 1 = 3$ votes required for both Prepare and Commit phases.
* **Cryptographic Signatures:** Every vote (PrePrepare, Prepare, Commit) is digitally signed with the validator's ML-DSA-65 private key.
* **Monotonic Persistence:** Each validator maintains an append-only SQLite store with WAL mode, foreign keys, and atomic `.checkpoint` monotonic counter protection to defeat database rollbacks.
* **State Synchronization:** Recovered or lagging nodes execute peer catch-up synchronization by validating Merkle roots and commit certificates back to Genesis.

---

## 8. Blind Forensic Attribution Pipeline

When a leaked document is recovered, the investigator initiates blind attribution:
1. **Zero Prior Knowledge:** The investigator does not need the original document, does not need the document password, and does not have access to recipient private keys.
2. **Signal Extraction:** DWT-DCT blind extraction measures cross-correlation between the image coefficients and the deterministic pseudo-noise dictionary.
3. **Correlation Validation:** If normalized correlation $\tau \ge 4.0$, the 256-bit payload is successfully decoded.
4. **Ledger Resolution:** The extracted Watermark ID is resolved against the BFT ledger, retrieving the block height, transaction root, and signed decryption event.
5. **Multi-Factor Verification:**
   * Merkle audit path proof to Block Header.
   * Commit Certificate quorum signature verification ($2f+1$ valid validator signatures).
   * Recipient ML-DSA-65 digital signature verification against the Root CA.
   * Document hash binding check (proves the event was for this exact document).
6. **Verdict Generation:** Emits a formal verdict (`VERIFIED`, `INCONCLUSIVE`, or `TAMPERED`).

---

## 9. Standalone Evidence Bundles (`.tcproof`)

To satisfy strict evidentiary standards in military tribunals, courts of law, and administrative inquiries:
* TraceCrypt packages all forensic evidence into an immutable, self-contained `.tcproof` bundle.
* The bundle contains:
  * Extracted Watermark Metadata & Correlation Metrics
  * Raw Signed Decryption Event
  * Block Header & 2f+1 Validator Signatures
  * Complete Merkle Audit Path
  * Recipient Identity Certificate Chain
  * Root CA Public Key Anchor
* **Independent Verification:** Any independent examiner on a completely disconnected machine can verify the bundle using:
  ```bash
  tracecrypt verify-bundle LEAK_ATTRIBUTION_PROOF.tcproof --root-ca root_ca.pub
  ```
  with zero network, ledger, or database access required.

---

## 10. Adversarial Threat Model & Security Validations

TraceCrypt was subjected to adversarial red-team testing across 4 core attack vectors:

| Attack Vector | Attacker Action | System Defense | Result |
| :--- | :--- | :--- | :--- |
| **Vector 1: Identity Framing** | Malicious actor modifies `recipient_id` from Alice to Bob while retaining Alice's signature. | Cryptographic signature verification recalculates message digest and validates against claimed certificate. | **REJECTED** (Signature mismatch against subject identity) |
| **Vector 2: Document Binding Mismatch** | Insider attempts to bind valid watermark to a different sensitive document. | Forensic engine recomputes source document hash and compares with event binding. | **REJECTED** (`DOCUMENT_MISMATCH`) |
| **Vector 3: Signature Corruption** | Attacker flips a single byte in the ML-DSA-65 signature envelope. | NIST FIPS 204 verification algorithm detects mathematical inconsistency. | **REJECTED** (`CRYPTOGRAPHIC_SIGNATURE_INVALID`) |
| **Vector 4: Replay Attack** | Insider attempts to re-submit historical decryption event to forge duplicate release. | Ledger verifies anti-replay nonces and transaction unicity in Sparse Merkle Tree. | **REJECTED** (`ReplayAttackError`) |

---

## 11. Watermark Channel Degradation & Empirical Robustness Boundaries

TraceCrypt prioritizes scientific honesty over unsubstantiated marketing claims:
* **Clean Electronic Leak (PDF/lossless):** Normalized correlation $\tau = 6.772$ -> **100% Extraction (Status: DECODED)**.
* **Lossy JPEG Compression ($Q=80$):** Correlation degrades to $\tau = 1.984$ -> **Status: CORRUPTED**.
* **Spatial Downscaling ($0.85\times$):** Correlation degrades to $\tau = 1.798$ -> **Status: CORRUPTED**.
* **Operational Scope:** Designed and optimized for direct electronic exfiltration (email leaks, cloud uploads, removable media copying, endpoint file theft). Print-and-scan and optical camera-capture channels are formally declared out-of-scope for the baseline DWT-DCT transform.

---

## 12. Strict Air-Gap Architecture & Offline Guarantees

TraceCrypt is engineered strictly for air-gapped security enclaves:
* **Zero Socket Calls to External Hosts:** All cluster communication is bound to local loopback (`127.0.0.1`) or direct offline file exchanges.
* **Zero Remote Dependencies:** Contains zero telemetry, zero analytics, zero external NTP queries, and zero cloud KMS integrations.
* **Deterministic Environment Initialization:** Standalone offline Root CA initializes all recipient credentials and genesis block locally.
* **Automated Guard Enforcement:** The `AirGapGuard` subsystem actively audits active network sockets and aborts operations if unauthorized outbound interfaces are detected.

---

## 13. Team Laccha Paratha Engineering Contributions Matrix

| Team Member | SIH Role | Subsystem Architecture & Code Deliverables |
| :--- | :--- | :--- |
| **Adarsh Aher** | Team Leader & Systems Architect | End-to-end architecture, Atomic Release Gate, CLI integration, SIH demo engine, post-quantum PKI orchestration. |
| **Kashish** | Cryptographic Engineer | NIST FIPS 203 ML-KEM-768 encapsulation & NIST FIPS 204 ML-DSA-65 digital signature verification engine. |
| **Twinkle Belhekar** | Distributed Systems Engineer | Byzantine Fault Tolerant (PBFT) consensus state machine, 4-node quorum engine, and state synchronization. |
| **Pratibha Kumari** | Signal Processing Engineer | DWT-DCT spread-spectrum watermarking pipeline, Haar wavelet transform, and perceptual fidelity benchmarks (PSNR/SSIM). |
| **Utkarsh Magar** | Forensic Systems Engineer | Blind watermark extraction algorithm, cross-correlation detector, and `.tcproof` standalone audit bundle exporter. |
| **Akash Rajput** | Security & Ledger Engineer | Sparse Merkle Tree (SMT), append-only SQLite storage engine with monotonic rollback checkpoints, and adversarial red-team test suite. |

---

## 14. Competitive Advantage & Commercial / Defense Viability

* **National Defense Applicability:** Directly addresses leak attribution requirements for Ministry of Defence, intelligence agencies, and diplomatic communications.
* **Zero Vendor Lock-In:** 100% open standards (NIST FIPS 203, 204; AES-GCM; SHA-3; SQLite; pure Python).
* **Cost Efficiency:** Does not require expensive proprietary hardware security modules (HSMs) or enterprise cloud DRM subscriptions.
* **Quantum Readiness:** Fully post-quantum from Day 1; resilient against "harvest now, decrypt later" attacks by foreign quantum adversaries.

---

## 15. Future Roadmap & National Security Impact

1. **Hardware Token Binding:** Integrating PKCS#11 hardware security keys (e.g., indigenous Indian crypto-tokens) for private key storage.
2. **Print-Resistant Hybrid Watermarking:** Researching Fourier-Mellin transform and polar-logarithmic coordinates to extend robustness to physical print-and-scan channels.
3. **OS-Level Decryption Sandboxing:** Packaging the Atomic Release Gate into an isolated micro-VM / secure enclave to protect in-memory decrypted buffers from kernel-level screen capture malware.
