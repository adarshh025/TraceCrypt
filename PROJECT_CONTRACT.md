# TraceCrypt Project Contract
**Version: 1.0.0 — Binding Engineering Specification**

This contract is the authoritative source of truth for all engineering, architectural, and implementation phases of **TraceCrypt**. All contributors and subsequent implementation prompts must strictly adhere to these rules.

---

### 1. Architectural Rules
* **R-001 (Zero External Connectivity):** No component shall initiate or depend upon network connections outside the local air-gapped subnet (`127.0.0.1` or designated private LAN range). Any import or call that makes external DNS or HTTP/HTTPS requests is strictly prohibited.
* **R-002 (Strict Separation of Concerns):** Cryptographic operations, watermark transformations, document parsing, event serialization, and ledger consensus must reside in isolated modules communicating exclusively via strongly typed interfaces and data classes.
* **R-003 (Deterministic State Machine):** All ledger transitions, canonical event hashes, and verification verdicts must be 100% deterministic and reproducible across platforms.

### 2. Cryptographic Rules
* **R-004 (Standardized PQC Primitives):** Key encapsulation must use NIST FIPS 203 ML-KEM-768. Digital signatures must use NIST FIPS 204 ML-DSA-65. No proprietary or unstandardized cryptographic algorithms may be introduced.
* **R-005 (Cryptographic Separation):** Keys used for ML-KEM encapsulation must never be repurposed for digital signatures. AES-256-GCM encryption keys must be ephemeral and derived via HKDF-SHA256.
* **R-006 (Zeroization):** Plaintext document buffers, ephemeral symmetric keys, and decrypted private key material must be explicitly overwritten with zeros (`b"\x00" * len(buf)`) immediately after use in a `finally:` block.
* **R-007 (Hardcoded Secrets Prohibited):** No private keys, master passphrases, or test tokens may be committed to source code or configuration files.

### 3. Watermarking Rules
* **R-008 (Transform-Domain Only):** Watermark embedding must be performed in the frequency transform domain (DWT-DCT). LSB, metadata-only, visible overlays, or single-character steganography are strictly prohibited.
* **R-009 (Perceptual Threshold):** Embedded documents must maintain SSIM $\ge 0.995$ and PSNR $\ge 42.0$ dB relative to the rendered original document.
* **R-010 (Error Correction Mandate):** Watermark bitstreams must incorporate Reed-Solomon Forward Error Correction capable of correcting at least 8 symbol errors per block.
* **R-011 (PII Exclusion):** Raw personally identifiable information (names, emails, SSNs) must never be encoded directly into the watermark payload. Only cryptographic hashes and random identifiers are permitted.

### 4. Ledger & Event Rules
* **R-012 (No Toy Blockchains):** Ledger records must be validated through multi-node consensus with Byzantine fault tolerance and cryptographic state hashing. A single administrator-controlled database table does not constitute a valid ledger.
* **R-013 (RFC 8785 Canonicalization):** Decryption events must be serialized strictly using the RFC 8785 JSON Canonicalization Scheme prior to signature generation or verification.
* **R-014 (Anti-Replay Enforcement):** The ledger must reject any transaction featuring an existing `WatermarkID` or duplicate `(DocumentID, SessionID)` combination.

### 5. Forensic Attribution Rules
* **R-015 (Independent Mathematical Verification):** The forensic verifier must never rely on unverified database lookups. It must independently verify the extracted watermark, the ML-DSA-65 signature, the certificate chain, the ledger Merkle proof, and the original document hash.
* **R-016 (Explicit Verdict Boundaries):** Forensic outputs must strictly conform to the 9-verdict enum (`VERIFIED`, `NOT_FOUND`, `INVALID_WATERMARK`, `SIGNATURE_INVALID`, `LEDGER_INVALID`, `DOCUMENT_MISMATCH`, `CORRUPTED_WATERMARK`, `AMBIGUOUS`, `UNVERIFIABLE`). If evidence is degraded or ambiguous, the system must return `CORRUPTED_WATERMARK`, `AMBIGUOUS`, or `UNVERIFIABLE`. False attribution is classified as a critical system failure.
* **R-017 (Immutable Audit Proof):** All forensic findings must compile into a self-contained cryptographic proof bundle capable of being audited by an independent third party with standard command-line tools.

### 6. Coding & Quality Rules
* **R-018 (Strict Type Annotations):** All Python code must utilize complete type hints (`typing` / Pydantic v2). Code must pass strict static analysis without type errors.
* **R-019 (Fail-Closed Exception Handling):** Cryptographic verification failures must immediately raise explicit exceptions. Silent failures, fallback to unverified states, or debug bypasses are strictly forbidden.
* **R-020 (Empirical Test Verification):** No benchmark or performance metric may be claimed without executable tests generating verifiable numbers on the local hardware.
