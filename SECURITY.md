# TraceCrypt Security Policy & Vulnerability Reporting

## 1. Scope & Objective
TraceCrypt is designed to operate as an offline, air-gapped forensic document attribution platform. The security architecture relies on NIST post-quantum cryptographic primitives (FIPS 203 ML-KEM-768, FIPS 204 ML-DSA-65), Discrete Wavelet/Cosine Transform spread-spectrum watermarking with Reed-Solomon error correction, RFC 8785 canonical event serialization, and an offline permissioned Byzantine Fault Tolerant distributed ledger.

## 2. Core Security Assumptions & Boundaries

### 2.1 The Attribution Boundary
* **Cryptographic Proof vs. Human Identity:** The system mathematically proves that a registered ML-DSA-65 private key signed a canonical Decryption Event recorded on the permissioned ledger. It **does not prove** biological human identity at the physical keyboard. Human attribution is an operational determination reliant on workstation physical security, passphrase protection, and identity registration integrity.
* **Air-Gap Operational Requirement:** TraceCrypt is designed for zero-trust, isolated networks. Host-level security controls block external network socket creation, but true air-gap assurance relies on physical network isolation.
* **Analog Hole Limitations:** Forensic watermarks survive moderate transformations (JPEG compression $Q \ge 65$, 150 DPI downsampling, $\pm 3^\circ$ rotation, 15% cropping). Extreme physical defacement ($>60\%$ cropping or severe optical blur) triggers `CORRUPTED_WATERMARK` or `UNVERIFIABLE`. The system **never fabricates an attribution**.

## 3. Reporting a Vulnerability

If you discover a potential security flaw, vulnerability, or cryptographic weakness within TraceCrypt:
1. **Do not create public GitHub/GitLab issues.**
2. Prepare a detailed, encrypted report containing:
   * Description of the vulnerability and attack vector (referencing threat model IDs T1–T25 where applicable).
   * Exact reproduction steps or proof-of-concept code.
   * Assessment of impact (confidentiality, attribution integrity, ledger consensus).
3. Deliver the report in-person or via secure, encrypted air-gapped media to the designated Lead Security Architect.
4. Security triage will acknowledge receipt within 48 hours and coordinate remediation following the TraceCrypt Project Contract rules.

## 4. Key Custody & Secrets Policy
* **Zero Hardcoded Secrets:** Private keys, seed phrases, passphrases, and test tokens must never be committed to source control.
* **Encrypted Storage:** Private signing and decapsulation keys must be stored inside Argon2id-encrypted (`m=64MB, t=3, p=4`) + AES-256-GCM containers (`EncryptedKeyContainer`) with RFC 8785 canonical Authenticated Associated Data (AAD) metadata binding.
* **Host Permission Hardening:** Windows filesystem ACLs are restricted using `icacls /inheritance:r /grant:r %USERNAME%:F`.
* **Memory Zeroization Policy:** Plaintext document buffers, ephemeral symmetric keys, and decrypted private key bytes in mutable buffers must be actively overwritten with zeros (`buf[i] = 0`) immediately after operation completion. Pure Python CPython memory allocation limitations are explicitly documented in `docs/security/keystore.md`.
* **Cryptographic Separation:** Under no circumstances may an ML-KEM private key be used for signing, nor may an ML-DSA private key be used for key decapsulation.

## 5. Security Documentation References
* [Post-Quantum Cryptography Specification](file:///C:/TraceCrypt/docs/security/pqc.md)
* [Key Management & Lifecycle](file:///C:/TraceCrypt/docs/security/key-management.md)
* [Offline PKI & Certificate Architecture](file:///C:/TraceCrypt/docs/security/pki.md)
* [Argon2id Keystore & Container Security](file:///C:/TraceCrypt/docs/security/keystore.md)
* [Device Enrollment & Hardware Telemetry](file:///C:/TraceCrypt/docs/security/device-identity.md)
