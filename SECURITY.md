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
* **Document Distribution Security Policy:**
  * **Single-Content Encryption:** Bulk document content is encrypted once using AES-256-GCM with a fresh 256-bit CEK and 96-bit nonce. Bulk re-encryption per recipient is forbidden.
  * **Independent PQC Envelopes:** The CEK is encapsulated independently per authorized recipient using NIST FIPS 203 ML-KEM-768.
  * **Cryptographic AAD Binding:** Package metadata (`document_id`, `distribution_id`, `recipient_set_digest`, `source_document_hash`, `cipher_algorithm`, `format_version`) is canonicalized via RFC 8785 and authenticated by the AES-GCM tag.
  * **Post-Decryption Plaintext Verification:** Decrypted plaintext is verified against the original SHA3-256 `source_document_hash`. Mismatch immediately zeroizes the buffer and fails closed.
  * **No Direct Persisted Plaintext:** Decryption returns an in-memory `SecureDocumentBuffer`; unwatermarked plaintext is never persisted to disk.

* **Forensic Watermarking Security Policy:**
  * **Transform-Domain Only:** Watermarking operates strictly in 2D Haar DWT + 8x8 block DCT frequency domain. LSB and metadata watermarking are strictly forbidden.
  * **Zero Raw PII:** Payloads contain only 128-bit CSPRNG identifiers, truncated session tags, and cryptographic binding tokens. Raw names, emails, and phone numbers are strictly excluded.
  * **Cryptographic Document Binding:** Watermark is cryptographically bound to the source document SHA3-256 hash via a domain-separated token. Mismatched documents fail closed.
  * **Multi-Page Consistency:** Conflicting watermark IDs across document pages trigger `AMBIGUOUS` status. The system never arbitrarily attributes a spliced document.

* **Recipient Decryption Attribution & Release Gate Policy:**
  * **Dynamic Ephemeral Watermarks:** Watermarks are created strictly at decryption time. Reusing a watermark across sessions or generating static watermarks during packaging/enrollment is prohibited.
  * **Unwatermarked Release Prohibition:** Unwatermarked plaintext documents must NEVER be released to the recipient or persisted to disk.
  * **NIST FIPS 204 ML-DSA-65 Signing:** Decryption events are signed using the recipient's private key. Roots of trust, server keys, or administrator keys must never sign recipient events.
  * **RFC 8785 Canonical Serialization:** Events are canonicalized via RFC 8785 and hashed via SHA3-256 before signature generation. Signatures over non-canonical JSON are invalid.
  * **Fail-Closed Release Gate:** `DocumentReleaseGate` permits release only when watermark embedding succeeds, the event signature is valid, the certificate chain is verified, and the ledger confirms final commitment.
  * **Active Buffer Zeroization:** Raw plaintext buffers and recovered CEK are zeroized in `finally:` blocks.

## 5. Security Documentation References
* [Post-Quantum Cryptography Specification](file:///C:/TraceCrypt/docs/security/pqc.md)
* [Key Management & Lifecycle](file:///C:/TraceCrypt/docs/security/key-management.md)
* [Offline PKI & Certificate Architecture](file:///C:/TraceCrypt/docs/security/pki.md)
* [Argon2id Keystore & Container Security](file:///C:/TraceCrypt/docs/security/keystore.md)
* [Device Enrollment & Hardware Telemetry](file:///C:/TraceCrypt/docs/security/device-identity.md)
* [Document Content Encryption & AAD Binding](file:///C:/TraceCrypt/docs/security/document-encryption.md)
* [Multi-Recipient Post-Quantum KEM](file:///C:/TraceCrypt/docs/security/multi-recipient-kem.md)
* [17-Point Package Validation Pipeline](file:///C:/TraceCrypt/docs/security/package-validation.md)
* [Forensic Watermark Security Architecture](file:///C:/TraceCrypt/docs/security/watermark-security.md)
* [Forensic Watermark Threat Model & Limitations](file:///C:/TraceCrypt/docs/security/watermark-threats.md)
* [Attribution Boundary & Legal Semantics](file:///C:/TraceCrypt/docs/security/attribution-boundary.md)
* [Centralized Document Release Gate](file:///C:/TraceCrypt/docs/security/release-gate.md)
* [Post-Quantum Event Signing & Verification](file:///C:/TraceCrypt/docs/security/event-signing.md)

