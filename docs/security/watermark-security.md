# Forensic Watermark Security Architecture

## 1. Security Guarantees & Principles

### 1.1 Zero Plaintext PII
The forensic watermark payload embeds zero plaintext personal identities:
- No names, email addresses, employee IDs, department names, or workstation hostnames.
- The payload contains only cryptographically derived identifiers: `WatermarkID` (128-bit CSPRNG), `session_tag` (64-bit derived hash), and `document_binding` (40-bit domain-separated token).
- Leaked documents reveal no identity directly from visual or frequency analysis. Final attribution is possible only by an authorized forensic investigator with access to the cryptographically signed ledger decryption records.

### 1.2 Ephemeral Session Uniqueness
- Every decryption operation generates a fresh 128-bit `WatermarkID` and `SessionID`.
- If the same recipient decrypts the same document 10 times, 10 distinct, non-overlapping watermarks are generated.
- Prevents cross-session watermark replay and enables pinpointing the exact leaked file revision.

### 1.3 Cryptographic Document Binding
The embedded 40-bit binding token enforces document association:
$$\text{Binding} = \text{SHA3-256}(\text{"TraceCrypt-Watermark-Binding:"} \parallel \text{DocHash} \parallel \text{SessionID} \parallel \text{WatermarkID})[:5]$$
If an adversary extracts a watermark from Document A and attempts to graft it onto Document B, the binding token does not match Document B's SHA3-256 hash. The forensic verification engine flags this as a cryptographic mismatch.

### 1.4 Fail-Closed Extraction
The blind extractor implements strict fail-closed state machines:
- **Random noise or unwatermarked images** produce low correlation ($\text{corr} < 1.0$) and fail Reed-Solomon parity checks $\to$ `NOT_DETECTED` or `CORRUPTED`.
- **Mismatched Document Hashes** yield orthogonal pseudo-random carrier sequences with zero correlation $\to$ `NOT_DETECTED`.
- The extractor **never invents an attribution** or returns a random WatermarkID.

---

## 2. Multi-Page Forensic Integrity

### 2.1 Independent Page Attestation
In multi-page documents, every page carries the full 512-bit watermark codeword. This ensures that:
- Leaking a single torn or photographed page allows complete forensic attribution.
- Redundant evidence across multiple pages increases attribution confidence.

### 2.2 Splicing & Collage Attack Detection
If an adversary splices pages from different recipients or decryption sessions into a composite document:
1. The extractor analyzes every page independently.
2. If Page 1 decodes to `WatermarkID_A` and Page 2 decodes to `WatermarkID_B`, the extractor detects conflicting identifiers.
3. The extractor returns `ExtractionStatus.AMBIGUOUS` with the full list of distinct IDs in diagnostics.
4. The system refuses to arbitrarily select one watermark, preventing malicious frame-ups or spoofed single-page attribution.

---

## 3. Strict Air-Gap & Cryptographic Randomness

- **Zero Network Operations**: All transform, embedding, normalization, and extraction logic is 100% self-contained and operates within the offline air-gap boundary. Network sockets are strictly blocked by `AirGapGuard`.
- **Approved Randomness**: All random seeds and identifiers originate from `tracecrypt.crypto.random.SecureRandom`, utilizing `secrets` / `os.urandom()`. Standard non-cryptographic PRNGs (`random.random()`, `numpy.random`) are prohibited for key or ID generation.
