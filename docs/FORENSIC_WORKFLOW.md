# TraceCrypt Forensic Investigation Workflow & Attribution Guide

**Document Version:** 1.0.0  
**Security Classification:** Air-Gapped / Forensic Operations  
**Compliance Baseline:** NIST FIPS 203 (ML-KEM-768), NIST FIPS 204 (ML-DSA-65), RFC 8785 (JCS), ISO/IEC 27037:2012  

---

## 1. Overview and Chain of Custody

The TraceCrypt Forensic Attribution Engine is designed to identify the exact recipient responsible for leaking a protected digital document while preserving strict mathematical verifiability and chain of custody.

```
+------------------+     +-------------------+     +--------------------+
|  Leaked Document | --> |   Normalization   | --> |  Blind Extraction  |
| (PDF/PNG/TIFF)   |     |    & Denoising    |     |  DWT-DCT Sub-bands |
+------------------+     +-------------------+     +--------------------+
                                                              |
                                                              v
+------------------+     +-------------------+     +--------------------+
| Court-Admissible | <-- |  9-Verdict Matrix | <-- | Ledger Lookup &    |
| Evidence Package |     | Mathematical Proof|     | Cryptographic Proof|
+------------------+     +-------------------+     +--------------------+
```

The process operates under the assumption of an adversarial environment where:
- Leaked documents may have undergone downscaling, JPEG compression, blurring, cropping, rotation, or contrast adjustment.
- Malicious actors may claim false positives or spoofed identities.
- Verification must succeed in an isolated, air-gapped forensic lab without contacting active distribution nodes.

---

## 2. Evidence Intake & Normalization

Forensic document intake requires preserving initial file metadata and bit-for-bit forensic integrity before any analysis:

1. **Intake Hashing:** Calculate SHA-256 and SHA3-256 of the raw leaked file.
2. **Page Rasterization:** Render input document pages (PDF/raster) to 300 DPI raw luminance arrays ($Y$-channel of $YC_bC_r$).
3. **Geometric Correction:** Apply automated deskewing (Hough transform) and boundary alignment.
4. **Resolution Normalization:** Rescale to the canonical embedding dimensions ($1024 \times 1024$ minimum block alignment).

---

## 3. Blind Frequency-Domain Extraction (DWT-DCT)

TraceCrypt performs **blind extraction**—the original un-watermarked document is never required during forensic recovery:

1. **Discrete Wavelet Transform (DWT):**
   - 2-level 2D Haar or Daubechies wavelet decomposition.
   - Target sub-band: $LL_2$ or mid-frequency sub-bands ($LH_1, HL_1$) chosen during embedding.
2. **Block-Based Discrete Cosine Transform (DCT):**
   - Partition sub-band into $8 \times 8$ pixel blocks.
   - Extract quantized middle-frequency DCT coefficient pairs: $(u_1, v_1)$ and $(u_2, v_2)$.
3. **Differential Demodulation:**
   - For each block $k$, decode embedded bit $\hat{b}_k$:
     $$\hat{b}_k = \begin{cases} 1 & \text{if } C(u_1, v_1) > C(u_2, v_2) \\ 0 & \text{otherwise} \end{cases}$$
4. **Reed-Solomon Error Correction:**
   - Decode raw bitstream using Reed-Solomon $(N, K)$ decoder over $GF(2^8)$.
   - Correct bit-flips introduced by lossy compression, printing, or photographic capture.
   - Output: 32-byte canonical `WatermarkPayload`.

---

## 4. Ledger Cross-Referencing & Cryptographic Proof Verification

Once the `watermark_id` is extracted from the decoded payload:

1. **State Store Query:** Query the local verified ledger replica for a committed `DecryptionEvent` where `event.watermark_id == extracted_watermark_id`.
2. **Merkle Audit Trail:**
   - Locate the containing block height $h$ in the immutable ledger.
   - Verify the Merkle inclusion proof from the transaction root to the canonical `DecryptionEvent` hash.
3. **Post-Quantum Signature Verification:**
   - Retrieve the recipient's public key from their X.509-compliant certificate.
   - Verify the **NIST FIPS 204 ML-DSA-65** digital signature across the RFC 8785 canonical JSON bytes of the `DecryptionEvent`.
4. **Certificate Validity Check:**
   - Verify certificate chain up to the offline Root CA.
   - Validate `KeyPurpose.DIGITAL_SIGNATURE`.
   - Validate certificate validity window and check revocation status in the local CRL/revocation ledger.

---

## 5. The 9-State Forensic Verdict Matrix

Every forensic evaluation produces one of nine mathematically defined verdicts:

| Verdict Code | Verdict Name | Technical Condition | Evidentiary Status |
| :--- | :--- | :--- | :--- |
| `V1` | **AFFIRMATIVE_ATTRIBUTION** | Watermark verified, Merkle proof valid, ML-DSA-65 signature valid, cert active. | Definite Attribution (Court Admissible) |
| `V2` | **RECIPIENT_REVOKED_POST_EVENT** | Signature valid, but recipient cert was revoked *after* the decryption event timestamp. | Valid Attribution with Status Warning |
| `V3` | **SIGNATURE_INVALID** | Ledger record found, but ML-DSA-65 signature verification failed. | Tampered / Corrupted Ledger Record |
| `V4` | **CERTIFICATE_REVOKED_PRIOR** | Certificate was already revoked before the event timestamp. | Illegitimate Decryption / Compromised Key |
| `V5` | **MERKLE_PROOF_INVALID** | Ledger record exists, but Merkle path does not anchor to block header root. | Ledger State Inconsistency |
| `V6` | **WATERMARK_CORRUPTED** | ECC decoding failed; bit-error rate exceeded Reed-Solomon error correction capacity. | Inconclusive (Severe Image Degradation) |
| `V7` | **UNREGISTERED_WATERMARK** | Watermark extracted cleanly, but no matching `DecryptionEvent` exists on ledger. | Uncommitted or Rogue Package |
| `V8` | **CERTIFICATE_EXPIRED** | Recipient certificate expired prior to decryption event timestamp. | Policy Violation / Expired Key |
| `V9` | **INSUFFICIENT_EVIDENCE** | No watermark detected in frequency sub-bands; image lacks forensic markers. | Negative Attribution |

---

## 6. Standalone Portable Evidence Verification

Forensic examiners and legal authorities do not need access to the TraceCrypt application server to verify findings. The standalone verifier can be executed directly from a USB drive:

```powershell
python -m tracecrypt.forensics.standalone_verifier `
    --report-bundle "reports/ATTRIBUTION-REPORT-2026-09-01.json" `
    --root-cert "certs/ca_root_cert.pem"
```

The standalone verifier:
1. Re-computes SHA3-256 digests of all referenced evidentiary artifacts.
2. Validates the Merkle audit path mathematically.
3. Performs pure Python/native ML-DSA-65 signature verification.
4. Generates an independent verification certificate with zero network or external database dependencies.
