# Watermark Threat Model & Engineering Limitations

## 1. Adversarial Threat Model

TraceCrypt assumes an active, technologically capable adversary seeking to leak confidential documents without attribution, or seeking to frame another authorized recipient.

### 1.1 Threat Classes & Mitigations

| Threat | Adversary Strategy | TraceCrypt Defense | Residual Risk / Limitation |
| :--- | :--- | :--- | :--- |
| **Tampering & Bit Flips** | Modifying document pixels or compression artifacts. | Systematic RS(32,16) ECC corrects up to 16 byte errors across interleaved blocks. | Bit error rate exceeding $6.25\%$ causes deterministic decoding failure (`CORRUPTED`). |
| **Page Splicing** | Replacing or combining pages from different recipients. | Independent page-level extraction + cross-page consistency check. Detects conflicts and returns `AMBIGUOUS`. | Replacing 100% of pages with another document eliminates original attribution. |
| **Document Transplantation** | Extracting watermark from Document A and claiming it belongs to Document B. | Cryptographic document binding token locks watermark to original SHA3-256 document hash. | Fails closed on mismatched documents. |
| **Frame-Up Attack** | Crafting a counterfeit payload pointing to another user. | Payload contains only unguessable 128-bit CSPRNG identifiers. Final attribution requires matching signed ledger event (Phase 5). | Adversary cannot forge valid signature on decryption event. |
| **Metadata Stripping** | Stripping PDF metadata, annotations, and comments. | Watermark is embedded directly into pixel luminance in DWT/DCT frequency domain, not in PDF metadata. | Immune to metadata stripping. |

---

## 2. Engineering Limitations & Realistic Boundaries

Forensic invisible watermarking is an evidentiary mechanism, not an absolute cryptographic barrier against analog destruction.

### 2.1 Known Robustness Boundaries
1. **Severe Lossy Compression (JPEG Q < 65)**:
   - High-quantization JPEG eliminates mid- and high-frequency DCT coefficients where watermark energy resides.
   - At $Q \le 65$, raw BER exceeds the error-correction capacity of RS(32,16). The extractor returns `NOT_DETECTED` or `CORRUPTED`.
2. **Extreme Geometric Warping & Non-Linear Distortion**:
   - The normalization pipeline handles affine rotations up to $\pm 3^\circ$ and uniform DPI scaling.
   - Severe non-linear warping (such as photographing a curved, bent, or crumpled physical paper sheet) disrupts block DCT grid alignment unless manual forensic unwarping is applied.
3. **Severe Cropping (> 15%)**:
   - The watermark survives up to 15% boundary cropping because the spreading sequence distributes bits uniformly across the page.
   - Cropping more than 20% of the document canvas destroys a significant fraction of carrier chips, preventing reliable correlation.
4. **Adversarial Frequency Scrubbing**:
   - An attacker with signal-processing knowledge who applies aggressive low-pass filtering (e.g., Gaussian blur with kernel size $\ge 7 \times 7$) will attenuate the watermark. However, this also severely degrades document readability, rendering confidential text illegible.
5. **The Analog Screen Photograph Hole**:
   - Taking a handheld smartphone photograph of a monitor introduces moiré patterns, sensor lens distortion, and ambient reflection.
   - TraceCrypt's normalization pipeline deskews planar rotations, but high-angle off-axis photographs require specialized geometric rectification.

---

## 3. Boundary of Attribution Claims

> [!IMPORTANT]
> The watermark alone does NOT prove biological human identity.
> It cryptographically identifies a **specific decryption session** and **device context**.
> Final forensic attribution requires the triad:
> 1. Decoded watermark payload (`WatermarkID`, `SessionID`, `DocumentBinding`).
> 2. Cryptographically signed decryption event record (NIST FIPS 204 ML-DSA-65).
> 3. Recipient identity certificate issued by the Offline Root CA.
