# Blind Frequency-Domain Watermark Extraction Pipeline

## 1. Algorithmic Overview

TraceCrypt uses blind frequency-domain spread-spectrum watermarking combining **2-Level 2D Discrete Wavelet Transform (Haar DWT)** and **8x8 Block Discrete Cosine Transform (DCT)** with **Reed-Solomon RS(32, 16)** error correction. The detector operates strictly blindly: neither the pristine original document nor candidate recipient keys are required.

```text
Normalized Grayscale Page Image (H x W)
                   │
                   ▼
         [2D Haar DWT (Level 1)]
   ┌───────┬───────┐
   │  LL1  │  HL1  │  (HL1: Horizontal details)
   ├───────┼───────┤  (LH1: Vertical details)
   │  LH1  │  HH1  │  (HH1: Diagonal details)
   └───────┴───────┘
                   │
         [Target LH1 Subband]
                   │
                   ▼
        [8x8 Block Partitioning]
                   │
                   ▼
            [2D Block DCT]
                   │
                   ▼
     [Mid-Frequency Selection (4,3)]
                   │
                   ▼
  [Correlation with Carrier Sequence]
   (Derived from suspect document hash)
                   │
                   ▼
   [256-Bit Raw Demodulated Stream]
                   │
                   ▼
   [Reed-Solomon RS(32, 16) Decoding]
   (Corrects up to 8 symbol errors in GF(2^8))
                   │
                   ▼
      [CRC-16-CCITT Verification]
   (Polynomial 0x1021 over first 30 bytes)
                   │
                   ▼
  [Recovered 32-Byte Logical Payload]
   - Version: 1 byte
   - WatermarkID: 16 bytes (128 bits)
   - Session Tag: 8 bytes (64 bits)
   - Document Binding: 5 bytes (40 bits)
   - Checksum: 2 bytes (16 bits)
```

---

## 2. Mathematical Formulation

### 2.1 Wavelet Decomposition
For a grayscale page image $I(x, y)$, the 1-level 2D Haar wavelet transform decomposes the image into four quarter-resolution subbands:
$$I \xrightarrow{\text{DWT}} \{LL_1, LH_1, HL_1, HH_1\}$$
The horizontal-detail subband $LH_1$ provides high perceptual masking while resisting low-pass filtering and JPEG compression.

### 2.2 Block DCT Modulation
$LH_1$ is partitioned into non-overlapping $8 \times 8$ pixel blocks $B_k$. The 2D DCT is computed for each block:
$$D_k(u, v) = \text{DCT}(B_k)$$
Watermark bits are extracted from the mid-frequency coefficient at $(u=4, v=3)$ by evaluating correlation against the deterministic pseudo-random carrier sequence $C_k \in \{-1, +1\}$ derived from the document hash:
$$\text{bit}_k = \begin{cases} 1 & \text{if } \langle D_k(4,3), C_k \rangle > 0 \\ 0 & \text{otherwise} \end{cases}$$

### 2.3 Reed-Solomon Error Correction: RS(32, 16)
- **Field**: Galois Field $GF(2^8)$ with primitive polynomial $p(x) = x^8 + x^4 + x^3 + x^2 + 1$ ($0x11D$).
- **Message Length**: $k = 16$ bytes (128 bits).
- **Codeword Length**: $n = 32$ bytes (256 bits).
- **Error Correction Capability**: $t = \frac{n - k}{2} = 8$ bytes. The engine can completely correct up to 8 arbitrary symbol errors (up to 64 corrupted bits).

---

## 3. Preprocessing and Normalization

To ensure invariant frequency extraction across real-world scan and rendering variations:
1. **Color Normalization**: All multi-channel formats (RGB, RGBA, CMYK) are converted to linear luminance $L$:
   $$L = 0.299R + 0.587G + 0.114B$$
2. **Dimension Alignment**: Padded to the nearest multiple of 16 pixels to prevent boundary truncation during DWT and $8 \times 8$ block DCT.
3. **Controlled Deskewing**: Horizontal text baselines are detected using the Probabilistic Hough Transform (`cv2.HoughLinesP`). Skew angles within $[-10^\circ, +10^\circ]$ are rotated to horizontal alignment.
