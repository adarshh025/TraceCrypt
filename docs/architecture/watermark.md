# Transform-Domain Forensic Watermark Architecture

## 1. System Overview

TraceCrypt's forensic watermarking subsystem is designed for **blind, invisible, robust attribution** of leaked confidential documents to the exact decryption session in which they were rendered.

The watermarking engine operates strictly in the **transform domain**, combining 2D Discrete Wavelet Transform (Haar DWT), Block Discrete Cosine Transform (8x8 DCT), deterministic spread-spectrum modulation, and Reed-Solomon RS(32,16) forward error correction over $\text{GF}(2^8)$.

```
                      Pristine Document (PDF / Image)
                                     │
                                     ▼
                        Deterministic Rasterization
                                     │
                                     ▼
                            2D Haar Wavelet DWT
                                     │
                 ┌───────────────────┴───────────────────┐
                 ▼                                       ▼
       HL Subband (Horizontal)                 LH Subband (Vertical)
                 │                                       │
                 ▼                                       ▼
          8x8 Block 2D DCT                        8x8 Block 2D DCT
                 │                                       │
                 └───────────────────┬───────────────────┘
                                     │
                                     ▼
                        Mid-Frequency Selection (Zigzag)
                                     │
                                     ▼
                   Spread-Spectrum Additive Modulation
                    (Coded 512-bit RS Payload * Carrier)
                                     │
                 ┌───────────────────┴───────────────────┐
                 ▼                                       ▼
         Inverse 8x8 DCT                         Inverse 8x8 DCT
                 │                                       │
                 └───────────────────┬───────────────────┘
                                     │
                                     ▼
                            Inverse 2D Haar DWT
                                     │
                                     ▼
                     Lossless FlateDecode PDF Assembly
                                     │
                                     ▼
                          Watermarked Document PDF
```

---

## 2. Core Transform Pipeline

### 2.1 2D Haar Discrete Wavelet Transform
The rasterized luminance plane $I(x, y)$ is decomposed into four subbands using the orthogonal Haar wavelet:
- **LL (Approximation)**: Low-pass filtered baseline luminance (unmodified to prevent perceptual visibility).
- **HL (Horizontal Detail)**: High-pass filtered horizontally, low-pass vertically.
- **LH (Vertical Detail)**: Low-pass filtered horizontally, high-pass vertically.
- **HH (Diagonal Detail)**: High-pass filtered diagonally (unmodified due to susceptibility to lossy compression).

Embedding is restricted exclusively to **HL** and **LH** subbands.
The transform guarantees exact numerical invertibility with $\text{MSE} < 10^{-12}$:
$$\text{idwt2}(\text{dwt2}(I)) \equiv I$$

### 2.2 8x8 Block Discrete Cosine Transform
The HL and LH subband matrices are partitioned into non-overlapping $8 \times 8$ blocks. Each block is transformed into the frequency domain using the 2D Type-II Orthogonal DCT:
$$F(u, v) = \alpha(u) \alpha(v) \sum_{x=0}^7 \sum_{y=0}^7 f(x, y) \cos\left[\frac{(2x+1)u\pi}{16}\right] \cos\left[\frac{(2y+1)v\pi}{16}\right]$$

### 2.3 Mid-Frequency Selection
Within each $8 \times 8$ DCT block, coefficients are ordered via standard zigzag traversal. To maximize robustness against compression while preserving human perceptual invisibility:
- **DC component (index 0)** is excluded.
- **High-frequency corner (indices > 10)** is excluded (quantized to zero by lossy JPEG).
- **Mid-frequency band (indices 1 through 10)** is selected for modulation.

On a standard Letter document at 150 DPI ($1584 \times 1216$ pixels), the HL and LH subbands ($792 \times 608$) provide $135,432$ usable mid-frequency coefficient sites.

---

## 3. Spread-Spectrum Modulation

The 512-bit Reed-Solomon encoded codeword $b \in \{0, 1\}^{512}$ is modulated across the coefficient sites.

### 3.1 Bipolar Mapping
Each bit $b_i$ is mapped to a bipolar value $v_i \in \{-1, +1\}$:
$$v_i = 1 - 2b_i$$

### 3.2 Cryptographic Carrier Sequence
For each page $j$, a deterministic pseudo-random carrier sequence of site permutations $\pi$ and bipolar chips $s \in \{-1, +1\}^N$ is derived from the source document hash:
$$\text{Seed}_j = \text{SHA3-256}(\text{"TraceCrypt-Watermark-Carrier:v1:"} \parallel \text{DocumentHash} \parallel \text{":page:"} \parallel j)$$

The sequence is generated using SHAKE-256 as an air-gapped cryptographic XOF. Standard pseudo-random generators (`random.random()`) are strictly prohibited.

### 3.3 Spreading Gain
With $N = 135,432$ sites and $M = 512$ coded bits, each watermark bit is spread across:
$$L = \lfloor N / M \rfloor = 264 \text{ chips/bit}$$
This massive spreading gain ($24.2\text{ dB}$) enables reliable blind extraction even under severe channel noise and compression.

### 3.4 Coefficient Modulation
For each bit $i$, over its allocated chips $k \in [i \cdot L, (i+1) \cdot L)$:
$$C'(\pi_k) = C(\pi_k) + \alpha \cdot v_i \cdot s_k$$
where $\alpha$ is the configurable embedding strength (default $\alpha = 8.0$).

---

## 4. Blind Extraction Architecture

Extraction operates **blindly**—it does NOT require the original, unwatermarked document:

1. **Carrier Reconstruction**: The extractor computes $\text{Seed}_j$ from the alleged document hash and page index $j$, regenerating $\pi$ and $s$.
2. **Correlation Summation**: For each bit $i$, the soft correlation is computed across modulated DCT coefficients:
   $$\rho_i = \sum_{k=i \cdot L}^{(i+1) \cdot L - 1} C'(\pi_k) \cdot s_k$$
3. **Hard Decision**:
   $$\hat{b}_i = \begin{cases} 0 & \text{if } \rho_i > 0 \\ 1 & \text{if } \rho_i \le 0 \end{cases}$$
4. **Reed-Solomon Decoding**: The 512 extracted bits (64 bytes) are de-interleaved and passed to the RS(32,16) Berlekamp-Massey decoder, correcting up to 16 symbol errors (8 per block).
5. **CRC-16 & Binding Verification**: The 32-byte payload is validated against the CRC-16 checksum and checked for cryptographic document binding.

---

## 5. Multi-Page Splicing Defense

In multi-page documents, each page embeds the **same logical WatermarkID and SessionID**, but with **page-index differentiated carrier sequences**.

Upon extraction:
- Extracted WatermarkIDs across all pages are compared.
- If all decoded pages match $\to$ `DECODED` (Consistent consensus).
- If conflicting WatermarkIDs appear across pages (e.g. Page 1 from Session A spliced with Page 2 from Session B) $\to$ `AMBIGUOUS`. The system fails closed and refuses to attribute to either party.
- If some pages are destroyed or unwatermarked $\to$ reports partial consistency with exact corrupted page indices.
