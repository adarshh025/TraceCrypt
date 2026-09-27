# TraceCrypt Genuine Technical Limitations Register

**Release Baseline:** Version 1.0.0-rc1  
**Scope:** Architecture, Cryptography, Watermarking, Ledger, and Forensic Attribution  

---

## 1. Cryptographic & Runtime Limitations

### 1.1 Python Memory Zeroization Constraints
- **Constraint**: In CPython 3.11, immutable objects (`bytes`, `str`) cannot be securely wiped in place because their memory lifecycle is controlled by the internal memory allocator and garbage collector.
- **TraceCrypt Mitigation**: Native `bytearray` and `ctypes` buffers used for AES keys and sensitive plaintext buffers are zeroized explicitly via `ctypes.memset`. Keystore passwords and ephemeral keys are dereferenced immediately. However, defense-in-depth requires workstation-level full-disk encryption and swap disabling.

### 1.2 Pure Python BFT Ledger Throughput
- **Constraint**: The Python consensus implementation runs in a single-process thread with synchronous SQLite fsync operations (`PRAGMA synchronous = NORMAL`).
- **Measured Result**: Throughput is bounded at $\approx 12.3\text{ TPS}$ with 1-tx commit finality of $\approx 978\text{ ms}$.
- **Production Path**: Reaching $\ge 250\text{ TPS}$ requires deploying an asynchronous, multi-threaded C/Rust validator daemon.

---

## 2. Watermark & Signal Processing Limitations

### 2.1 Perceptual Fidelity vs Extreme Robustness Trade-off
- **Constraint**: DWT-DCT watermark modulation introduces imperceptible high-frequency luminance alterations.
- **Measured Result**:
  - At strength 4.0: $\text{PSNR} = 50.25\text{ dB}, \text{SSIM} = 0.9933$ (High visual fidelity, moderate attack defense).
  - At strength 10.0: $\text{PSNR} = 42.56\text{ dB}, \text{SSIM} = 0.9640$ (Hardened defense surviving JPEG Q65, $\pm 3^\circ$ rotation, 15% crop).
- **Limitation**: Embedding strengths above 10.0 lower SSIM to $\approx 0.95$, which does not meet the idealistic $0.995$ SSIM threshold.

### 2.2 Extreme Optical Destruction (> 75% Cropping)
- **Constraint**: The blind frequency extractor requires sufficient 2D DWT subband area to achieve correlation threshold $\ge 1.0$.
- **Limitation**: If an attacker destroys or crops more than 75% of a page, the correlation score drops below detection limits, producing `NOT_FOUND` or `UNVERIFIABLE`.

### 2.3 Supported Document Formats
- **Constraint**: The watermarking pipeline operates on PDF documents and standard rasterized image formats (PNG, JPEG, TIFF, BMP).
- **Limitation**: Native word processing formats (.docx, .odt) or markdown files must first be converted or rendered to PDF before packaging.

---

## 3. Threat Model & Operational Limitations

### 3.1 Byzantine Validator Limit ($f < N/3$)
- **Constraint**: The 4-validator consensus engine is safe against at most $f = 1$ Byzantine node ($N = 4 \implies 3f + 1$).
- **Limitation**: If 2 or more validators collude or are compromised simultaneously, consensus safety cannot be guaranteed.

### 3.2 Offline Revocation Propagation
- **Constraint**: In a fully air-gapped environment without continuous network connectivity, certificate revocation lists (CRLs) must be manually transferred to investigator stations via signed physical media.
- **Limitation**: Investigations conducted on stations with outdated revocation stores will rely on the validity state at the time of the ledger transaction commitment.
