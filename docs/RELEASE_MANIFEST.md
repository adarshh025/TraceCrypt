# TraceCrypt Release Artifact Manifest

**Release Version:** 1.0.0-rc1  
**Release Date:** 2026-09-27  
**Git Baseline Commit:** `1eaee13fb82dd58cfb0727a1f2b35af6a2a36c18`  
**Distribution Channel:** Air-Gapped Physical / Cryptographic Package  

---

## 1. System & Toolchain Specification

| Component | Exact Specification / Version |
| :--- | :--- |
| **Application Version** | `1.0.0-rc1` |
| **Protocol Version** | `1.0.0` |
| **Database Schema Version** | `1.0.0` |
| **Python Runtime** | `3.11.9` (64-bit, MSC v.1938 64 bit (AMD64)) |
| **Rust Toolchain** | `rustc 1.96.0` (ac68faa20 2026-05-25) |
| **Node.js Runtime** | `v24.17.0` |
| **npm Package Manager** | `11.13.0` |
| **Git Version** | `2.54.0.windows.1` |
| **OS Platform** | Microsoft Windows 10 Home (10.0.19045 Build 19045) |

---

## 2. Core Dependency Versions

| Library | Exact Version | Primary Role |
| :--- | :--- | :--- |
| `cryptography` | `46.0.5` | AES-256-GCM, SHA3, OS CSPRNG primitives |
| `pydantic` | `2.12.5` | Type validation and schema parsing |
| `pydantic_core` | `2.41.5` | High-speed C-extension schema engine |
| `dilithium_py` | `0.1.0` | NIST FIPS 204 ML-DSA-65 post-quantum signatures |
| `mlkem` | `0.1.0` | NIST FIPS 203 ML-KEM-768 post-quantum key encapsulation |
| `numpy` | `2.4.3` | Matrix operations for DWT-DCT watermark processing |
| `scipy` | `1.17.1` | Scientific 2D DCT signal transforms |
| `opencv-python` | `4.13.0` | Computer vision deskew and image normalization |
| `Pillow` | `12.1.1` | Raster image loading and format conversion |
| `reportlab` | `4.4.10` | Forensic attribution report PDF generation |
| `pypdf` | `6.8.0` | PDF parsing and page-level raster handling |
| `pytest` | `9.1.1` | Test runner and benchmark verification |

---

## 3. Cryptographic Algorithms Pinned in Release

- **Key Encapsulation Mechanism**: NIST FIPS 203 ML-KEM-768 (ek=1184 B, dk=2400 B, ct=1088 B)
- **Digital Signatures**: NIST FIPS 204 ML-DSA-65 (pk=1952 B, sk=4032 B, sig=3309 B)
- **Symmetric Encryption**: AES-256-GCM (256-bit key, 96-bit nonce, 128-bit tag)
- **Cryptographic Hashing**: SHA3-256 (256-bit digest)
- **Password KDF**: Argon2id ($m=64\text{ MB}, t=3, p=4$, 128-bit salt)
- **Canonical Serialization**: RFC 8785 JSON Canonicalization Scheme (JCS)
- **Watermark FEC**: Reed-Solomon RS(32,16) Galois Field $GF(2^8)$

---

## 4. Release Artifact Cryptographic Hashes (SHA3-256)

Computed using standard SHA3-256:

| Artifact File | Size (Bytes) | SHA3-256 Digest |
| :--- | :---: | :--- |
| `pyproject.toml` | 1,894 | `abade20b56b26b1a69fbcafe12bf1224a054d9f83dfce7624dde7b9e35503483` |
| `README.md` | 16,517 | `2abe517ad48b42a46f2a88f193c20d8470389426fe688ba3884e038c974e9fb6` |
| `LICENSE` | 1,072 | `5724a9dd6814754a0ac2083b8f4ae3355ee361689fba8895321669e7322404ea` |
| `tracecrypt/__init__.py` | 1,291 | `60e0bdeb1ab545a63c6262b52d8acb3bb309afb430188a632c8e451f7442126f` |
