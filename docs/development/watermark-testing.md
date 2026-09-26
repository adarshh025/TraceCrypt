# Forensic Watermarking Testing & Verification Guide

## 1. Overview

TraceCrypt provides safe CLI commands and automated pytest suites for developing, evaluating, and stress-testing the forensic watermarking subsystem in an offline air-gapped environment.

> [!WARNING]
> Direct CLI embedding (`tracecrypt watermark embed`) runs in **restricted development/test mode**.
> In production operations, watermarks are generated dynamically at decryption time within the secure runtime, bound to signed decryption events committed to the ledger.

---

## 2. CLI Forensic Commands

### 2.1 Embedding a Watermark (Development Mode)
Embeds an invisible transform-domain watermark into a PDF document:

```bash
tracecrypt watermark embed \
    --input sample.pdf \
    --output sample.watermarked.pdf \
    --strength 8.0
```

#### Options:
- `--input, -i`: Path to source PDF document (required).
- `--output, -o`: Path to output watermarked PDF (default: `<input>.watermarked.pdf`).
- `--doc-hash`: Optional SHA3-256 document hash (computed automatically if omitted).
- `--watermark-id`: Optional 128-bit hex identifier (defaults to CSPRNG).
- `--session-id`: Optional 128-bit hex identifier (defaults to CSPRNG).
- `--strength`: Embedding strength $\alpha$ (default: `8.0`).

### 2.2 Blind Extraction from Leaked Document
Extracts the watermark from a leaked PDF or image without requiring the pristine document:

```bash
tracecrypt watermark extract leaked_document.pdf
```

Output:
```
==================================================
TraceCrypt Blind Forensic Watermark Extraction
==================================================
Input Document:        leaked_document.pdf
Document Hash:         sha3-256:54bff5f...
Deskew Search:         ENABLED
Extracting...
--------------------------------------------------
Extraction Status:     DECODED
Confidence:            100.00%
Mean Correlation:      4.2031
Pages Analyzed:        2
Pages Decoded:         2
Pages Corrupted:       0
Corrected RS Errors:   4
--------------------------------------------------
Extracted Cryptographic Identity:
  WatermarkID:         wm-1a10e325664b5262886f2278bf47dbde
  SessionID:           d6ebcf570c99850c
  Document Binding:    3c042693c6
  Binding Valid:       VALID
  Payload Consistency: CONSISTENT
==================================================
```

### 2.3 Inspecting Document Watermark Status
```bash
tracecrypt watermark inspect suspicious_document.pdf
```

### 2.4 Running Performance & Latency Benchmarks
Measures local execution latency per page against the $\le 3.5\text{s}$ acceptance target:

```bash
tracecrypt watermark benchmark
```

### 2.5 Automated Robustness Attack Matrix
Executes the full simulated forensic attack suite:

```bash
tracecrypt watermark attack-test --strength 10.0
```

---

## 3. Automated Test Suite Execution

Run the complete watermarking test suite using pytest:

```bash
# Unit tests: GF(2^8) math, RS(32,16) ECC, 2D DWT, Block DCT, payload layout
python -m pytest tests/unit/test_watermark_*.py -v

# Integration tests: End-to-end multi-page PDF embedding and extraction
python -m pytest tests/integration/test_watermark_pipeline.py -v

# Security tests: Fail-closed verification, wrong hash, spliced pages, air-gap
python -m pytest tests/security/test_watermark_security.py -v

# Benchmark & robustness tests: Latency and attack matrix survivability
python -m pytest tests/benchmarks/test_watermark_benchmarks.py -v
```
