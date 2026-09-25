# TraceCrypt: Offline Forensic Document Attribution Platform

TraceCrypt is an offline, post-quantum, air-gapped document distribution and forensic attribution platform designed for sensitive and classified operational environments.

---

## Core Capabilities & Security Model

1. **Recipient-Specific Invisible Forensic Watermarking:** Every successful document decryption embeds an invisible, unique watermark bound to the specific recipient and the ephemeral decryption session.
2. **Post-Quantum Cryptography:** Built upon NIST post-quantum cryptographic standards:
   * **NIST FIPS 203 (ML-KEM-768):** Key encapsulation for confidential multi-recipient distribution.
   * **NIST FIPS 204 (ML-DSA-65):** Digital signatures over canonical decryption events.
3. **Cryptographically Signed Decryption Events:** Decryption automatically triggers the construction of a canonical event record adhering to **RFC 8785 (JSON Canonicalization Scheme)**, signed by the recipient's certified ML-DSA-65 private key.
4. **Permissioned Distributed Ledger:** Decryption events are permanently committed to an offline Byzantine Fault Tolerant (BFT) permissioned ledger on the local air-gapped LAN.
5. **Deterministic Forensic Attribution:** When a document leaks, an investigator can extract the watermark blindly, locate the corresponding ledger event, mathematically verify the recipient's signature, and output one of 9 deterministic verdicts.
6. **Zero-Trust Air-Gapped Operation:** Designed to operate completely without internet connectivity, external APIs, cloud KMS, public blockchains, or external certificate authorities.

---

## Architecture Overview

```
[Offline Root CA] ────────► Issues ML-DSA-65 Identity Certificates
                                    │
┌────────────────────────┐          │
│   SENDER WORKSTATION   │          ▼
│ Encrypts Doc (AES-GCM) ├────► [.tcdist Package]
│ Encapsulates (ML-KEM)  │          │
└────────────────────────┘          │
                                    ▼
┌────────────────────────────────────────────────────────┐
│                  RECIPIENT WORKSTATION                 │
│ 1. Decapsulate ML-KEM & Decrypt AES-256-GCM            │
│ 2. Embed DWT-DCT Watermark (RS 32,16 ECC)              │
│ 3. Construct RFC 8785 Canonical DecryptionEvent        │
│ 4. Sign Event with Recipient ML-DSA-65 Private Key     │
│ 5. Commit Transaction to Permissioned Ledger           │
│ 6. Render Document & Zeroize Sensitive Buffers        │
└────────────────────────┬───────────────────────────────┘
                         │
                         ▼
┌────────────────────────────────────────────────────────┐
│            AIR-GAPPED BFT LEDGER (4 NODES)             │
│ Validates Signatures, Nonces, and Merkle State Root    │
└────────────────────────┬───────────────────────────────┘
                         │
                         ▼ (Upon Leakage)
┌────────────────────────────────────────────────────────┐
│           FORENSIC INVESTIGATION WORKSTATION           │
│ 1. Normalize Leaked PDF / Scanned Image                │
│ 2. Blind DWT-DCT Extract Watermark Bitstream           │
│ 3. Reed-Solomon Decode Payload (WatermarkID, DocHash)  │
│ 4. Query Ledger & Retrieve Event + Merkle Proof        │
│ 5. Verify ML-DSA-65 Signature & Cert Validity          │
│ 6. Output 1 of 9 Deterministic Verdicts & Proof Report │
└────────────────────────────────────────────────────────┘
```

---

## Current Status (Phase 1: Production-Grade Foundation)

* [x] **Repository Scaffolding & Packaging:** Clean modular hierarchy, strict `.gitignore`, `.gitattributes`, `pyproject.toml`.
* [x] **Strict Configuration Management:** Typed settings via Pydantic v2 supporting DEVELOPMENT, TEST, and PRODUCTION modes. Fails closed on insecure parameters.
* [x] **Typed Domain Models:** 14 core domain entities with strict validation, zero private key leakage, and no ambiguous types.
* [x] **Typed Identifiers:** Immutability, prefix namespaces (`doc-`, `usr-`, `rcp-`, `dev-`, `ses-`, `wm-`, `evt-`, `tx-`, `blk-`, `cas-`), and regex validation.
* [x] **RFC 8785 JSON Canonicalization Scheme (JCS):** Pure-Python standards-compliant canonicalizer supporting UTF-16 lexicographical sorting, ECMA-262 numbers, and minimal escaping.
* [x] **Deterministic SHA-3 Hashing:** Byte, file, and canonical object digest utilities formatted as `sha3-256:<hex>`.
* [x] **Secure Randomness Abstraction:** CSPRNG backed strictly by `os.urandom` (zero pseudo-random generator leakage).
* [x] **Structured Exception Hierarchy:** 13 specialized error types providing diagnostic clarity without secret leakage.
* [x] **Air-Gap Enforcement:** Socket-level interception guard blocking unauthorized network and DNS attempts.
* [x] **Structured Security Logging:** Automated regex redaction of private keys, passphrases, and raw secrets.
* [x] **Local Storage Foundation:** Hardened SQLite manager with WAL mode, synchronous=FULL, and foreign key enforcement.
* [x] **CLI Foundation:** Administrative commands (`version`, `doctor`, `config validate`, `security airgap-check`).
* [x] **FastAPI Foundation:** Local-only REST endpoints (`/health`, `/version`, `/security/status`) with security headers.

---

## Quickstart (Development & Testing)

### 1. Environment Verification
```bash
python -m tracecrypt.cli.main doctor
```

### 2. Validate Configuration
```bash
python -m tracecrypt.cli.main config validate
```

### 3. Check Air-Gap Status
```bash
python -m tracecrypt.cli.main security airgap-check
```

### 4. Run Test Suite
```bash
pytest
```

---

## Governance & Security Rules

All implementation in this repository is strictly bound by [PROJECT_CONTRACT.md](file:///C:/TraceCrypt/PROJECT_CONTRACT.md) and [SECURITY.md](file:///C:/TraceCrypt/SECURITY.md).
