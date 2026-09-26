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

## Current Status
* [x] **Phase 1: Production-Grade Foundation:** Modular architecture, Pydantic v2 settings, typed domain identifiers, RFC 8785 canonicalization, deterministic SHA-3 hashing, air-gap guard, SQLite store, logging redaction.
* [x] **Phase 3: Post-Quantum Identity & Key Management Subsystem:**
  * **NIST FIPS 203 (ML-KEM-768):** Key encapsulation ($pk=1,184\text{B}, sk=2,400\text{B}, c=1,088\text{B}, ss=32\text{B}$) with implicit rejection.
  * **NIST FIPS 204 (ML-DSA-65):** Digital signatures ($pk=1,952\text{B}, sk=4,032\text{B}, \sigma=3,309\text{B}$) with deterministic verification.
  * **Strict Role Separation:** Type-safe separation preventing cross-algorithm key substitution.
  * **Offline Root CA:** Air-gapped trust anchor issuing ML-DSA-65 identity certificates.
  * **PQC Identity Certificates:** Versioned RFC 8785 canonical identity envelopes with 12-point offline validation.
  * **Key Lifecycle & Rotation:** Monotonic state machine preventing un-revocation; key rotation preserving historical event verifiability.
  * **Argon2id Keystore:** Password-derived encryption ($m=64\text{MB}, t=3, p=4$) + AES-256-GCM with canonical AAD metadata binding and Windows `icacls` permission hardening.
  * **Device Enrollment:** Workstation enrollment with hardware telemetry collection.
  * **Full Quality Gates:** 175 passing tests (100%), 0 flake8 errors, deterministic KAT vectors verified.

---

## Quickstart (Development & Testing)

### 1. Environment Verification
```bash
python -m tracecrypt.cli.main doctor
python -m tracecrypt.cli.main ca status
```

### 2. Initialize Offline Root CA
```bash
python -m tracecrypt.cli.main ca init --ca-id "ca-root-01" --passphrase "SecretMasterPass123!"
```

### 3. Generate Post-Quantum Identity & Certificate
```bash
python -m tracecrypt.cli.main identity generate --owner-id "rcp-agent-alpha" --passphrase "AgentKeyPass123!" --ca-passphrase "SecretMasterPass123!"
```

### 4. Inspect & Verify Identity
```bash
python -m tracecrypt.cli.main identity inspect --recipient-id "rcp-agent-alpha"
python -m tracecrypt.cli.main identity status
```

### 5. Run Test Suite
```bash
python -m pytest
```

---

## Governance & Security Rules

All implementation in this repository is strictly bound by [PROJECT_CONTRACT.md](file:///C:/TraceCrypt/PROJECT_CONTRACT.md) and [SECURITY.md](file:///C:/TraceCrypt/SECURITY.md).
