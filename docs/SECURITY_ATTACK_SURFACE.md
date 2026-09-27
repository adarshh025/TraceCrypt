# TraceCrypt Comprehensive Security Attack Surface Inventory

**Document Version:** 1.0.0  
**Classification:** Operational Security Architecture  
**Standard:** ISO/IEC 27034, NIST SP 800-53, NIST SP 800-218 (SSDF)  

---

## 1. Threat Boundaries & Architecture Overview

```
                      AIR-GAP ISOLATION BOUNDARY
═════════════════════════════════════════════════════════════════════════════
 [Untrusted Evidence]   [Air-Gapped Media]      [Local CLI / Scripts]
        │                       │                        │
        ▼                       ▼                        ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ TRACECRYPT CORE SECURITY ENCLAVE (LOCAL WORKSTATION / VALIDATOR NODE)     │
│                                                                           │
│  [Parser Sandbox] ──> [Schema Validator] ──> [Cryptographic Verifier]     │
│         │                     │                         │                 │
│         ▼                     ▼                         ▼                 │
│  [DWT-DCT Engine]     [JCS Canonicalizer]    [PQC Engine (ML-KEM/DSA)]    │
│         │                     │                         │                 │
│         ▼                     ▼                         ▼                 │
│  [Verdict Engine] <── [Replicated BFT Ledger] <── [Isolated Keystore]     │
│         │                                                                 │
│         ▼                                                                 │
│  [Court-Admissible Evidence Bundle (.tcproof) & Tamper-Evident Report]    │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Attack Surface Enumeration & Analysis Matrix

The table below enumerates all 22 attack surfaces across TraceCrypt, detailing the input, boundary, validation, failure mode, security consequence, and test coverage.

| Surface ID | Attack Surface Name | Attacker-Controlled Input | Trust Boundary | Validation Mechanism | Cryptographic Verification | Failure Mode | Security Consequence | Test Coverage |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **AS-01** | **CLI Interface** | Arguments, flags, environment vars, file paths | Host User $\to$ Process | Typer/Click type conversion, regex on IDs | Parameter bounds check | Non-zero exit with stderr message | Command injection, path escape, crash | `tests/security/test_cli_security.py` |
| **AS-02** | **REST / Local API** | HTTP requests, headers, query params, JSON payloads | Loopback socket $\to$ FastAPI app | Pydantic model validation, max payload size | TLS/mTLS, token/cert validation if enabled | HTTP 400/422/500 with sanitized JSON | DoS, deserialization injection, unauth access | `tests/security/test_api_security.py` |
| **AS-03** | **Distribution Package (.tcdist)** | Serialized binary file, header JSON, encrypted payload | Untrusted file $\to$ `DistributionService` | Preamble/magic check, size limits, JSON schema | SHA3-256 container checksum, ML-KEM-768 decapsulation, AES-GCM tag | `PackageValidationError`, `CryptographicError` | Plaintext leak, memory corruption, crash | `tests/security/test_package_security.py`, `test_fuzzing.py` |
| **AS-04** | **PDF Normalization** | Raw PDF files, binary stream, corrupted pages | Untrusted file $\to$ Document Processor | `pypdf`/`pypdfium2` parser bounds, page limits | SHA3-256 document hashing | `DocumentProcessingError` | Parser crash, memory exhaustion, arbitrary execution | `tests/forensics/test_normalization.py` |
| **AS-05** | **Raster Image Ingestion** | TIFF, PNG, JPEG bytes, color profiles, EXIF | Untrusted file $\to$ Forensic Ingestion | OpenCV / Pillow dimension bounds, 3-channel RGB check | Image byte hash commitment | `ImageProcessingError` | Image decompression bomb, buffer overflow | `tests/forensics/test_ingestion.py` |
| **AS-06** | **DWT-DCT Watermark Extraction** | Pixel luminance values, frequency coefficients | Untrusted image $\to$ DWT-DCT Extractor | Block dimension check ($1024 \times 1024$), sub-band bounds | Reed-Solomon RS(32,16) ECC, CRC16 payload checksum | `WatermarkCorruptedError`, `ExtractionError` | False attribution, algorithm crash, DoS | `tests/forensics/test_watermark_attacks.py`, `test_watermark_lab.py` |
| **AS-07** | **Identity & UserID** | RecipientID string (`usr-*`, `rcp-*`), metadata | User input $\to$ Identity system | Regex format validation (`^usr-[a-f0-9]{32}$`) | Bound to certified public key | `ValidationError` | Identity spoofing, impersonation | `tests/security/test_identity_security.py` |
| **AS-08** | **PQC Certificates** | Serialized X.509/JSON certificate, PEM blocks | Remote/untrusted cert $\to$ PKI validator | Pydantic model validation, validity period check | NIST FIPS 204 ML-DSA-65 signature against Root CA | `CertificateValidationError`, `SignatureInvalid` | Rogue identity enrollment, unauthorized action | `tests/security/test_certificate_attacks.py`, `test_fuzzing.py` |
| **AS-09** | **Argon2id Keystore** | Keystore JSON, ciphertext, salt, nonce, KDF params | Host filesystem $\to$ Keystore loader | Parameter bounds (m=64MB, t=3, p=4 enforcement) | AES-256-GCM auth tag over private key bytes | `KeystoreDecryptionError`, `TamperError` | Private key theft, KDF downgrade attack | `tests/security/test_keystore.py` |
| **AS-10** | **BFT Consensus Messages** | Proposal, Prevote, Precommit, Commit wire messages | Inter-node TCP/loopback $\to$ Consensus engine | Message schema validation, height/round monotonically checked | ML-DSA-65 validator signature, genesis chain ID | `ConsensusError`, Byzantine evidence logged | Byzantine takeover, split-brain, liveness stall | `tests/security/test_bft_byzantine.py`, `test_bft_fault_injection.py` |
| **AS-11** | **Ledger Block Ingestion** | BlockHeader, transaction array, Merkle root | Peer node $\to$ Ledger store | Block height sequence, parent hash linkage | Header SHA3-256 hash, Merkle transaction root | `LedgerValidationError` | Ledger fork, history rewriting, fraud | `tests/security/test_ledger_tampering.py` |
| **AS-12** | **DecryptionEvent Creation** | Event fields, timestamp, document hash, watermark ID | Recipient client $\to$ Event signer | Canonical schema validation, anti-replay nonce check | ML-DSA-65 recipient signature over RFC 8785 canonical bytes | `EventValidationError`, `ReplayAttackError` | Forged attribution event, repudiation | `tests/security/test_event_tampering.py`, `test_attribution_security.py` |
| **AS-13** | **Merkle Proof Verification** | Leaf hash, sibling path, target root, index | Standalone verifier $\to$ Merkle engine | Path length validation, index bit-path check | Deterministic SHA3-256 pair hashing | `ProofVerificationError` | Fraudulent inclusion claim, false verification | `tests/security/test_proof_tampering.py` |
| **AS-14** | **SQLite Metadata Database** | SQL query parameters, persisted state records | Application $\to$ SQLite WAL database | Parameterized queries (no string interpolation) | SQLite page checksums, integrity check PRAGMA | `sqlite3.DatabaseError` | SQL injection, state corruption, data tampering | `tests/security/test_ledger_security.py` |
| **AS-15** | **Configuration Parsing** | YAML / JSON config files, environment overrides | Config file $\to$ Configuration manager | Strict Pydantic model with `extra='forbid'` | Profile-based invariant validation | `ConfigurationError` | Security feature disablement, unsafe mode | `tests/unit/test_config.py` |
| **AS-16** | **Backup Archive (.tcbackup)**| Zip file archive, manifest JSON, compressed DBs | Untrusted file $\to$ `BackupManager` | Safe path expansion, traversal sanitization (`..`), file size limits | SHA-256 & SHA3-256 digest verification against manifest | `BackupVerificationError` | Path traversal, arbitrary file overwrite, DoS | `tests/security/test_file_security.py`, `test_fuzzing.py` |
| **AS-17** | **Disaster Recovery Restore**| Extracted backup trees, database files | Restorer $\to$ Target directories | Directory lockdown, existing file safety backup | Manifest integrity verification | `RestoreError` | System state corruption, rollback attack | `tracecrypt/storage/backup.py` |
| **AS-18** | **Forensic Evidence Bundle (.tcproof)**| Complete proof package JSON, certificates, proofs | Standalone Verifier $\to$ Evaluation engine | Comprehensive Pydantic schema validation | Complete independent cryptographic re-verification | `VerificationFailure` | Acceptance of fabricated investigation results | `tests/forensics/test_proof_bundle.py`, `test_fuzzing.py` |
| **AS-19** | **Audit Logging** | Event logs, error traces, structured messages | Internal components $\to$ Log writer | Structured JSON formatter, field sanitization | Read-only permissions on log directory | Silent write failure, log rotation | Log injection, secret leakage in logs | `tests/unit/test_logging.py` |
| **AS-20** | **Forensic Report Generation**| Case evidence, attribution verdicts, metadata | Investigation engine $\to$ ReportLab PDF generator| Canvas boundary limits, text escape sanitization | Cryptographic digest of final report PDF | `ReportGenerationError` | PDF injection, memory leak, DoS | `tests/forensics/test_verdicts.py` |
| **AS-21** | **Air-Gap Network Boundary**| Network interfaces, socket syscalls, HTTP calls | Operating system $\to$ TraceCrypt runtime | Static AST audit, dynamic socket patching | Runtime enforcement of offline policy | `AirGapViolationError` | Network exfiltration, remote code execution | `tests/security/test_airgap.py`, `scripts/verify_airgap.py` |
| **AS-22** | **Memory Zeroization** | Intermediate keys, decrypted plaintext buffers | Application heap $\to$ Garbage collector | `SecureDocumentBuffer`, `ctypes.memset` zeroization | Memory overwrite verification before deallocation | Buffer already deallocated exception | Plaintext / key material recovery via memory dump | `tests/security/test_zeroize.py` |

---

## 3. Defense-in-Depth Enforcements

1. **Fail-Closed Principle:** Every validation failure raises a typed exception and immediately terminates processing without returning partial or unauthenticated state.
2. **Cryptographic Supremacy:** No business logic or heuristic may override cryptographic validation. Even if an investigator marks a suspect as culpable, a signature or Merkle proof mismatch strictly yields `SIGNATURE_INVALID` or `LEDGER_INVALID`.
3. **No Dynamic Code Execution:** TraceCrypt prohibits `eval()`, `exec()`, or unvetted deserializers (`pickle`, unsafe YAML). Only RFC 8785 JSON and typed binary structs are permitted.
