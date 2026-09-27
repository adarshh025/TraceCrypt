# TraceCrypt Security Asset Inventory

**Classification:** RESTRICTED / TRACECRYPT AIR-GAPPED CRYPTOGRAPHIC ASSET CONTROL  
**Standard Compliance:** NIST SP 800-57, FIPS 140-3, NIST SP 800-88  
**Scope:** Offline Root CA, Recipient Workstations, BFT Validators, Forensic Attribution Engine  

---

## 1. Executive Summary

This document maintains the rigorous security asset inventory for TraceCrypt. In accordance with zero-trust offline operational principles, every cryptographic secret, identifier, key material, plaintext buffer, and evidence artifact is classified by origin, storage location, copy boundaries, zeroization policy, and access boundary.

TraceCrypt enforces strict key separation:
- **ML-KEM-768 Private Keys** $\neq$ **ML-DSA-65 Private Keys**
- **Recipient Signing Keys** $\neq$ **Validator Consensus Keys**
- **Document Encryption Keys** $\neq$ **Watermark Extraction Keys**
- **Root CA Private Keys** reside strictly on air-gapped Master CA storage and are never loaded onto validator nodes or recipient client workstations.

---

## 2. Cryptographic and Information Asset Inventory

| Asset Name | Generation Origin | Storage Location | In-Memory Lifetime | Zeroization Mechanism | Logging Policy | Access Boundary |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Root CA Private Key** (ML-DSA-65) | `OfflineRootCA.initialize` via `SecureRandom` | Encrypted Argon2id keystore on dedicated offline media | Ephemeral during certificate issuance and revocation signing | Explicit `ctypes.memset` zeroization in `MLDSAPrivateKey.zeroize()` / bytearray wiping | **STRICT REDACTION**: Never logged under any log level | Offline CA enclave only |
| **Recipient ML-DSA-65 Private Key** | `generate_mldsa_keypair` / `KeystoreManager` | Local Argon2id encrypted file (`.keystore.json`) | Unlocked only during DecryptionEvent signing | `MLDSAPrivateKey.zeroize()` / `bytearray` zeroization on keystore close | **STRICT REDACTION**: Redacted via `LogFilter` regex `(?i)(private_key\|sk)` | Recipient user session only |
| **Recipient ML-KEM-768 Private Key** | `generate_mlkem_keypair` / `KeystoreManager` | Local Argon2id encrypted file (`.keystore.json`) | Unlocked only during document key decapsulation | `MLKEMPrivateKey.zeroize()` / `bytearray` zeroization on session termination | **STRICT REDACTION**: Never logged | Recipient user session only |
| **Validator Consensus Private Keys** (ML-DSA-65) | Node initialization / genesis bootstrap | Local OS-secured keystore or environment token | Persists during validator node process execution | Zeroized upon process exit or SIGTERM | **STRICT REDACTION**: Never logged | Local Validator daemon only |
| **AES-256-GCM Document Key** | Sender document packager via `SecureRandom.random_bytes(32)` | Encapsulated in recipient KEM ciphertexts; never stored in plaintext | Ephemeral during encryption and decryption pipeline | Explicit buffer overwrite via `ctypes.memset` or garbage-collected ephemeral slice | **STRICT REDACTION**: Never printed or logged | Sender encryption pipeline & Recipient decryption pipeline |
| **AES-GCM Nonce** (96-bit) | `SecureRandom.random_bytes(12)` | Embedded in encrypted document header / package envelope | Ephemeral during encryption/decryption | Immutable byte value; uniqueness tracked in `_used_nonces` registry | Public metadata (logged as hex) | Public within package metadata |
| **Watermark Nonce / Entropy** (128-bit) | `SecureRandom.random_nonce_128()` | Embedded in `DecryptionEvent.anti_replay_nonce` | Ephemeral during event generation | Ephemeral object lifecycle | Public in event metadata (non-secret entropy) | Consensus and Forensic engine |
| **Session ID** (128-bit UUID) | `SessionID.generate()` via `SecureRandom` | Embedded in `DecryptionEvent`, `WatermarkPayload`, and Ledger | Persists in ledger index for replay protection | N/A (Public identifier) | Logged as hex/string | Public forensic domain |
| **Watermark ID** (128-bit) | `WatermarkID.generate()` via `SecureRandom` | Modulated into DWT-DCT coefficients and committed in Ledger | Persists in ledger index and forensic database | N/A (Public identifier) | Logged as hex/string | Public forensic domain |
| **Document Hash** (SHA3-256) | `Hasher.digest_bytes` over plaintext bytes | Recorded in document metadata and `DecryptionEvent` | Persists in package and ledger state | N/A (One-way cryptographic commitment) | Logged as hex | Public forensic domain |
| **Plaintext Document Buffer** | Loaded by sender or decrypted by recipient | RAM only (in-memory bytes buffer) | Held only during rendering / watermark embedding | Best-effort memory wiping via mutable bytearrays and prompt GC | **FORBIDDEN**: Never logged, printed, or written to disk unwatermarked | Core crypto memory space only |
| **Watermarked PDF Buffer** | `WatermarkEmbedder.embed_document` | Written to user-designated output destination | Output lifecycle | Standard OS file permissions | Non-secret output | User filesystem |
| **Signed Decryption Event** | `DecryptionEventSigner.sign_event` | In-memory transaction, Mempool, SQLite database | Permanent in ledger | N/A (Public immutable ledger record) | Public canonical JSON | Public consortium domain |
| **PQC Identity Certificates** | Issued by Offline Root CA | Stored in ledger state, `.tcproof` bundles, filesystem | Permanent public record | N/A (Public certificate) | Public canonical JSON | Public consortium domain |
| **Revocation State / Records** | `OfflineRevocationStore` / `KeyLifecycleManager` | SQLite `revocations` table / standalone sync file | Permanent in local storage | N/A (Public signed revocation list) | Public signed record | Public consortium domain |
| **Ledger Storage State** | Replicated BFT blocks in SQLite + WAL | Local disk: `<data_dir>/ledger.db` + `.checkpoint` | Permanent across restarts | Checkpoint validation protects against rollback | SQLite WAL mode, query logs | Local validator node only |
| **Forensic Proof Bundle** (`.tcproof`) | `ForensicProofBundle.create` | Written to export path designated by investigator | Permanent audit record | N/A (Tamper-evident signed JSON) | Public canonical JSON | Forensic investigator & legal court |
| **Normalized Evidence Images** | `WatermarkNormalizer.rasterize_pdf` / OpenCV | In-memory NumPy uint8 arrays | Investigator process lifetime | Automatically deallocated when investigation completes | Never logged | Investigator RAM sandbox |
| **Temporary Files** (`.tmp`) | `tempfile.NamedTemporaryFile` in secure temp | OS temporary directory with restricted permissions | Scope of `with` block (cleaned in `finally`) | Immediate deletion via context manager / `unlink()` | Paths logged at DEBUG level | Local process sandbox |

---

## 3. Cryptographic Purpose and Key Separation Matrix

TraceCrypt strictly enforces separation between all cryptographic roles:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        Offline Root CA                                 │
│                   [ML-DSA-65 Root Signing Key]                         │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ Issues Certificates
         ┌─────────────────────────┴─────────────────────────┐
         ▼                                                   ▼
┌──────────────────────────────┐            ┌──────────────────────────────┐
│   Recipient Signing Key      │            │   Validator Consensus Key    │
│       [ML-DSA-65]            │            │       [ML-DSA-65]            │
│  Purpose: DIGITAL_SIGNATURE  │            │  Purpose: CONSENSUS_VOTING   │
└──────────────────────────────┘            └──────────────────────────────┘
         ▲
         │ Independent Keys
┌──────────────────────────────┐            ┌──────────────────────────────┐
│  Recipient Decryption Key    │            │    Document Encryption Key   │
│       [ML-KEM-768]           │            │       [AES-256-GCM]          │
│ Purpose: KEY_ENCAPSULATION   │            │   Purpose: PAYLOAD_ENCRYPT   │
└──────────────────────────────┘            └──────────────────────────────┘
```

1. **Algorithm Separation**: ML-KEM-768 public and private keys are strongly typed objects and cannot be passed to ML-DSA-65 signing functions. Passing an ML-KEM key to an ML-DSA function raises an immediate `TypeError` or `ValidationError`.
2. **Purpose Separation**: Identity certificates carry an immutable `key_purpose` field (`DIGITAL_SIGNATURE` or `KEY_ENCAPSULATION`). Validating a digital signature against a certificate issued for key encapsulation triggers `ValidationError(Check 10 Failed)`.
3. **Consensus Isolation**: Validator consensus keys belong to a distinct `NodeRole.VALIDATOR` profile and are never accepted as recipient decryption authorities.
4. **Key Derivation Domain Separation**: Keystore Argon2id derivation uses domain separation salts distinct from document encryption nonces and watermark frequency seeds.

---

## 4. Zeroization and Memory Disposal Guidelines

1. **Native Buffers & Bytearrays**: Where private key material is manipulated in native or C-level buffers, `ctypes.memset` or zero-fill passes (`b[:] = b"\x00" * len(b)`) overwrite memory prior to deallocation.
2. **Python Immutable Constraints**: Python `bytes` and `str` objects are immutable and managed by the CPython memory pool. Where direct zeroization is prevented by runtime semantics, TraceCrypt:
   - Encapsulates secrets in short-lived scopes.
   - Cleans references immediately in `finally:` blocks.
   - Explicitly invokes `gc.collect()` in sensitive crypto workers.
   - Avoids string interpolation or concatenation that leaves lingering string interning copies in memory.
