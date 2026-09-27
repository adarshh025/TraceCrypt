# TraceCrypt Production Security Model & Controls

**Version:** 1.0.0  
**Classification:** Operational Cryptographic Security Standard  
**Standard:** NIST FIPS 203, NIST FIPS 204, RFC 8785, Argon2id  

---

## 1. Development vs. Production Modes

TraceCrypt strictly enforces separation between four execution environments:
`development`, `test`, `benchmark`, `production`.

### Production Mode Enforcements:
- **DEBUG Logging Disabled:** All verbose tracing and secret-bearing debug output is suppressed.
- **Mock / Toy Crypto Rejection:** Any attempt to substitute NIST FIPS 203 ML-KEM-768 or NIST FIPS 204 ML-DSA-65 with classical algorithms (RSA, ECDSA) or mock placeholders raises a fatal `SecurityError`.
- **Zero Test Keys Allowed:** Test keypairs and hardcoded seeds are rejected in production.
- **Fake Ledger Shortcuts Blocked:** Transactions must commit through genuine BFT quorum before documents can be released.
- **Fail-Closed CORS & Bindings:** Internal API servers bind exclusively to `127.0.0.1` and reject cross-origin requests.

---

## 2. Key Protection & Argon2id Keystore Specification

All private keys stored on disk are protected using password-authenticated key derivation and authenticated symmetric encryption:

### Cryptographic Parameters:
```
Algorithm:       Argon2id (RFC 9106)
Memory Cost (m): 64 MB (65,536 KB)
Time Cost (t):   3 iterations
Parallelism (p): 4 threads
Cipher:          AES-256-GCM
Nonce:           96-bit CSPRNG (SecureRandom)
Metadata:        RFC 8785 JCS bound in AAD
```

### Filesystem Hardening (Windows):
Private keystore files on Windows are locked down using `icacls.exe`:
- Inheritance removed (`/inheritance:r`).
- Read/Write granted exclusively to the active operating system user (`/grant:r "%USERNAME%:(R,W)"`).
- All world-readable and group-readable permissions stripped.

---

## 3. Ephemeral In-Memory Zeroization

TraceCrypt enforces memory zeroization for all decrypted plaintexts, Content-Encryption Keys (CEK), and private keys:
- `SecureDocumentBuffer` encapsulates plaintext documents in memory.
- `finally:` blocks explicitly overwrite byte arrays with zeroes (`0x00`) using `ctypes.memset` or buffer manipulation before deallocation.
- Python garbage collection is forced (`gc.collect()`) following sensitive operations.
- Plaintext documents are **NEVER** written to unencrypted temporary files on disk.

---

## 4. Production Directory Layout

General data is strictly isolated from secret-bearing material:

```
C:\TraceCrypt\
├── data/
│   ├── config/          # Read-only configuration files
│   ├── database/        # SQLite WAL metadata store
│   ├── ledger/          # BFT blocks and transaction index
│   ├── keys/            # Argon2id encrypted private keystores (LOCKED ACLs)
│   ├── certificates/    # Public certificates and CRLs (World-readable)
│   ├── cases/           # Forensic evidence (Read-only copy-on-ingest)
│   ├── reports/         # PDF investigation reports and .tcproof bundles
│   └── backups/         # .tcbackup archives
└── logs/                # Structured operational logs (Redacted identifiers only)
```

---

## 5. Secure Startup Validation Pipeline

Every production service and CLI invocation performs mandatory pre-flight checks:
1. **Runtime Verification:** Confirms 64-bit Python $\ge 3.11$ and presence of native C extensions.
2. **Cryptographic Self-Test:** Generates and validates an ephemeral ML-KEM encapsulation and ML-DSA signature.
3. **Database Integrity Check:** Runs SQLite `PRAGMA integrity_check` and verifies WAL journal mode.
4. **Ledger Chain Verification:** Confirms block hashes from genesis to tip match canonical headers.
5. **Air-Gap Assertion:** Verifies zero network interfaces bound to external subnets.

---

## 6. Vulnerability Severity Model

TraceCrypt applies a standardized five-tier vulnerability severity model:

| Severity | Scope and Impact | Remediation Standard |
| :--- | :--- | :--- |
| **CRITICAL** | Flaws leading to arbitrary cryptographic key compromise, forged attribution events, bypassed BFT safety, or remote/local code execution. | Immediate hotfix; release gate blocked. |
| **HIGH** | Flaws causing ledger state divergence, denial of service across consensus nodes, unauthenticated document decapsulation, or directory traversal. | Fix required prior to production release. |
| **MEDIUM** | Incomplete input sanitization, unhandled parser edge cases causing process termination, or non-deterministic verdict evaluation. | Fix required with regression test. |
| **LOW** | Minor information disclosure in local logs, non-standard exception types, or missing resource boundary assertions. | Remediation in scheduled maintenance cycle. |
| **INFORMATIONAL**| Security hygiene, defensive hardening suggestions, or operational best practice enhancements. | Tracked for continuous improvement. |

---

## 7. Fundamental Attribution Boundary Notice

TraceCrypt establishes cryptographic non-repudiation between a document decryption event and a certified NIST FIPS 204 ML-DSA-65 private key. TraceCrypt does not independently authenticate the biological identity of the human operator operating the hardware device. Physical attribution is enforced via complementary physical security controls, facility badges, and endpoint monitoring.
