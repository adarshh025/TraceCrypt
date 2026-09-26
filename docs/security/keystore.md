# Argon2id Keystore & Private Key Container Specification

## 1. Overview & Threat Model

Private cryptographic keys (ML-KEM-768 decapsulation keys and ML-DSA-65 signing keys) represent high-value targets. If an adversary obtains offline filesystem access to an air-gapped node, unencrypted private keys would permit unauthorized document decapsulation and forgery of forensic events.

TraceCrypt mandates that **no plaintext private key is ever stored on disk**. All private key material is stored within self-contained, authenticated encrypted containers (`EncryptedKeyContainer`).

---

## 2. Cryptographic Construction

The keystore construction employs a two-stage cryptographic pipeline:

```
                      [ User / Root Passphrase ]
                                  │
                                  ▼
                ┌──────────────────────────────────┐
                │             Argon2id             │
                │  m=64MB, t=3, p=4, 16-byte Salt  │
                └──────────────────────────────────┘
                                  │
                                  ▼
                    [ 256-bit Key-Encryption Key ]
                                  │
                                  ▼
                ┌──────────────────────────────────┐
                │           AES-256-GCM            │
                │     12-byte Nonce, 16-byte Tag   │
                │       RFC 8785 Canonical AAD     │
                └──────────────────────────────────┘
                                  │
                                  ▼
                  [ Encrypted Private Key File ]
```

### 2.1 Password-Based Key Derivation: Argon2id
* **Standard:** RFC 9106 / NIST SP 800-132.
* **Algorithm:** Argon2id (hybrid variant offering optimal defense against side-channel and GPU/ASIC attacks).
* **Cost Parameters:**
  * **Memory Cost ($m$):** 65,536 KiB (64 MiB).
  * **Time Cost ($t$):** 3 iterations.
  * **Parallelism ($p$):** 4 threads.
  * **Salt:** 16 bytes generated from cryptographically secure entropy (`os.urandom`).
  * **Output Length:** 32 bytes (256 bits for AES-256).

### 2.2 Authenticated Symmetric Encryption: AES-256-GCM
* **Standard:** NIST SP 800-38D.
* **Key:** 256-bit derived key from Argon2id.
* **Nonce:** 96-bit (12-byte) unique IV generated via `SecureRandom.random_bytes(12)`.
* **Authentication Tag:** 128-bit (16-byte) GMAC tag ensuring plaintext integrity and authenticity.

### 2.3 Authenticated Associated Data (AAD) Metadata Binding
To prevent metadata manipulation (such as swapping key IDs, altering algorithms, or reassigning key ownership), the container metadata is bound into the AES-GCM authentication tag:
```json
{
  "format_version": "1.0.0",
  "container_id": "cnt-01...",
  "key_id": "key-rcp-01-dsa-v1",
  "owner_id": "rcp-operative-42",
  "algorithm": "ML-DSA-65",
  "parameter_set": "ML-DSA-65",
  "purpose": "DIGITAL_SIGNATURE",
  "public_key_fingerprint": "mldsa65:sha3-256:...",
  "created_at": 1774579200000000
}
```
* The metadata dictionary is normalized using **RFC 8785 JSON Canonicalization Scheme (JCS)**.
* The canonical bytes are passed as the `associated_data` parameter to AES-GCM.
* Any unauthorized modification of the container JSON metadata invalidates the tag and results in immediate, fail-closed rejection with `CryptographicError`.

---

## 3. Host-Level Filesystem Security (Windows ACLs)

On the Windows host operating system, filesystem permissions must prevent lateral access by unprivileged local accounts:
* When a keystore file is written, `_harden_file_permissions()` executes Windows `icacls`.
* Inheritance is stripped: `/inheritance:r`.
* Full access is granted strictly to the current executing user: `/grant:r %USERNAME%:F`.
* On POSIX operating systems, fallback mode `0600` is applied.

---

## 4. In-Memory Handling & Zeroization Limitations

### 4.1 CPython Memory Limitations
In pure Python running on CPython:
* Python's standard `bytes` objects are immutable and allocated through the internal CPython obmalloc pool.
* Python provides no language-level guarantee of physical RAM zeroization upon variable deletion (`del`), as memory recycling and garbage collection reside within the C runtime and OS paging manager.
* Operating systems may swap memory pages to disk (pagefile.sys or swap partitions).

### 4.2 Architectural Mitigations
TraceCrypt applies the strongest practical controls available in the Python runtime:
1. **Mutable Buffers:** Intermediate key-encryption keys and decapsulated shared secrets utilize mutable `bytearray` buffers where appropriate.
2. **Explicit Overwriting:** Mutable buffers implement a zeroization loop overwriting all elements with zeroes (`buf[i] = 0`) before disposal.
3. **Shortened Lifetimes:** Private keys are loaded only for the duration of the cryptographic operation (signing or decapsulation) and released immediately.
4. **Zero-Leak Logging:** Logging and exception handlers redact any field matching `*key*`, `*secret*`, or `*passphrase*`. No private key material is ever included in exception messages, debug dumps, or CLI stdout.
