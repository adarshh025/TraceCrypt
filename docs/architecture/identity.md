# Identity & Public Key Infrastructure Architecture

## 1. System Overview

The TraceCrypt Identity Subsystem provides the post-quantum cryptographic identity and key-management infrastructure required across all subsequent phases (document distribution, watermark generation, and distributed ledger consensus).

The subsystem operates entirely offline, enforcing air-gap constraints and cryptographic role separation between confidentiality (ML-KEM) and non-repudiation (ML-DSA).

```
                      ┌────────────────────────────┐
                      │    Offline Root CA         │
                      │  (Master ML-DSA-65 Key)    │
                      └──────────────┬─────────────┘
                                     │
                    Issues Certified Identity Envelopes
                                     │
               ┌─────────────────────┴─────────────────────┐
               ▼                                           ▼
┌─────────────────────────────┐             ┌─────────────────────────────┐
│    Recipient Identity       │             │       Device Identity       │
├─────────────────────────────┤             ├─────────────────────────────┤
│ • ML-KEM-768 Key Pair       │             │ • ML-DSA-65 Key Pair        │
│   (Document Decryption)     │             │   (Workstation Attestation) │
│ • ML-DSA-65 Key Pair        │             │ • Hardware Telemetry        │
│   (Decryption Event Signing)│             │ • Device Certificate        │
│ • Identity Certificates     │             └─────────────────────────────┘
└─────────────────────────────┘
```

---

## 2. Subsystem Modular Breakdown

| Module | Responsibility |
| :--- | :--- |
| `tracecrypt.crypto.types` | Strongly-typed cryptographic representations (`MLKEMPublicKey`, `MLDSAPublicKey`, `KeyMetadata`, etc.) with memory zeroization logic and exact byte length assertions. |
| `tracecrypt.crypto.pqc_kem` | NIST FIPS 203 ML-KEM-768 key generation, encapsulation, and decapsulation with implicit rejection. |
| `tracecrypt.crypto.pqc_dsa` | NIST FIPS 204 ML-DSA-65 key generation, signature generation, and deterministic verification. |
| `tracecrypt.identity.ca` | Air-gapped Root Certificate Authority managing root key generation, certificate issuance, and keystore persistence. |
| `tracecrypt.identity.certificate`| Versioned `PQCIdentityCertificate` envelope, RFC 8785 canonical serialization, and 12-point offline validation engine. |
| `tracecrypt.identity.keystore` | Encrypted private key storage using Argon2id ($m=64\text{MB}, t=3, p=4$) + AES-256-GCM with canonical AAD metadata binding and Windows ACL hardening. |
| `tracecrypt.identity.lifecycle`| Monotonic key state machine, versioned key rotation preserving historical event verifiability, and offline signed revocation records. |
| `tracecrypt.identity.device` | Workstation device enrollment, hardware telemetry collection, and device certificate binding. |
| `tracecrypt.storage.sqlite_store`| Encrypted metadata persistence for certificates, keys, and revocation assertions. |
| `tracecrypt.cli.main` | Administrative CLI commands (`ca init`, `identity generate`, `identity list`, `identity verify`, `identity rotate`, `identity revoke`). |
| `tracecrypt.api.app` | Localhost-only HTTP REST management endpoints with security headers and administrative token authorization. |

---

## 3. Storage Layer Integration

The identity subsystem persists data through the `IdentityStore` protocol implemented by `SQLiteStorageManager`:

```sql
-- Certified identity envelopes
CREATE TABLE IF NOT EXISTS certificates (
    serial_number TEXT PRIMARY KEY,
    subject_id TEXT NOT NULL,
    issuer_id TEXT NOT NULL,
    role TEXT NOT NULL,
    key_purpose TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    valid_from INTEGER NOT NULL,
    valid_until INTEGER NOT NULL,
    certificate_json TEXT NOT NULL
);

-- Cryptographic key metadata (NO private key material stored here)
CREATE TABLE IF NOT EXISTS key_metadata (
    key_id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    purpose TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    status TEXT NOT NULL,
    version INTEGER NOT NULL,
    fingerprint TEXT NOT NULL,
    keystore_path TEXT NOT NULL,
    metadata_json TEXT NOT NULL
);

-- Signed offline revocation assertions
CREATE TABLE IF NOT EXISTS revocation_records (
    revocation_id TEXT PRIMARY KEY,
    serial_number TEXT NOT NULL,
    key_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    revoked_at INTEGER NOT NULL,
    revoked_by_ca_id TEXT NOT NULL,
    record_json TEXT NOT NULL
);
```

**Security Invariant:** Under no circumstances are plaintext private keys or passphrases saved in SQLite tables. Database records reference the filesystem path of the encrypted `EncryptedKeyContainer`.
