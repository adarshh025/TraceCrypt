# Key Management and Cryptographic Lifecycle

## 1. Scope & Security Model

The TraceCrypt Key Management Subsystem governs the end-to-end lifecycle of post-quantum asymmetric keys across air-gapped workstations. Key management enforces:
* Cryptographic role separation (KEM vs. DSA).
* Deterministic state transitions preventing credential reuse or un-revocation.
* Historical event auditability through immutable versioning.
* Strong authenticated encryption at rest (Argon2id + AES-256-GCM).

---

## 2. Key Metadata & Identification

Every cryptographic key in TraceCrypt is paired with an immutable `KeyMetadata` record:

| Field | Type | Description |
| :--- | :--- | :--- |
| `key_id` | `str` | Globally unique identifier with typed prefix (e.g., `key-rcp-01-dsa-v1`). |
| `owner_id` | `str` | Identity of the certified subject (e.g., `rcp-agent-alpha` or `dev-ws-01`). |
| `purpose` | `KeyPurpose` | `DIGITAL_SIGNATURE`, `KEY_ENCAPSULATION`, or `ROOT_AUTHORITY`. |
| `algorithm` | `str` | `ML-DSA-65` or `ML-KEM-768`. |
| `parameter_set`| `str` | `ML-DSA-65` or `ML-KEM-768`. |
| `created_at` | `int` | POSIX microsecond timestamp of key generation. |
| `activated_at` | `Optional[int]` | Microsecond timestamp when transition to `ACTIVE` occurred. |
| `expires_at` | `Optional[int]` | Microsecond timestamp of credential expiration. |
| `status` | `KeyStatus` | Current lifecycle state. |
| `version` | `int` | Monotonically increasing integer starting at 1. |
| `fingerprint` | `str` | Deterministic SHA3-256 digest of canonical public key bytes. |

---

## 3. Key Lifecycle State Machine

The key lifecycle follows a strict monotonic directed acyclic graph (with controlled suspension):

```
       [ GENERATED ]
             │
             ▼
    [ PENDING_ACTIVATION ]
             │
             ├──────────────────────────┐
             ▼                          ▼
        [ ACTIVE ] ◄──────────► [ SUSPENDED ]
             │                          │
      ┌──────┼───────────────┬──────────┘
      ▼      ▼               ▼
  [EXPIRED] [COMPROMISED] [REVOKED]
      │              │       │
      └──────┬───────┘       │
             ▼               ▼
               [ DESTROYED ]
```

### 3.1 Permitted Transitions
* `GENERATED` $\to$ `PENDING_ACTIVATION`, `DESTROYED`
* `PENDING_ACTIVATION` $\to$ `ACTIVE`, `REVOKED`, `DESTROYED`
* `ACTIVE` $\to$ `SUSPENDED`, `REVOKED`, `EXPIRED`, `COMPROMISED`
* `SUSPENDED` $\to$ `ACTIVE`, `REVOKED`, `COMPROMISED`
* `EXPIRED` $\to$ `REVOKED`, `DESTROYED`
* `COMPROMISED` $\to$ `REVOKED`, `DESTROYED`
* `REVOKED` $\to$ `DESTROYED`
* `DESTROYED` $\to$ None (terminal state).

### 3.2 Prohibited Transitions & Invariants
* **No Un-Revocation:** Once a key enters `REVOKED` or `DESTROYED`, it can **never** transition back to `ACTIVE` or `SUSPENDED`. Attempting to do so raises `SecurityError`.
* **Fail-Closed State Checks:** Signature generation and decryption decapsulation verify that the active key status is strictly `ACTIVE`. Any other status halts operations immediately.

---

## 4. Key Rotation Architecture

When an operational key reaches its expiration window or periodic rotation threshold:

1. **Version Increment:** The active key (Version $N$) is transitioned to `REVOKED` (Reason: `SUPERSEDED`).
2. **Successor Generation:** A new key pair (Version $N+1$) is generated and certified by the Root CA.
3. **Historical Event Independence:**
   * Forensic decryption events signed with Version $N$ remain **permanently verifiable** against the public key and certificate of Version $N$.
   * Rotating to Version $N+1$ does **not** invalidate historical ledger entries or alter historical attribution.
   * Ledger verifiers resolve the public certificate corresponding to the historical event timestamp and key version, verifying the signature independently of current active keys.

---

## 5. Anti-Replay Mechanisms

TraceCrypt enforces three layers of anti-replay validation:
1. **Key ID Uniqueness:** Database schemas reject duplicate key IDs via primary key constraints.
2. **Certificate Serial Uniqueness:** Every certificate carries a random 128-bit UUID serial (`crt-...`). Re-issuing the same serial raises `StorageError`.
3. **Monotonic Versioning:** During rotation, key versioning must strictly increment ($N+1 > N$). Replays of old key versions are rejected during verification.
