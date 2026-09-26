# Cryptographic Key Lifecycle & Rotation Architecture

## 1. Lifecycle State Machine Invariants

All cryptographic keys in TraceCrypt transition through explicit states defined in `KeyStatus`:
* `GENERATED`: Key material generated in volatile memory; metadata created.
* `PENDING_ACTIVATION`: Key saved in encrypted keystore container; pending administrative certificate issuance.
* `ACTIVE`: Fully certified by Root CA; actively used for digital signatures or decapsulations.
* `SUSPENDED`: Temporarily deactivated due to investigation or policy hold; can be resumed or permanently revoked.
* `EXPIRED`: Key validity period exceeded; no new operations permitted.
* `COMPROMISED`: Key compromised or suspected compromised; immediate revocation required.
* `REVOKED`: Key permanently invalidated; can never return to active service.
* `DESTROYED`: Encrypted container deleted; physical key material purged.

### Permitted vs. Prohibited Transition Matrix

| Current State | Permitted Destination States | Prohibited Destination States |
| :--- | :--- | :--- |
| `GENERATED` | `PENDING_ACTIVATION`, `DESTROYED` | `ACTIVE`, `SUSPENDED`, `REVOKED`, `EXPIRED`, `COMPROMISED` |
| `PENDING_ACTIVATION` | `ACTIVE`, `REVOKED`, `DESTROYED` | `GENERATED`, `SUSPENDED`, `EXPIRED`, `COMPROMISED` |
| `ACTIVE` | `SUSPENDED`, `REVOKED`, `EXPIRED`, `COMPROMISED` | `GENERATED`, `PENDING_ACTIVATION`, `DESTROYED` |
| `SUSPENDED` | `ACTIVE`, `REVOKED`, `COMPROMISED` | `GENERATED`, `PENDING_ACTIVATION`, `EXPIRED`, `DESTROYED` |
| `EXPIRED` | `REVOKED`, `DESTROYED` | `GENERATED`, `PENDING_ACTIVATION`, `ACTIVE`, `SUSPENDED`, `COMPROMISED` |
| `COMPROMISED` | `REVOKED`, `DESTROYED` | `GENERATED`, `PENDING_ACTIVATION`, `ACTIVE`, `SUSPENDED`, `EXPIRED` |
| `REVOKED` | `DESTROYED` | `GENERATED`, `PENDING_ACTIVATION`, `ACTIVE`, `SUSPENDED`, `EXPIRED`, `COMPROMISED` |
| `DESTROYED` | *None (Terminal)* | *All* |

---

## 2. Key Rotation with Historical Preservation

### 2.1 The Forensic Attribution Problem
In conventional PKI, certificate renewal or key replacement often replaces existing keys in-place. In a forensic document attribution platform, in-place key replacement is catastrophic:
* If Recipient $R$ signed a Decryption Event $E_1$ with Key $V_1$ on Day 1, and rotated to Key $V_2$ on Day 10, an audit conducted on Day 30 must verify $E_1$ using $V_1$.
* If $V_1$ were deleted or overwritten, $E_1$ would become unverifiable, destroying forensic chain of custody.

### 2.2 TraceCrypt Rotation Invariant
```
Recipient: rcp-01
├── Key Version 1 (V1) [REVOKED / SUPERSEDED]
│   └── Bound to Event E1 (Signed at T=1) ──► Independently Verifiable with V1 Cert
│
└── Key Version 2 (V2) [ACTIVE]
    └── Bound to Event E2 (Signed at T=12) ──► Independently Verifiable with V2 Cert
```

1. **State Update:** When `KeyLifecycleManager.rotate_key()` executes, Version $N$ is transitioned to `REVOKED` with `RevocationReason.SUPERSEDED`.
2. **Successor Creation:** Version $N+1$ is initialized with `version = N + 1`, new key IDs, and newly generated key material.
3. **Historical Isolation:**
   * The encrypted container and metadata for Version $N$ remain archived in the SQLite store and keys directory.
   * Signature verifiers look up the exact certificate matching the `key_id` and `timestamp` recorded inside the forensic event.
   * Events signed prior to revocation remain valid.
   * New events signed with Version $N$ after revocation are rejected immediately by `CertificateValidator`.
