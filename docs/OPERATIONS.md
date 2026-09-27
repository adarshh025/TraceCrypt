# TraceCrypt Operations & Administration Runbook

**Version:** 1.0.0  
**Classification:** Operational Security / Air-Gapped Environments  

---

## 1. Operational CLI Commands Summary

TraceCrypt provides a strictly typed, comprehensive command-line suite:

| Command | Subcommands | Purpose |
|:---|:---|:---|
| `tracecrypt doctor` | *(none)* | Comprehensive 9-point environmental & security health check |
| `tracecrypt smoke-test`| *(none)* | Automated 11-stage full subsystem verification |
| `tracecrypt version` | *(none)* | Displays product, protocol, and cryptographic suite versions |
| `tracecrypt config` | `validate` | Validates active configuration against fail-closed rules |
| `tracecrypt security` | `airgap-check` | Asserts air-gap isolation and zero-egress state |
| `tracecrypt ca` | `init`, `status` | Offline Root Certificate Authority management |
| `tracecrypt identity` | `generate`, `list`, `inspect`, `verify`, `rotate`, `revoke` | PQC identity lifecycle and certificate management |
| `tracecrypt document` | `hash`, `package`, `validate`, `recipients`, `decrypt` | Document encryption and `.tcdist` handling |
| `tracecrypt watermark`| `embed`, `extract`, `benchmark`, `attack-test` | Forensic watermarking diagnostics and testing |
| `tracecrypt ledger` | `init`, `start`, `status`, `blocks`, `block`, `verify`, `tx`, `event`, `watermark`, `proof`, `validators` | BFT consensus and ledger querying |
| `tracecrypt validator`| `init`, `status`, `start` | Individual validator node lifecycle administration |
| `tracecrypt forensic` | `investigate`, `verify`, `extract` | Leaked document attribution and proof verification |
| `tracecrypt verify-bundle` | `<file>` | Standalone proof verification without database trust |
| `tracecrypt backup` | `create`, `verify`, `restore` | Cryptographically signed `.tcbackup` management |
| `tracecrypt database`| `version`, `check`, `migrate` | SQLite WAL schema versioning and transactional migrations |
| `tracecrypt upgrade` | `check`, `prepare`, `apply`, `verify` | Deterministic offline software version upgrades |

---

## 2. Daily Health Check Procedure

At the beginning of each operational shift, run the doctor command:
```cmd
tracecrypt doctor
```

Verify that all checks return `[PASS]` and the final status is `STATUS: READY`.

If `STATUS: NOT READY` is returned:
1. Review the failing category (Runtime, ML-KEM, ML-DSA, AES-GCM, SQLite WAL, PKI, Ledger, Zeroization, or Offline dependencies).
2. Check `docs/TROUBLESHOOTING.md` for specific remediation steps.
3. Do **NOT** attempt document encryption or decryption while doctor reports failures.

---

## 3. Secure Structured Logging Policy

TraceCrypt enforces strict structured logging standards to avoid secret leakage:

### Permitted Log Identifiers
- `DocumentID` (e.g. `doc-381ec118...`)
- `DistributionID` (e.g. `dst-67f763f6...`)
- `SessionID` (e.g. `ses-4475006f...`)
- `WatermarkID` (e.g. `wm-890ea424...`)
- `EventID` (e.g. `evt-439f0b43...`)
- `TransactionID` (e.g. `tx-c4185988...`)
- `BlockHeight` (e.g. `Height: 42`)
- `ValidatorID` (e.g. `val-e586c2c3...`)
- `CaseID` (e.g. `cas-0a0b4f31...`)

### Prohibited Log Contents (Strict Redaction)
- **NEVER** log raw or decrypted document text.
- **NEVER** log Content-Encryption Keys (CEK) or Key-Wrap Keys (KWK).
- **NEVER** log private keys (ML-KEM or ML-DSA) or keystore passphrases.
- **NEVER** log watermark carrier seeds or unmasked watermark bitstreams.
- **NEVER** log unencrypted user credentials.

---

## 4. Key Rotation & Revocation Runbook

### Key Rotation
When an operative rotates their cryptographic credentials (e.g. annual scheduled rotation):
```cmd
tracecrypt identity rotate \
    --owner-id rcp-AGENT-01 \
    --passphrase <NEW_PASSPHRASE> \
    --ca-passphrase <ROOT_CA_PASSPHRASE>
```
*Note: Historical decryption events signed by prior keys remain permanently verifiable through the archived public certificate ledger records.*

### Certificate Revocation
If a workstation or credential is compromised:
```cmd
tracecrypt identity revoke \
    --serial crt-74f114eb8ad77732f7fbad76b3a9de57 \
    --reason KEY_COMPROMISE \
    --ca-passphrase <ROOT_CA_PASSPHRASE>
```
The revocation is written to the offline CRL store. Subsequent decapsulation and release attempts using this certificate will fail closed.
