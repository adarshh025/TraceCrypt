# TraceCrypt Backup, Restore & Disaster Recovery Runbook

**Version:** 1.0.0  
**Specification:** Master Prompt 11 - Sections 17 & 18  

---

## 1. Backup Subsystem Architecture

TraceCrypt implements a cryptographically verifiable archive format (`.tcbackup`) managed by `BackupManager` in `tracecrypt/storage/backup.py`.

### Architectural Guarantees:
1. **Component-Level Cryptographic Integrity:** Every included file has its SHA-256 and SHA3-256 computed and bound in a signed `manifest.json`.
2. **Private Key Isolation:** Private keystores (`*.json` containing private keys or binary `*_priv.bin`) are **STRICTLY EXCLUDED** by default. Inclusion requires explicit operator confirmation (`--include-keystores`).
3. **ZipSlip Traversal Defense:** Path normalization rejects any component attempting directory traversal outside the target root.
4. **Protocol & Schema Version Binding:** Archives enforce protocol version and ledger schema version compatibility upon restore.

---

## 2. Backup CLI Commands

### Create a Verifiable Backup
```cmd
tracecrypt backup create \
    --output "backups/tc_state_20260928.tcbackup" \
    --description "Routine operational state backup"
```

### Verify Backup Archive Integrity
```cmd
tracecrypt backup verify "backups/tc_state_20260928.tcbackup"
```
Output:
```
============================================================
           TRACECRYPT BACKUP VERIFICATION REPORT
============================================================
Backup File        : tc_state_20260928.tcbackup
Backup ID          : 3e81d1d2297413c2deb0530ad694f924
Timestamp          : 2026-09-28T01:00:00Z
Application Version: 1.0.0
Protocol Version   : 1.0.0
Components Included: 11
Integrity Status   : [PASS] ALL CHECKS CLEAN
============================================================
```

### Restore from Backup
```cmd
tracecrypt restore "backups/tc_state_20260928.tcbackup" --target-dir "C:\TraceCrypt\data" --force
```

---

## 3. Disaster Recovery Runbooks: 8 Critical Scenarios

### Scenario 1: Single Validator Node Lost
- **Impact:** Network operates at $n=3$, which still satisfies the $2f+1=3$ quorum requirement ($f=1$).
- **Remediation:**
  1. Provision a new replacement machine.
  2. Copy `genesis.json` and node configuration from cluster root.
  3. Generate a replacement validator identity or restore the lost node's key from cold custody.
  4. Launch the replacement node: `python deployment/validator/start_validator.py --node-dir <path>`.
  5. The node initiates the state sync catch-up protocol from the remaining 3 active peers.

### Scenario 2: One Validator Database Corrupted
- **Impact:** Startup verification fails with `Cryptographic integrity violation detected`.
- **Remediation:**
  1. Stop the failing node immediately.
  2. Remove the corrupted `ledger.db` and WAL files: `del ledger.db*`.
  3. Start the node. The node initializes clean genesis and automatically catch-up synchronizes all finalized blocks from peer nodes.

### Scenario 3: Recipient Workstation Lost
- **Impact:** Recipient private keys destroyed; device cannot decrypt subsequent `.tcdist` packages.
- **Remediation:**
  1. Root CA issues a revocation certificate for the lost recipient certificate:
     `tracecrypt identity revoke --serial <SERIAL> --reason UNSPECIFIED`.
  2. Provision a new recipient identity: `tracecrypt identity generate --owner-id rcp-NEW-01`.
  3. Historical attribution records already committed to the BFT ledger remain permanent and non-repudiated.

### Scenario 4: Investigator Workstation Lost
- **Impact:** Local workstation cache lost.
- **Remediation:**
  1. Install TraceCrypt on a new workstation: `scripts\offline_install.bat`.
  2. Connect to the read-only ledger mirror or restore the forensic cases backup.
  3. Standalone `.tcproof` bundles previously exported remain verifiable on any machine without database state.

### Scenario 5: Ledger Backup Restored
- **Impact:** Reverting ledger state to an earlier height.
- **Remediation:**
  1. Execute `tracecrypt restore <archive> --force`.
  2. Run `tracecrypt ledger verify` to ensure chain integrity is unbroken.
  3. Nodes with missing blocks catch up via state synchronization.

### Scenario 6: Configuration Accidentally Modified
- **Impact:** `tracecrypt doctor` or `tracecrypt config validate` fails closed.
- **Remediation:**
  1. Run `tracecrypt config validate`.
  2. Restore the golden production template from `deployment/configs/production.json`.
  3. Re-run `tracecrypt doctor` to confirm `STATUS: READY`.

### Scenario 7: Invalid or Tampered Backup Supplied
- **Impact:** Corrupted file digest or unauthorized component modification.
- **Remediation:**
  1. `tracecrypt backup verify <archive>` detects SHA-256 / SHA3-256 hash divergence.
  2. Restore engine aborts immediately before modifying disk files (`FAIL CLOSED`).
  3. Quarantine the compromised archive and inspect provenance.

### Scenario 8: Backup from Incompatible Protocol Version Supplied
- **Impact:** Attempting to restore a backup across incompatible breaking protocol versions.
- **Remediation:**
  1. `tracecrypt backup verify` checks `protocol_version`.
  2. If the major version is incompatible, `verify_protocol_compatibility()` raises `ProtocolVersionIncompatibleError`.
  3. Restore engine refuses to apply incompatible database state.
