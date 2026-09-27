# TraceCrypt Offline Upgrade & Version Migration Guide

**Version:** 1.0.0  
**Target:** Air-Gapped Workstations & Validator Nodes  

---

## 1. Upgrade Philosophy & Invariants

TraceCrypt implements a deterministic, fail-closed offline upgrade subsystem governed by `UpgradeManager` in `tracecrypt/storage/upgrade.py`:
1. **Zero Runtime Downloads:** Upgrades are delivered exclusively via versioned offline update packages (`TraceCrypt-<version>-offline-deployment-bundle.zip`).
2. **Mandatory Pre-Upgrade Backup Snapshot:** An upgrade cannot be applied without first generating an immutable verified `.tcbackup` archive.
3. **Strict Protocol Compatibility Verification:** Major version bumps that change canonical event formats or ledger rules reject incompatible state transitions unless explicit migration adapters exist.
4. **Transactional Database Migrations:** SQLite schema migrations are atomic (`BEGIN TRANSACTION` -> apply -> verify -> `COMMIT`). If any migration step fails, the database is rolled back immediately.
5. **Fail-Safe Post-Upgrade Validation:** An upgrade is only marked complete after `tracecrypt doctor` and `tracecrypt database check` report zero defects.

---

## 2. Upgrade Lifecycle Commands

The `tracecrypt upgrade` command family manages the four stages of system upgrades:

```
[1. check] ────► [2. prepare] ────► [3. apply] ────► [4. verify]
Compatibility     Pre-Upgrade        Database &         Doctor & State
Validation        Snapshot           Code Update        Verification
```

### Step 1: Check Upgrade Compatibility
Inspect whether the current system state can safely transition to the target version:
```cmd
tracecrypt upgrade check 1.0.0
```
Expected output:
```json
{
  "current_version": "1.0.0",
  "target_version": "1.0.0",
  "compatible": true,
  "requires_db_migration": false,
  "details": "Target version 1.0.0 is compatible with current protocol version 1.0.0"
}
```

### Step 2: Prepare Pre-Upgrade Backup
Generate a mandatory pre-upgrade snapshot covering ledger state, databases, certificates, and reports:
```cmd
tracecrypt upgrade prepare --output-dir backups/
```
Output:
```json
{
  "prepared": true,
  "backup_archive": "backups/pre_upgrade_1.0.0_20260928_120000.tcbackup",
  "verified": true,
  "component_count": 8
}
```

### Step 3: Apply Upgrade & Database Migrations
Deploy new application code files from the offline package, then execute transactional database migrations:
```cmd
tracecrypt upgrade apply
```
Output:
```json
{
  "status": "APPLIED",
  "current_version": "1.0.0",
  "migrations_applied": 0,
  "db_schema_version": 1
}
```

### Step 4: Verify Post-Upgrade System State
Verify cryptographic providers, ledger state, and environmental health:
```cmd
tracecrypt upgrade verify
```
Output:
```json
{
  "status": "HEALTHY",
  "doctor_status": "READY",
  "db_integrity": "OK",
  "protocol_version": "1.0.0"
}
```

---

## 3. Rollback & Disaster Recovery Runbook

If an upgrade fails during the `apply` stage or post-upgrade verification fails:
1. Stop all running validator nodes or TraceCrypt services.
2. Restore the pre-upgrade snapshot created in Step 2:
   ```cmd
   tracecrypt restore backups/pre_upgrade_1.0.0_20260928_120000.tcbackup --force
   ```
3. Re-verify the restored database:
   ```cmd
   tracecrypt database check
   ```
4. Run doctor diagnostics:
   ```cmd
   tracecrypt doctor
   ```
5. Confirm that the system has returned to the stable pre-upgrade state.
