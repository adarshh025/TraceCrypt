# TraceCrypt Offline Disaster Recovery & Backup Runbook

**Classification:** OPERATIONAL RECOVERY SPECIFICATION (AIR-GAPPED ENCLAVES)  
**Standard Compliance:** NIST SP 800-34 Rev. 1 (Contingency Planning Guide for Federal Information Systems)  

---

## 1. Cryptographic Backup Architecture

In a strict air-gap environment, all backups must be created and transported via dual-custody encrypted offline media (e.g. FIPS 140-3 Level 3 USB drives).

```
                      +-----------------------------+
                      |  TraceCrypt Air-Gap Assets  |
                      +--------------+--------------+
                                     |
         +---------------------------+---------------------------+
         |                                                       |
         v                                                       v
+------------------------+                              +------------------------+
| PUBLIC ASSETS (Raw)   |                              | PRIVATE SECRETS        |
| - Root CA Public Cert  |                              | - CA Private Key (sk)  |
| - Validator Pub Keys   |                              | - Recipient Private sk |
| - Ledger SQLite DB     |                              | - Validator Private sk |
| - State Checkpoints    |                              +-----------+------------+
| - .tcproof Bundles     |                                          |
+------------------------+                                          v
                                                        +------------------------+
                                                        | Argon2id + AES-256-GCM |
                                                        | Encrypted Keystores    |
                                                        | (.tckeystore)          |
                                                        +------------------------+
```

> **CRITICAL RULE:** Private keys must NEVER be backed up in plaintext. All private cryptographic material must reside in standard Argon2id-encrypted keystores (`.tckeystore`) requiring a high-entropy passphrase.

---

## 2. Backup Procedures

### 2.1 Root CA Backup
1. Export the public Root CA certificate:
   ```bash
   python -m tracecrypt.cli ca export-cert --ca-dir ./ca --output ./backup/ca_root.cert
   ```
2. Backup the password-protected encrypted private key container:
   ```bash
   cp ./ca/root_ca.tckeystore ./backup/ca_root.tckeystore
   ```

### 2.2 Ledger State & Monotonic Checkpoints
1. Ensure SQLite database is in a consistent state:
   ```sql
   PRAGMA wal_checkpoint(TRUNCATE);
   ```
2. Copy the database file and monotonic checkpoint verification file:
   ```bash
   cp ./ledger/node_0/ledger.db ./backup/ledger_node0.db
   cp ./ledger/node_0/ledger.checkpoint ./backup/ledger_node0.checkpoint
   ```

---

## 3. Disaster Recovery Scenarios

### Scenario A: Loss of 1 Validator Node ($f = 1$)
- **Symptom**: 1 of the 4 nodes goes offline or suffers hardware failure.
- **Recovery Procedure**:
  1. The remaining 3 honest nodes continue operating seamlessly without interruption (quorum $2f + 1 = 3$ satisfied).
  2. Provision a replacement workstation in the enclave.
  3. Copy the latest `ledger.db` and `genesis.json` from any active honest node.
  4. Restore the validator's certified keystore.
  5. Launch the node; it synchronizes any missing blocks from peers via loopback/LAN transport.

### Scenario B: SQLite Database Corruption on a Node
- **Symptom**: Node reports `sqlite3.DatabaseError: database disk image is malformed` on startup.
- **Recovery Procedure**:
  1. Stop the corrupted validator node process.
  2. Quarantine corrupted file: `mv ledger.db ledger.db.corrupted`.
  3. Copy the verified SQLite database from another honest validator node.
  4. Verify chain integrity:
     ```bash
     python -m tracecrypt.cli ledger verify-chain --db ./ledger/ledger.db
     ```
  5. Restart node.

### Scenario C: Workstation Loss / Destruction
- **Symptom**: Recipient or Investigator physical laptop destroyed or lost.
- **Recovery Procedure**:
  1. Notify Enclave Security Officer immediately.
  2. Revoke the lost identity's certificate at the Root CA:
     ```bash
     python -m tracecrypt.cli ca revoke --serial <SERIAL_NUMBER> --reason UNSPECIFIED
     ```
  3. Export and distribute the updated `OfflineRevocationStore` across enclave nodes.
  4. Provision new workstation, re-enroll identity, issue fresh certificate.

### Scenario D: Interrupted Transaction / Sudden Power Loss
- **Symptom**: Power lost during proposal or block persistence.
- **Recovery Procedure**:
  1. TraceCrypt uses SQLite WAL mode with synchronous atomic transactions and an external `.checkpoint` monotonic counter.
  2. Upon boot, `LedgerStorage.initialize()` executes SQLite automatic WAL recovery.
  3. If the checkpoint matches the block height, the node resumes normally. If a partial block was written, it is rolled back automatically.

### Scenario E: Temporary Network Partition (e.g. 2 + 2 Split)
- **Symptom**: Enclave switch cable disconnected; 2 nodes separated from other 2.
- **Behavior**:
  - Quorum requires $\ge 3$ validators.
  - Neither partition can reach quorum. Block production halts safely (safety preserved; zero divergent forks created).
- **Recovery**:
  - Reconnect the network link.
  - Honest nodes exchange missing votes and resume block production within 1 consensus round.
