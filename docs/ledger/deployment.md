# TraceCrypt 4-Node Local Cluster Deployment Guide

## 1. Quick Start with `run_ledger_cluster.py`

TraceCrypt provides a development and operational cluster runner script at `scripts/run_ledger_cluster.py`.

### Step 1: Initialize 4-Node Cluster Genesis
```bash
python scripts/run_ledger_cluster.py --cluster-dir C:\TraceCrypt\cluster_data init
```
This command:
1. Generates an offline Root CA for the consensus cluster.
2. Creates 4 distinct validator private keys and identities (`node-1` through `node-4`).
3. Issues ML-DSA-65 validator identity certificates.
4. Generates a canonical `genesis.json` binding the validator set and initial state root.

### Step 2: Check Cluster Status
```bash
python scripts/run_ledger_cluster.py --cluster-dir C:\TraceCrypt\cluster_data status
```
Inspects all 4 validator databases, reporting heights, committed block hashes, and state roots to verify cryptographic lockstep.

### Step 3: Inject Forensic Decryption Event
```bash
python scripts/run_ledger_cluster.py --cluster-dir C:\TraceCrypt\cluster_data inject
```
Submits a signed `DecryptionEvent` transaction to `node-1`'s mempool.

### Step 4: Step Consensus Round
```bash
python scripts/run_ledger_cluster.py --cluster-dir C:\TraceCrypt\cluster_data step
```
Executes a deterministic BFT consensus round across all active validators, committing the pending transactions into Block 1.

### Step 5: Verify Chain Integrity Across Cluster
```bash
python scripts/run_ledger_cluster.py --cluster-dir C:\TraceCrypt\cluster_data verify
```
Runs end-to-end chain verification on all node SQLite databases.

### Step 6: Simulate Byzantine / Offline Validator Fault
```bash
python scripts/run_ledger_cluster.py --cluster-dir C:\TraceCrypt\cluster_data simulate-failure
```
Shuts down `node-4` and executes consensus with only 3 nodes, proving that $f=1$ fault tolerance succeeds ($3 \ge 2f + 1$).

---

## 2. CLI Usage Reference

TraceCrypt also exposes first-class CLI commands for direct validator administration:

```bash
# Query status of local validator
tracecrypt ledger status --db-path ./data/ledger.db

# Verify local chain from genesis to tip
tracecrypt ledger verify --db-path ./data/ledger.db

# Inspect block at height 1
tracecrypt ledger block 1 --db-path ./data/ledger.db

# Lookup committed transaction
tracecrypt ledger tx tx-26db6d48... --db-path ./data/ledger.db

# Lookup committed event by EventID
tracecrypt ledger event evt-238cf63c... --db-path ./data/ledger.db

# Lookup event by WatermarkID (forensic correlation)
tracecrypt ledger watermark wm-39589bcf... --db-path ./data/ledger.db

# Export standalone cryptographic Merkle inclusion proof
tracecrypt ledger proof tx-26db6d48... --db-path ./data/ledger.db --out proof.json
```
