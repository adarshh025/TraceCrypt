# TraceCrypt Air-Gapped Incident Response Runbook

**Document Version:** 1.0.0  
**Classification:** Operational Security Runbook  
**Applicability:** Air-Gapped Key Custodians, Security Officers, Ledger Administrators  

---

## 1. Incident Response Framework

All incident response procedures in TraceCrypt operate strictly **offline** without external network dependencies:

```
[DETECTION / ALERT] ──> [CONTAINMENT & ISOLATION] ──> [EVIDENCE PRESERVATION]
                                                             │
                                                             ▼
[REPORTING & POST-MORTEM] <── [SYSTEM RECOVERY] <── [REVOCATION & ROTATION]
```

---

## 2. Incident Playbooks

### Playbook 1: Compromised Recipient Key
- **Containment:** Immediately remove the compromised recipient's workstation from the operational facility.
- **Evidence Preservation:** Take a bit-stream forensic disk image of the workstation's local storage.
- **Revocation:** Issue a signed revocation certificate from the Offline Root CA:
  ```powershell
  tracecrypt pki revoke-cert --cert-serial "<SERIAL>" --reason "KEY_COMPROMISE" --out "crl.json"
  ```
- **Ledger Handling:** Publish the updated CRL / revocation transaction to the BFT validator cluster.
- **Certificate Handling:** Re-issue new certified keypairs (ML-KEM-768 and ML-DSA-65) with unique serial numbers.
- **Forensic Verification:** Future forensic investigations will evaluate decryptions after the revocation epoch as `CERTIFICATE_REVOKED_PRIOR` (Verdict V4).

### Playbook 2: Compromised Validator Node
- **Containment:** Stop the affected validator node process immediately (`kill` or service shutdown).
- **Evidence Preservation:** Archive the node's local database (`ledger.db`) and WAL files.
- **Consensus Quorum:** In an $n=4, f=1$ network, the remaining 3 validators continue normal consensus operation.
- **Validator Rotation:**
  1. Root CA revokes the compromised validator certificate.
  2. Generate a new validator identity and ML-DSA-65 keypair.
  3. Reconfigure the active validator set in the ledger genesis/governance state.
  4. Bring the new validator online and sync state from healthy peers.

### Playbook 3: Compromised Offline Root CA
- **Containment:** Immediately declare a complete cryptographic epoch reset across all facilities.
- **Evidence Preservation:** Secure physical custody of the CA hardware security module or air-gapped machine.
- **Remediation:**
  1. Initialize a new Root CA with a fresh ML-DSA-65 master keypair:
     ```powershell
     python deployment/ca/init_ca.py --ca-dir "data/ca_new" --common-name "TraceCrypt-Root-CA-Epoch2"
     ```
  2. Distribute the new Root CA public certificate (`ca_root_cert.pem`) to all senders, recipients, and validators via certified write-once media (e.g. optical CD-R).
  3. Re-issue certificates for all active participants under Epoch 2.

### Playbook 4: Suspected Watermark Manipulation / Adversarial Bleed
- **Containment:** Quarantine the leaked document artifact.
- **Evidence Preservation:** Compute and record SHA-256 and SHA3-256 hashes of the artifact; log custody actions.
- **Investigation:**
  1. Run multi-angle extraction and deskewing.
  2. Inspect Reed-Solomon symbol syndrome error count.
  3. If multi-page splicing is detected, the engine deterministically yields `AMBIGUOUS`.
  4. If carrier correlation is below noise threshold, the engine yields `UNVERIFIABLE`.

### Playbook 5: Suspected Ledger Tampering
- **Containment:** Pause write operations on the suspected validator node.
- **Verification:**
  ```powershell
  tracecrypt doctor
  tracecrypt ledger verify-chain --db "data/ledger.db"
  ```
- **Remediation:** If local database blocks fail header hash or Merkle verification, purge the corrupted SQLite database and re-sync from an authentic peer validator.

### Playbook 6: Lost or Stolen Recipient Workstation
- **Containment:** Revoke the device's ML-KEM and ML-DSA certificates immediately.
- **Security Invariant:** Private keys on disk are protected with Argon2id ($m=64\text{MB}, t=3, p=4$) and AES-256-GCM. Without the passphrase, offline brute force is computationally infeasible.
- **Recovery:** Provision a replacement workstation with a fresh User ID and certified keypair.

### Playbook 7: Stolen Encrypted Distribution Package (.tcdist)
- **Risk Assessment:** `.tcdist` files are encrypted with AES-256-GCM using a Content-Encryption Key wrapped via NIST FIPS 203 ML-KEM-768.
- **Containment:** The thief cannot decrypt the document unless they possess both the `.tcdist` package AND the private key of an authorized recipient specified in the package header.
- **Action:** If the recipient's private key is also suspected of compromise, revoke that recipient's certificate immediately.

### Playbook 8: Suspected Forged Forensic Report
- **Verification:** Execute the standalone independent verifier against the evidence bundle (`.tcproof`):
  ```powershell
  python -m tracecrypt.forensics.standalone_verifier --report-bundle "report.tcproof" --root-cert "ca_root_cert.pem"
  ```
- **Remediation:** If the report or evidence was modified, the bundle digest, Merkle proof, or ML-DSA-65 signature checks will fail, producing an explicit tampering warning.

### Playbook 9: Database Corruption (SQLite WAL Error)
- **Containment:** Stop the affected service.
- **Recovery:** Re-apply the latest verified `.tcbackup` snapshot:
  ```powershell
  python -c "from tracecrypt.storage.backup import BackupManager; bm = BackupManager('data'); bm.restore_backup('data/backups/latest.tcbackup')"
  ```

### Playbook 10: Malicious Software Detected on Workstation
- **Containment:** Disconnect the workstation completely from local LAN; power down immediately.
- **Evidence Preservation:** Remove storage media for offline forensic imaging.
- **Remediation:** Re-image workstation from certified offline golden image; restore application binaries from verified `release/TraceCrypt-1.0.0-Windows-x64-portable.zip`.
