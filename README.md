# TraceCrypt: Offline Post-Quantum Forensic Document Attribution Platform

**Version:** 1.0.0  
**Build Target:** Air-Gapped Environments (Windows x64 / Linux)  
**Security Standard:** 100% Offline, Zero Network Egress, Post-Quantum Cryptography  

TraceCrypt is a production-grade, fully offline, air-gapped forensic document attribution platform. It enforces cryptographic non-repudiation on document access by embedding unique, invisible transform-domain watermarks at the moment of decryption, committing digitally signed canonical attribution events into an offline permissioned BFT ledger, and providing deterministic forensic adjudication when leaks occur.

---

## 1. Cryptographic Baseline & Architecture

TraceCrypt operates without cloud KMS, external certificate authorities, public blockchains, SaaS dependencies, or telemetry.

* **NIST FIPS 203 (ML-KEM-768):** Post-quantum key encapsulation for multi-recipient document distribution.
* **NIST FIPS 204 (ML-DSA-65):** Post-quantum digital signatures over canonical RFC 8785 attribution events and BFT consensus messages.
* **Symmetric Encryption:** AES-256-GCM with unique 256-bit Content-Encryption Keys (CEK) and 96-bit nonces.
* **Hashing & Digest:** NIST FIPS 202 SHA3-256 with explicit domain separation prefixes.
* **Key Derivation & Protection:** Argon2id ($m=64\text{ MB}, t=3, p=4$) keystores with Windows `icacls` ACL lockdown.
* **Forensic Watermarking:** 2D Haar DWT + 8x8 block DCT spread-spectrum modulation in mid-frequency subbands with Systematic Reed-Solomon RS(32, 16) error correction.
* **Permissioned BFT Ledger:** Tendermint-inspired round progression ($n=4, f=1$, Quorum $= 3$) with binary Merkle inclusion proofs.
* **Forensic Engine:** Deterministic 9-state adjudication state machine outputting verifiable `.tcproof` bundles and signed PDF reports.

---

## 2. System Deployment Topology

```
                      ┌────────────────────────┐
                      │    OFFLINE ROOT CA     │
                      │ NIST FIPS 204 ML-DSA   │
                      └───────────┬────────────┘
                                  │ Certified Keys
         ┌────────────────────────┼────────────────────────┐
         ▼                        ▼                        ▼
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────────┐
│  SENDER STATION  │    │  RECIPIENT GATE  │    │ 4-NODE BFT CONSENSUS │
│ AES-256-GCM Enc  │    │ ML-KEM Decaps    │    │ Node-1 (Port 9101)   │
│ ML-KEM Wrap      ├───►│ DWT-DCT Watermark├───►│ Node-2 (Port 9102)   │
│ .tcdist Envelope │    │ ML-DSA Signature │    │ Node-3 (Port 9103)   │
└──────────────────┘    │ Zeroization Gate │    │ Node-4 (Port 9104)   │
                        └──────────────────┘    └──────────┬───────────┘
                                                           │
                                                           ▼ (Upon Leak)
                                                ┌──────────────────────┐
                                                │ INVESTIGATOR STATION │
                                                │ Blind DWT-DCT Extract│
                                                │ Merkle Verification  │
                                                │ 9-State Adjudication │
                                                │ Standalone .tcproof  │
                                                └──────────────────────┘
```

---

## 3. Operational Command-Line Interface

TraceCrypt provides a unified production CLI entrypoint accessible via `tracecrypt` (or `python -m tracecrypt`):

### Diagnostic & System Health
```bash
# Verify air-gapped system readiness across all 9 operational categories
tracecrypt doctor

# Run full release smoke test across all 11 subsystem stages
tracecrypt smoke-test

# Display platform, post-quantum baseline, and protocol versioning
tracecrypt version
```

### Identity & Certificate Authority
```bash
# Initialize Root CA
tracecrypt ca init --ca-id ca-root-primary --passphrase <MASTER_PASSPHRASE>

# Generate certified recipient credentials
tracecrypt identity generate --owner-id rcp-AGENT-ALPHA --passphrase <KEYSTORE_PASS> --ca-passphrase <CA_PASS>

# Inspect certificate details and public key fingerprint
tracecrypt identity inspect --recipient-id rcp-AGENT-ALPHA
```

### Encryption, Packaging & Decryption
```bash
# Encrypt and package document for authorized recipient(s)
tracecrypt encrypt --input briefing.pdf --recipient-cert certs/agent_alpha.json --output briefing.tcdist

# Validate .tcdist package offline (17-point structural & cryptographic check)
tracecrypt document validate briefing.tcdist
```

### Ledger & Validator Cluster Administration
```bash
# Bootstrap 4-node reference BFT ledger cluster
python scripts/bootstrap_four_node_ledger.py --cluster-dir deployment/validator/cluster

# Inspect cluster consensus state across all nodes
tracecrypt ledger status --cluster-dir deployment/validator/cluster

# Verify cryptographic chain integrity from genesis to tip
tracecrypt ledger verify --cluster-dir deployment/validator/cluster
```

### Forensic Investigation & Independent Attribution
```bash
# Ingest leaked artifact and execute full deterministic investigation
tracecrypt investigate leaked_scan.pdf \
    --node-dir deployment/validator/cluster/node-1 \
    --output-report reports/forensic_report.pdf \
    --output-proof reports/case_proof.tcproof

# Independently verify standalone proof bundle (.tcproof) without database connection
tracecrypt verify-bundle reports/case_proof.tcproof
```

### Backup, Database & Upgrades
```bash
# Create cryptographically verified .tcbackup archive
tracecrypt backup create --output backups/backup_20260928.tcbackup

# Verify backup checksums and component integrity
tracecrypt backup verify backups/backup_20260928.tcbackup

# Transactional database schema check and migration
tracecrypt database check
tracecrypt database migrate

# Offline system upgrade management
tracecrypt upgrade check 1.0.0
tracecrypt upgrade verify
```

---

## 4. Offline Installation & Air-Gap Verification

### Clean Machine Installation
1. Copy the release bundle (`TraceCrypt-1.0.0-Windows-x64-portable.zip` or `TraceCrypt-1.0.0-offline-deployment-bundle.zip`) to the target machine via approved optical disc or hardware-write-blocked media.
2. Extract the archive into `C:\TraceCrypt`.
3. Execute the automated air-gapped installation script:
   ```cmd
   scripts\offline_install.bat
   ```
4. Run the automated air-gap and egress verification script:
   ```cmd
   python scripts/verify_airgap.py
   ```
5. Confirm operational readiness:
   ```cmd
   tracecrypt doctor
   ```

---

## 5. Demonstration & Automated Verification

TraceCrypt includes a 23-step end-to-end demonstration workflow that runs completely offline:
```cmd
python scripts/demo_full_workflow.py
```
This tests every stage from Root CA initialization through encryption, decapsulation, watermarking, signing, BFT ledger commit, exfiltration simulation, blind extraction, Merkle verification, forensic verdict derivation, and standalone independent verification.

---

## 6. Documentation Index

Comprehensive engineering, architectural, operational, and security documentation is located in the `docs/` directory:

| Document | Purpose |
|:---|:---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Complete system architecture, trust boundaries, data flow, key flow, and ledger diagrams |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Step-by-step air-gapped deployment for CA, Sender, Recipient, Validators, and Investigator |
| [docs/OFFLINE_INSTALLATION.md](docs/OFFLINE_INSTALLATION.md) | Offline installation, dependency bundles, and zero-egress verification procedures |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Administrator and operator runbooks for daily maintenance and cluster operations |
| [docs/UPGRADE.md](docs/UPGRADE.md) | Offline version upgrade, pre-upgrade snapshots, database migrations, and rollback |
| [docs/BACKUP_RECOVERY.md](docs/BACKUP_RECOVERY.md) | `.tcbackup` management and disaster recovery runbooks across 8 critical scenarios |
| [docs/SECURITY.md](docs/SECURITY.md) | Security model, zeroization invariants, Argon2id parameters, and ACL lockdowns |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Adversary models, attack vectors, mitigations, and formal security boundaries |
| [docs/FORENSIC_WORKFLOW.md](docs/FORENSIC_WORKFLOW.md) | Blind extraction, 9-state verdict state machine, and `.tcproof` structure |
| [docs/PROTOCOL_VERSIONING.md](docs/PROTOCOL_VERSIONING.md) | Semantic protocol versioning rules and cross-version compatibility matrix |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Diagnosis and remediation for common environmental and consensus faults |
| [docs/THIRD_PARTY_NOTICES.md](docs/THIRD_PARTY_NOTICES.md) | Third-party software licenses and intellectual property notices |
| [docs/RELEASE_TRACEABILITY.md](docs/RELEASE_TRACEABILITY.md) | Requirements traceability matrix mapping FR, NFR, SEC, R, and T items to tests |
| [CHANGELOG.md](CHANGELOG.md) | Semantic release notes and historical milestone tracking |

---

## 7. License

Proprietary / Internal Operational License. All rights reserved.
See [LICENSE](LICENSE) and [docs/THIRD_PARTY_NOTICES.md](docs/THIRD_PARTY_NOTICES.md) for full terms.
