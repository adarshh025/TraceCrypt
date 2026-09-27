# TraceCrypt Production Deployment Guide

**Version:** 1.0.0  
**Target Environment:** 100% Air-Gapped Windows x64 / Linux  
**Network Architecture:** Isolated LAN (Zero Internet Egress)  

---

## 1. Overview of Deployment Environments

TraceCrypt mandates strict physical or logical separation between five operational environments:

```
[Environment A: Root CA]
        │ Public Keys & Certs
        ▼
[Environment B: Sender] ────► [Environment C: Recipient] ────► [Environment D: 4-Node BFT Ledger]
     .tcdist Package                                                       │
                                                                           ▼ (Upon Leak)
                                                                [Environment E: Investigator]
```

---

## 2. Environment A: Root CA / Identity Authority

### Hardware & OS Requirements
- Dedicated air-gapped machine with disabled Wi-Fi, Bluetooth, and cellular hardware.
- USB port write-blocker for secure certificate transfer.
- OS: Windows 10/11 x64 or hardened Linux.
- Python 3.11 runtime (pre-installed via offline bundle).

### Deployment Steps
1. Extract TraceCrypt portable distribution:
   ```cmd
   cd C:\TraceCrypt
   scripts\offline_install.bat
   ```
2. Initialize Root CA with master passphrase:
   ```cmd
   tracecrypt ca init --ca-id ca-root-primary --passphrase <STRONG_MASTER_PASSPHRASE>
   ```
3. Verify Root CA status and public key fingerprint:
   ```cmd
   tracecrypt ca status
   ```
4. Export Root CA public key `ca_root_pub.bin` and public certificate `ca_root_cert.json` to read-only media for distribution to other workstations.

---

## 3. Environment B: Sender Workstation

### Purpose
Authoring and encrypting source documents into `.tcdist` packages.

### Deployment Steps
1. Install TraceCrypt offline:
   ```cmd
   scripts\offline_install.bat
   ```
2. Import Root CA public key into `data/ca/`:
   ```cmd
   copy D:\Certs\ca_root_pub.bin data\ca\
   ```
3. Import authorized recipient public certificates into `certs/recipients/`:
   ```cmd
   copy D:\Certs\rcp_*.json certs\recipients\
   ```
4. Packaging workflow:
   ```cmd
   tracecrypt encrypt \
       --input "C:\Briefings\classified_briefing.pdf" \
       --recipient-cert "certs\recipients\rcp_field_agent.json" \
       --output "C:\Outbox\classified_briefing.tcdist"
   ```

---

## 4. Environment C: Recipient Workstation

### Purpose
Secure document decryption, watermark embedding, event signing, and atomic release.

### Deployment Steps
1. Install TraceCrypt offline:
   ```cmd
   scripts\offline_install.bat
   ```
2. Generate recipient PQC credentials (enrolled by Root CA):
   ```cmd
   tracecrypt identity generate \
       --owner-id rcp-FIELD-OPERATIVE-01 \
       --org "Special Operations Directorate" \
       --passphrase <RECIPIENT_KEYSTORE_PASSWORD> \
       --ca-passphrase <ROOT_CA_PASSPHRASE>
   ```
3. Configure local ledger endpoint or replicated storage database in `config.json`.
4. Decryption & Attribution Gate execution:
   ```cmd
   python deployment/recipient/decrypt_and_attribute.py \
       --package "C:\Inbox\classified_briefing.tcdist" \
       --recipient-id rcp-FIELD-OPERATIVE-01 \
       --kem-key "C:\TraceCrypt\data\keys\rcp_kem.bin" \
       --dsa-key "C:\TraceCrypt\data\keys\rcp_dsa.bin" \
       --kem-cert "C:\TraceCrypt\data\keys\rcp_kem_cert.json" \
       --dsa-cert "C:\TraceCrypt\data\keys\rcp_dsa_cert.json" \
       --output "C:\Released\classified_briefing_viewable.pdf"
   ```

---

## 5. Environment D: 4-Node Permissioned BFT Consensus Network

### Reference Topology
Four validator nodes running on an isolated air-gapped subnet or loopback addresses:
- **Node 1:** `127.0.0.1:9101`
- **Node 2:** `127.0.0.1:9102`
- **Node 3:** `127.0.0.1:9103`
- **Node 4:** `127.0.0.1:9104`
- **Quorum:** $n=4, f=1$, Quorum threshold $= 2f + 1 = 3$ votes.

### Cluster Bootstrapping Steps
1. Execute the automated 4-node cluster bootstrapper:
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\bootstrap_four_node_ledger.ps1 -ClusterDir deployment/validator/cluster
   ```
   *(Or using Python directly: `python scripts/bootstrap_four_node_ledger.py --cluster-dir deployment/validator/cluster`)*

2. Verify all 4 nodes share identical genesis state and cryptographic state roots:
   ```cmd
   tracecrypt ledger status --cluster-dir deployment/validator/cluster
   ```

3. Verify cryptographic chain integrity from genesis to tip:
   ```cmd
   tracecrypt ledger verify --cluster-dir deployment/validator/cluster
   ```

4. Service Startup (Optional for continuous daemon execution):
   Launch each node in its own terminal or background process:
   ```cmd
   python deployment/validator/start_validator.py --node-dir deployment/validator/cluster/node-1
   python deployment/validator/start_validator.py --node-dir deployment/validator/cluster/node-2
   python deployment/validator/start_validator.py --node-dir deployment/validator/cluster/node-3
   python deployment/validator/start_validator.py --node-dir deployment/validator/cluster/node-4
   ```

---

## 6. Environment E: Forensic Investigator Workstation

### Purpose
Ingestion of leaked artifacts, blind watermark extraction, ledger querying, Merkle verification, and legal proof package generation.

### Deployment Steps
1. Install TraceCrypt offline:
   ```cmd
   scripts\offline_install.bat
   ```
2. Configure read-only access to validator ledger storage (`ledger.db`) or synchronized peer node.
3. Import Root CA public key `ca_root_pub.bin`.
4. Ingest leaked artifact and execute full investigation:
   ```cmd
   tracecrypt investigate "C:\Evidence\leaked_scan.pdf" \
       --case-id "cas-2026-HQ-LEAK-01" \
       --node-dir "deployment/validator/cluster/node-1" \
       --output-report "reports/forensic_report.pdf" \
       --output-proof "reports/case_proof.tcproof"
   ```
5. Independent Standalone Verification (For court or third-party audit):
   ```cmd
   tracecrypt verify-bundle "reports/case_proof.tcproof"
   ```
