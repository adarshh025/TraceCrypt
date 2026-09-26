# Offline Root CA Initialization Ceremony & Trust Runbook

## 1. Scope & Objective

The TraceCrypt Root Certificate Authority (Root CA) anchors trust for all cryptographic identities, workstation enrollments, and forensic certificates.

Because the Root CA controls the master **NIST FIPS 204 ML-DSA-65** signing key, its key generation and initialization ceremony must be conducted under strict operational security protocols within an isolated, air-gapped environment.

---

## 2. Ceremony Prerequisites

1. **Physical Facility:** Secure, access-controlled clean room (Faraday shielding recommended).
2. **Ceremony Machine:** Dedicated air-gapped workstation with all wireless, Bluetooth, and cellular hardware physically removed or disabled in firmware.
3. **Operating Environment:** Verified clean offline OS installation with no persistent network configurations.
4. **Participants:** Minimum two-person integrity (Ceremony Officer and Independent Security Auditor).
5. **Storage Media:** Two brand-new, write-once physical media (e.g., optical discs or hardware-encrypted offline flash storage).

---

## 3. Step-by-Step Ceremony Execution

### Step 1: Pre-Flight Environment & Entropy Verification
Verify that the host environment is strictly disconnected from all network interfaces and that cryptographic self-tests pass:
```powershell
python -m tracecrypt.cli system-check
python -m pytest tests/unit/test_random.py tests/unit/test_pqc_dsa.py
```

### Step 2: Initialize Root CA Key Pair
Execute the offline initialization command via the TraceCrypt CLI:
```powershell
python -m tracecrypt.cli ca init --ca-id "ca-root-airgap-01" --passphrase "<HIGH_ENTROPY_PASSPHRASE>"
```

**Underlying Cryptographic Actions:**
* Generates 4,032-byte ML-DSA-65 private key and 1,952-byte public key using `os.urandom`.
* Derives a 256-bit Key-Encryption Key via **Argon2id** ($m=64\text{MB}, t=3, p=4$).
* Encrypts the private key into `ca_root.json` using **AES-256-GCM** with RFC 8785 canonical metadata binding.
* Issues self-signed Root Identity Certificate `ca_root_cert.json` valid for 10 years (3,650 days).

### Step 3: Fingerprint Verification & Physical Recording
Record the deterministic public key fingerprint:
```powershell
python -m tracecrypt.cli ca status
```
* Note down the canonical SHA3-256 fingerprint (e.g. `mldsa65:sha3-256:7f4c...`).
* The Auditor and Ceremony Officer independently sign the physical ceremony record attesting to the exact fingerprint string.

### Step 4: Secure Backup & Dual-Custody Safe Storage
1. Copy the encrypted `ca_root.json` and `ca_root_cert.json` to Backup Media #1 and Backup Media #2.
2. The high-entropy passphrase is split using a manual $M$-of-$N$ threshold scheme or sealed in two tamper-evident envelopes.
3. Media #1 and Envelope #1 are transferred to Primary Physical Vault A.
4. Media #2 and Envelope #2 are transferred to Secondary Off-Site Vault B.

### Step 5: Public Certificate Deployment
Distribute **only** the public certificate (`ca_root_cert.json`) and public key (`ca_root_pub.json`) to operational workstations. Under no circumstances is `ca_root.json` (the encrypted private key) copied to operational recipient workstations.

### Step 6: Memory Zeroization & Ephemeral Shutdown
* Delete any temporary script outputs or staging folders.
* Perform hard power-off of the ceremony workstation.
