# Workstation Device Enrollment & Hardware Identity

## 1. Objective & Architecture

In an offline deployment, documents and forensic decryption events originate from designated physical workstations. TraceCrypt implements a structured device enrollment subsystem (`DeviceEnrollmentManager`) that anchors every device in the offline PKI:

1. **Device ID Allocation:** A unique, typed identifier (`DeviceID`, e.g. `dev-ws-alpha-01`).
2. **Device Post-Quantum Key Pair:** An ML-DSA-65 signing key pair generated locally on the workstation.
3. **Root CA Certification:** Issuance of an official `PQCIdentityCertificate` signed by the Root CA with `role="DEVICE"`.
4. **Local Hardware Telemetry Collection:** Capture of hardware baseline metrics for behavioral anomaly detection.

---

## 2. Hardware Fingerprinting: Risks & Limitations

### 2.1 Critical Security Notice
**Hardware fingerprinting DOES NOT constitute cryptographic proof of device identity.**

Relying solely on physical or OS hardware attributes introduces severe vulnerabilities:
* **MAC Address Spoofing:** Network interface MAC addresses can be trivially modified in OS settings or emulated in virtual environments.
* **Virtualization & Hypervisor Clones:** In virtual machine deployments (Hyper-V, KVM, VMware), virtual CPU identifiers, BIOS serials, and disk UUIDs can be cloned across multiple physical hosts.
* **Hardware Replacement:** Legitimate motherboard, network card, or disk replacement alters hardware fingerprints, potentially causing denial of service.

### 2.2 TraceCrypt Defense-in-Depth Approach
TraceCrypt uses hardware attributes strictly as **secondary telemetry signals**:
* **Cryptographic Identity is Primary:** Proof of device identity is established exclusively through possession of the device's certified post-quantum private key (`MLDSAPrivateKey`).
* **Telemetry as Audit Signals:** Machine GUID, hostname, OS kernel version, and CPU architecture are captured into a deterministic SHA3-256 fingerprint (`DeviceTelemetry`).
* **Discrepancy Reporting:** When a device signs a decryption event, changes in hardware telemetry trigger security audit warnings rather than immediate automated denial of service.

---

## 3. Enrollment & Re-Enrollment Workflow

### 3.1 Initial Device Enrollment
```
Workstation                          Offline Root CA
    │                                       │
    ├─ 1. Collect Device Telemetry          │
    ├─ 2. Generate ML-DSA-65 Device Key     │
    ├─ 3. Submit Enrollment Request ───────►│
    │                                       ├─ 4. Verify Administrator Authorization
    │                                       ├─ 5. Issue Device Identity Certificate
    │◄──────── 6. Return Certificate ───────┘
    ├─ 7. Store Key in Argon2 Keystore
    └─ 8. Persist Device Record in SQLite
```

### 3.2 Re-Enrollment on Hardware Modification
If physical components are upgraded:
1. An administrator issues an offline revocation record for the previous device certificate (Reason: `SUPERSEDED`).
2. A new ML-DSA-65 key pair is generated on the modified workstation.
3. The administrator signs a new device certificate, linking the existing `DeviceID` to the new post-quantum public key.
4. Historical event logs signed under the previous certificate remain verifiable.
