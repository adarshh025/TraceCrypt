# TraceCrypt Offline Installation & Air-Gap Verification Guide

**Version:** 1.0.0  
**Standard:** 100% Offline / Zero Runtime Package Downloads  
**Supported Platforms:** Windows 10/11 x64, Windows Server 2022, Hardened Linux  

---

## 1. Zero-Download Guarantee

TraceCrypt is designed from first principles for air-gapped forensic and military intelligence environments. During installation and execution, the system:
- **NEVER** calls `pip`, `npm`, `cargo`, `winget`, `choco`, `apt`, `yum`, or `pacman`.
- **NEVER** invokes `curl`, `wget`, `git clone`, or socket requests to external registries.
- **NEVER** queries public DNS, external PKI, or cloud KMS services.
- **NEVER** loads runtime JavaScript, fonts, or assets from CDNs.

If an essential dependency is missing or corrupted, the installer **fails closed immediately** with a descriptive diagnostic error.

---

## 2. Release Package Contents

The official air-gapped release consists of:

```
TraceCrypt-1.0.0-offline-deployment-bundle/
├── install/
│   ├── offline_install.bat      # Windows automated installer
│   ├── offline_verify.bat       # Full integrity verification suite
│   ├── offline_uninstall.bat    # Safe uninstaller (preserves evidence)
│   ├── tracecrypt.bat           # CLI launcher for Command Prompt
│   └── tracecrypt.ps1           # CLI launcher for PowerShell
├── manifests/
│   └── DEPENDENCIES.json        # Manifest with SHA-256 and SHA3-256 hashes
├── deployment/
│   ├── ca/                      # Root CA templates and operational scripts
│   ├── sender/                  # Sender encryption profiles
│   ├── recipient/               # Recipient attribution gate scripts
│   ├── validator/               # 4-node BFT cluster configuration
│   ├── investigator/            # Forensic investigation scripts
│   ├── configs/                 # Production and development configs
│   └── schemas/                 # JSON schemas for config, event, proof, backup
├── RELEASE_MANIFEST.json        # Machine-readable release metadata
├── SHA256SUMS                   # Cryptographic SHA-256 checksums
└── SHA3SUMS                     # Cryptographic SHA3-256 checksums
```

---

## 3. Step-by-Step Installation Runbook

### Step 1: Media Transfer
Transfer the release archive to the air-gapped workstation using optical disc (CD-R / DVD-R / BD-R) or hardware-write-blocked USB storage.

### Step 2: Extraction
Extract the archive into your target directory (e.g. `C:\TraceCrypt`):
```cmd
mkdir C:\TraceCrypt
tar -xf TraceCrypt-1.0.0-Windows-x64-portable.zip -C C:\TraceCrypt
cd C:\TraceCrypt
```

### Step 3: Run Automated Offline Installer
Execute `offline_install.bat`:
```cmd
scripts\offline_install.bat
```
The installer executes the following deterministic steps:
1. Validates Python runtime version ($\ge 3.11$).
2. Validates availability of the 16 core mathematical and cryptographic libraries:
   `cryptography`, `pydantic`, `numpy`, `scipy`, `opencv-python`, `pillow`, `fastapi`, `uvicorn`, `aiosqlite`, `sqlalchemy`, `pdfminer.six`, `reportlab`, `pypdf`, `pypdfium2`, `dilithium-py`, `mlkem`.
3. Configures local `PYTHONPATH` and CLI wrappers.
4. Executes `tracecrypt doctor` diagnostic checks.

### Step 4: Run Formal Air-Gap Verification
Execute the air-gap verification script to confirm zero outbound network egress:
```cmd
python scripts\verify_airgap.py
```
Expected output:
```
======================================================================
        TRACECRYPT AIR-GAP ASSURANCE & ZERO-EGRESS VERIFIER        
======================================================================
[1/3] Running Static AST Code Inspection across tracecrypt/...
  -> [PASS] Zero forbidden cloud/telemetry/egress imports detected.

[2/3] Auditing Project Dependencies (pyproject.toml)...
  -> [PASS] Dependency set is 100% offline-compatible.

[3/3] Executing Dynamic Runtime Egress Interception Test...
[PASS] Runtime
[PASS] ML-KEM-768
[PASS] ML-DSA-65
[PASS] AES-256-GCM
[PASS] SQLite WAL
[PASS] PKI configuration
[PASS] Ledger configuration
[PASS] Zeroization configuration
[PASS] Offline dependency set

STATUS: READY
  -> [PASS] Zero outbound socket, DNS, or HTTP egress attempts recorded.

======================================================================
AIR-GAP VERIFICATION STATUS: [COMPLIANT - ZERO NETWORK EGRESS]
TraceCrypt performs zero outbound network communication.
======================================================================
```

### Step 5: Run Full Release Smoke Test
Confirm complete end-to-end functionality across all subsystems:
```cmd
tracecrypt smoke-test
```
When all 11 stages report `[PASS]`, the installation is certified ready for operational deployment.
