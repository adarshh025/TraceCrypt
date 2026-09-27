# TraceCrypt Offline Installation Guide (Air-Gapped Enclaves)

**Target Environment:** Windows 10/11 (64-bit), Offline Air-Gapped Workstations  
**Internet Access:** Zero internet connectivity required or permitted.  

---

## 1. Prerequisites Checklist

Ensure the target air-gapped machine has:
- Windows 10/11 x64
- Python 3.11.9 installed in PATH
- Git 2.54.0+ installed
- CPython 3.11 site-packages containing:
  - `cryptography`
  - `pydantic`
  - `numpy`, `scipy`
  - `opencv-python` (`cv2`)
  - `Pillow` (`PIL`)
  - `pypdf`, `reportlab`
  - `dilithium_py`, `mlkem`

---

## 2. Step-by-Step Offline Installation

### Step 1: Copy TraceCrypt Repository Media
Mount the verified, virus-scanned USB media into the air-gapped workstation and copy the release directory:
```cmd
xcopy D:\TraceCrypt C:\TraceCrypt /E /I /H /Y
cd C:\TraceCrypt
```

### Step 2: Run Offline Installer
Execute the automated Windows offline installer:
```cmd
scripts\offline_install.bat
```
This batch script:
1. Validates Python runtime version $\ge 3.11$.
2. Verifies presence of all 11 required libraries.
3. Sets up local `PYTHONPATH` pointing to `C:\TraceCrypt`.
4. Runs `tracecrypt doctor` self-check.

### Step 3: Run Offline Verification
Execute the offline system verification:
```cmd
scripts\offline_verify.bat
```
Expected output:
```text
[*] Verification 1: System Doctor Diagnostics ... [PASS]
[*] Verification 2: Deterministic PQC Vectors (FIPS 203 & 204) ... [PASS]
[*] Verification 3: Air-Gap Operational Security Enforcement ... [PASS]
[*] Verification 4: Deterministic Golden End-to-End Attribution ... [PASS]
[PASS] TraceCrypt verified ready for air-gapped production deployment.
```

---

## 3. Environment Self-Check (`tracecrypt doctor`)

To manually run the system diagnostic doctor:
```cmd
python -m tracecrypt.cli doctor
```
Or via installed CLI entry point:
```cmd
tracecrypt doctor
```

The diagnostic performs individual checks:
- Python Version Check: `[PASS] Python 3.11.9 detected`
- Core Libraries Check: `[PASS] All 10 required packages imported successfully`
- Post-Quantum Cryptography: `[PASS] NIST FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65) available`
- Database Engine: `[PASS] SQLite 3 available (WAL mode enabled)`
- Filesystem Access: `[PASS] Read/write access verified`
- Offline Air-Gap Mode: `[PASS] Air-gap guard active (no external sockets permitted)`
