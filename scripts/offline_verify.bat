@echo off
setlocal
echo ======================================================================
echo TraceCrypt Air-Gapped Offline System Verification (Windows)
echo ======================================================================

set REPO_DIR=%~dp0\..
cd /d "%REPO_DIR%"

echo [*] Verification 1: System Doctor Diagnostics
python -m tracecrypt.cli doctor
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] TraceCrypt doctor diagnostics failed.
    exit /b 1
)

echo.
echo [*] Verification 2: Deterministic Post-Quantum Cryptographic Vectors (FIPS 203 and 204)
python -m pytest tests\vectors -q
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] Cryptographic reference test vectors failed.
    exit /b 1
)

echo.
echo [*] Verification 3: Air-Gap Operational Security Enforcement
python -m pytest tests\security\test_airgap.py -q
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] Air-gap network isolation test failed.
    exit /b 1
)

echo.
echo [*] Verification 4: Deterministic Golden End-to-End Attribution Pipeline
python -m pytest tests\forensics\test_end_to_end.py -q
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] Golden end-to-end workflow verification failed.
    exit /b 1
)

echo.
echo ======================================================================
echo [PASS] TraceCrypt verified ready for air-gapped production deployment.
echo ======================================================================
exit /b 0
