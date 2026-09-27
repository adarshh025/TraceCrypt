@echo off
setlocal
echo ======================================================================
echo TraceCrypt Air-Gapped Offline Installer (Windows)
echo ======================================================================

set REPO_DIR=%~dp0\..
cd /d "%REPO_DIR%"

echo [*] Step 1: Checking Python runtime...
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] Python is not installed or not in PATH.
    exit /b 1
)
python -c "import sys; assert sys.version_info >= (3, 11), 'Python >= 3.11 required'" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] Python version must be >= 3.11.
    exit /b 1
)
for /f "tokens=*" %%i in ('python --version') do echo [PASS] Found %%i

echo [*] Step 2: Checking offline prerequisites...
python -c "import cryptography, pydantic, numpy, scipy, cv2, PIL, pypdf, reportlab, dilithium_py, mlkem" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [WARN] Some packages missing from default environment.
    echo [*] Checking local wheel cache in .\wheels or pip cache...
    if exist "%REPO_DIR%\wheels" (
        echo [*] Installing cached wheels without internet...
        python -m pip install --no-index --find-links="%REPO_DIR%\wheels" -r requirements.txt
    ) else (
        echo [*] Installing package locally via setuptools...
        python setup.py develop --no-deps >nul 2>&1
    )
) else (
    echo [PASS] All 11 core cryptographic and forensic libraries are already available.
)

echo [*] Step 3: Configuring TraceCrypt local CLI...
set PYTHONPATH=%REPO_DIR%;%PYTHONPATH%

echo [*] Step 4: Running TraceCrypt offline self-check (doctor)...
python -m tracecrypt.cli doctor
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] TraceCrypt offline self-check encountered warnings or errors.
    exit /b %ERRORLEVEL%
)

echo ======================================================================
echo [SUCCESS] TraceCrypt offline installation and configuration complete.
echo Run 'scripts\offline_verify.bat' to verify system integrity.
echo ======================================================================
exit /b 0
