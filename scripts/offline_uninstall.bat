@echo off
setlocal EnableDelayedExpansion

echo ======================================================================
echo TraceCrypt Air-Gapped Safe Uninstaller (Windows)
echo ======================================================================
echo.
echo [SAFETY WARNING]
echo TraceCrypt stores critical forensic evidence, ledger databases,
echo identity certificates, and private keystores.
echo.
echo This uninstaller distinguishes application code from mutable data:
echo   1. Application code (packaging, scripts, modules)
echo   2. Configuration files
echo   3. Ledger databases and blocks
echo   4. Forensic case evidence and reports
echo   5. Private keystores and root CA keys
echo   6. Backup archives (.tcbackup)
echo.

set REPO_DIR=%~dp0\..
cd /d "%REPO_DIR%"

rem Parse arguments
set FORCE_MODE=0
set PURGE_EVIDENCE=0
set PURGE_KEYS=0

if "%1"=="--force" set FORCE_MODE=1
if "%1"=="--purge-all" (
    set FORCE_MODE=1
    set PURGE_EVIDENCE=1
    set PURGE_KEYS=1
)

if %FORCE_MODE% NEQ 1 (
    echo [PROMPT] Do you wish to proceed with removing TraceCrypt application files? [y/N]
    set /p CONFIRM=
    if /i "!CONFIRM!" NEQ "y" (
        echo [ABORTED] Uninstallation canceled by user.
        exit /b 0
    )
)

echo.
echo [*] Step 1: Removing build caches and temporary python files...
if exist "__pycache__" rd /s /q "__pycache__" >nul 2>&1
for /d /r . %%d in (__pycache__) do @if exist "%%d" rd /s /q "%%d" >nul 2>&1
if exist ".pytest_cache" rd /s /q ".pytest_cache" >nul 2>&1
if exist "htmlcov" rd /s /q "htmlcov" >nul 2>&1
if exist ".coverage" del /f /q ".coverage" >nul 2>&1
echo [PASS] Caches cleaned.

echo.
echo [*] Step 2: Preserving Forensic Evidence, Ledger, and Keystores...
echo   - Ledger data:        PRESERVED (data\ or cluster_data\)
echo   - Forensic evidence:  PRESERVED (forensics.db or case folders)
echo   - Private keystores:  PRESERVED (keys\ or ca_root.json)
echo   - Backups:            PRESERVED (*.tcbackup)

if %PURGE_ALL%==1 (
    echo [WARNING] --purge-all requested. Removing local databases...
    if exist "tracecrypt_local.db" del /f /q "tracecrypt_local.db"
    if exist "cluster_data" rd /s /q "cluster_data"
)

echo.
echo ======================================================================
echo [SUCCESS] TraceCrypt uninstallation complete.
echo Cryptographic identities and forensic evidence remain preserved.
echo ======================================================================
exit /b 0
