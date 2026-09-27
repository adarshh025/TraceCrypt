@echo off
rem TraceCrypt Command-Line Launcher for Windows
rem Air-Gapped Forensic Document Attribution Platform

setlocal

set "SCRIPT_DIR=%~dp0"
set "APP_ROOT=%SCRIPT_DIR%..\.."

rem Set PYTHONPATH to include application root
if defined PYTHONPATH (
    set "PYTHONPATH=%APP_ROOT%;%PYTHONPATH%"
) else (
    set "PYTHONPATH=%APP_ROOT%"
)

rem Check for python
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python runtime not found in PATH.
    echo TraceCrypt requires Python 3.11+ in an air-gapped environment.
    exit /b 1
)

python -m tracecrypt %*
exit /b %ERRORLEVEL%
