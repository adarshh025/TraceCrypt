@echo off
setlocal
cd /d "%~dp0\.."
echo ======================================================================
echo TraceCrypt Release Gate Execution
echo ======================================================================
python scripts\release_gate.py
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Release gate failed with exit code %ERRORLEVEL%.
    exit /b %ERRORLEVEL%
)
echo [SUCCESS] Release gate completed successfully.
exit /b 0
