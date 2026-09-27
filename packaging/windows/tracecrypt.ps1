# TraceCrypt Command-Line Launcher for Windows (PowerShell)
# Air-Gapped Forensic Document Attribution Platform

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$AppRoot = (Resolve-Path "$ScriptDir\..\..").Path

if ($env:PYTHONPATH) {
    $env:PYTHONPATH = "$AppRoot;$env:PYTHONPATH"
} else {
    $env:PYTHONPATH = "$AppRoot"
}

if (-not (Get-Command "python" -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] Python runtime not found in PATH." -ForegroundColor Red
    Write-Host "TraceCrypt requires Python 3.11+ in an air-gapped environment." -ForegroundColor Red
    exit 1
}

& python -m tracecrypt @args
exit $LASTEXITCODE
