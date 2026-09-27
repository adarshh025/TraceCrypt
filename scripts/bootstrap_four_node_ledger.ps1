# TraceCrypt 4-Node Permissioned BFT Ledger Cluster Bootstrapper (PowerShell)
# Master Prompt 11 - Section 15 Reference Deployment

param(
    [string]$ClusterDir = "deployment/validator/cluster",
    [string]$ChainId = "tracecrypt-airgap-1",
    [int[]]$Ports = @(9101, 9102, 9103, 9104)
)

$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "TRACECRYPT 4-NODE BFT LEDGER BOOTSTRAP (OFFLINE)" -ForegroundColor Cyan
Write-Host "Cluster Directory: $ClusterDir"
Write-Host "Chain ID:          $ChainId"
Write-Host "Ports:             $($Ports -join ', ')"
Write-Host "============================================================"

# Invoke Python bootstrapper
$PythonCmd = "python"
if (Get-Command "python" -ErrorAction SilentlyContinue) {
    $portArgs = $Ports | ForEach-Object { $_.ToString() }
    & python scripts/bootstrap_four_node_ledger.py --cluster-dir "$ClusterDir" --chain-id "$ChainId" --ports $portArgs
    if ($LASTEXITCODE -eq 0) {
        Write-Host "============================================================" -ForegroundColor Green
        Write-Host "4-NODE BFT CLUSTER INITIALIZED SUCCESSFULLY" -ForegroundColor Green
        Write-Host "============================================================" -ForegroundColor Green
        exit 0
    } else {
        Write-Host "Error bootstrapping cluster (exit code: $LASTEXITCODE)" -ForegroundColor Red
        exit $LASTEXITCODE
    }
} else {
    Write-Host "Python runtime not found in PATH." -ForegroundColor Red
    exit 1
}
