# Palisade bootstrap for Windows 10/11 (PowerShell).
# Run from the repo root:  powershell -ExecutionPolicy Bypass -File scripts\bootstrap.ps1
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

$py = if (Get-Command py -ErrorAction SilentlyContinue) { "py -3" } else { "python" }

if (-not (Test-Path ".venv")) {
    Write-Host "creating virtualenv"
    Invoke-Expression "$py -m venv .venv"
}
& .\.venv\Scripts\Activate.ps1
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt

python -m palisade doctor
python -m palisade install @args
python -m palisade run
