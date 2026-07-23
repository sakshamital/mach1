# YOUR SENTINEL — Local dev launcher (Windows)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location "$Root\backend"

if (-not (Test-Path ".env")) {
    Copy-Item "$Root\.env" ".env" -ErrorAction SilentlyContinue
}

Write-Host "Installing dependencies..."
python -m pip install -r requirements.txt -q

Write-Host "Starting Your Sentinel on http://localhost:8000"
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
