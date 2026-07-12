# ARGIEM terminal demo (Windows / PowerShell) — deterministic, zero-infra.
#
# Same story as tools/demo.sh: a burst of failed SSH logins from one IP becomes a
# REAL brute-force alert, end to end, with NO Docker, no Redis, no OpenSearch.
# Exits non-zero if the acceptance test fails.
#
# Run it:  powershell -ExecutionPolicy Bypass -File tools\demo.ps1

$ErrorActionPreference = 'Stop'

# --- locate the repo root (this script lives in tools/) ----------------------
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = Resolve-Path (Join-Path $ScriptDir '..')
Set-Location $Root

# Pick a python: $env:PYTHON wins, else python, else python3.
$Py = $env:PYTHON
if (-not $Py) {
    if (Get-Command python  -ErrorAction SilentlyContinue) { $Py = 'python' }
    elseif (Get-Command python3 -ErrorAction SilentlyContinue) { $Py = 'python3' }
    else {
        Write-Error 'no python/python3 on PATH (set $env:PYTHON to your interpreter)'
        exit 127
    }
}

$rule = '------------------------------------------------------------------'

# --- banner ------------------------------------------------------------------
Write-Host $rule
Write-Host @'
  ARGIEM — an open-source SIEM pipeline.

  Raw security logs in  ->  one schema (OCSF)  ->  correlation rules  ->  real alerts.
  Every service is decoupled and talks only over a message bus.

  This demo runs the v0.1 acceptance test with ZERO infrastructure:
  no Docker, no Redis, no OpenSearch — just the in-memory bus.
'@
Write-Host $rule

# --- the story ---------------------------------------------------------------
Write-Host "`n# The signal: 10 failed SSH logins from a single IP (203.0.113.5) within 60s."
Write-Host "# The whole pipeline runs in-process: normalize -> detect -> triage -> index."
Write-Host "# Watch for the brute-force ALERT, then a replay that DEDUPES (idempotent)."
Write-Host "`n`$ python tools/demo_e2e.py"

& $Py tools/demo_e2e.py
$status = $LASTEXITCODE

Write-Host $rule
if ($status -ne 0) {
    Write-Error "  DEMO FAILED — acceptance test exited $status. Not a passing run."
    exit $status
}

Write-Host @'
  That alert is real, not mock data: the brute-force rule fired on the 10th
  failure, the alert reached the index, and replaying the event reused the same
  alert id instead of duplicating it.

  Try the live Dockerized stack:   make up   ->   http://localhost:8080
  Add a parser without Docker:      cd services/ws2-normalization && python test_contract.py
'@
Write-Host $rule
