#!/usr/bin/env bash
# ARGIEM terminal demo — deterministic, zero-infra, asciinema-friendly.
#
# Tells the ARGIEM story in well under 90 seconds: a burst of failed SSH logins
# from one IP becomes a REAL brute-force alert, end to end, with NO Docker, no
# Redis, no OpenSearch. It also proves the replay is idempotent.
#
# Record it:   asciinema rec --command "bash tools/demo.sh" argiem-demo.cast
# Run it:      bash tools/demo.sh
#
# It exits non-zero if the acceptance test fails, so a broken demo can never be
# recorded as "passing".
set -euo pipefail

# --- locate the repo root (this script lives in tools/) -----------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

# Pick a python: prefer python3, fall back to python. (No Docker, no venv needed.)
PY="${PYTHON:-}"
if [ -z "$PY" ]; then
  if command -v python3 >/dev/null 2>&1; then PY=python3
  elif command -v python  >/dev/null 2>&1; then PY=python
  else
    echo "error: no python3/python on PATH (set \$PYTHON to your interpreter)" >&2
    exit 127
  fi
fi

# --- tiny narration helpers ---------------------------------------------------
say()  { printf '\n%s\n' "$*"; }
rule() { printf '%s\n' "------------------------------------------------------------------"; }

# --- banner -------------------------------------------------------------------
rule
cat <<'BANNER'
  ARGIEM — an open-source SIEM pipeline.

  Raw security logs in  ->  one schema (OCSF)  ->  correlation rules  ->  real alerts.
  Every service is decoupled and talks only over a message bus.

  This demo runs the v0.1 acceptance test with ZERO infrastructure:
  no Docker, no Redis, no OpenSearch — just the in-memory bus.
BANNER
rule

# --- the story ----------------------------------------------------------------
say "# The signal: 10 failed SSH logins from a single IP (203.0.113.5) within 60s."
say "# The whole pipeline runs in-process: normalize -> detect -> triage -> index."
say "# Watch for the brute-force ALERT, then a replay that DEDUPES (idempotent)."

say "\$ python tools/demo_e2e.py"

# Run the acceptance test. set -e makes a non-zero exit abort the demo, but we
# capture the status explicitly so we can print a clear closing line.
status=0
"$PY" tools/demo_e2e.py || status=$?

rule
if [ "$status" -ne 0 ]; then
  echo "  DEMO FAILED — acceptance test exited $status. Not a passing run." >&2
  exit "$status"
fi

cat <<'OUTRO'
  That alert is real, not mock data: the brute-force rule fired on the 10th
  failure, the alert reached the index, and replaying the event reused the same
  alert id instead of duplicating it.

  Try the live Dockerized stack:   make up   ->   http://localhost:8080
  Add a parser without Docker:      cd services/ws2-normalization && python test_contract.py
OUTRO
rule
