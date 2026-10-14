#!/usr/bin/env bash
# Fetch both third-party corpora (gitignored, not vendored) at PINNED commits,
# so a published benchmark number can be rebuilt exactly. Bumping a pin is a
# deliberate PR: the next nightly run on that branch shows the before/after.
# The commits each lane actually read are recorded in every trend row
# (tools/append_trend_row.py -> corpus_commits).
#
# splunk/attack_data stores its datasets in Git LFS: git-lfs must be installed
# (ubuntu-latest runners have it). The splunk lane fails loudly on LFS
# pointer stubs or missing files, never grades a partial corpus.
#
# Usage: bash eval/detection_accuracy/fetch_corpora.sh [dest-dir]   (default: this dir)
set -euo pipefail

EVTX_SHA=4ceed2f4706daf601c212a8f91c113dd85349a2c    # 2023-01-24; upstream unchanged since
SPLUNK_SHA=eac2f8f675ec31a6618003399dcc53641524e673  # 2026-10-13; the 2026-10-14 snapshot's corpus

DEST="${1:-$(cd "$(dirname "$0")" && pwd)}"

fetch() {  # <url> <sha> <dir>
  if [ -e "$3" ]; then
    echo "[FAIL] $3 already exists -- remove it first (a reused checkout may be partial)" >&2
    return 1
  fi
  git init -q "$3"
  git -C "$3" remote add origin "$1"
  git -C "$3" fetch -q --depth 1 origin "$2"
  git -C "$3" checkout -q FETCH_HEAD
  [ "$(git -C "$3" rev-parse HEAD)" = "$2" ] || { echo "[FAIL] $3 is not at $2" >&2; return 1; }
  echo "[OK] $3 @ $2"
}

echo "Fetching EVTX-ATTACK-SAMPLES (GPL-3.0)..."
fetch https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES "$EVTX_SHA" "$DEST/evtx-samples"
echo "Fetching splunk/attack_data (Git LFS, multi-GB)..."
fetch https://github.com/splunk/attack_data "$SPLUNK_SHA" "$DEST/splunk-attack-data"
