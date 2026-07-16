"""M2 coverage gate (PLAN_C Tier 2.3): WS-2/WS-3 core, ~85% target.

Runs coverage.py across every test script run_all_tests.sh actually invokes
for a service (not a blind `unittest discover`, which misses this repo's
check()/main()-pattern test files -- see this file's TARGETS for the mapping,
kept in sync with run_all_tests.sh by hand since there's no shared manifest).

HONEST THRESHOLDS, not the PLAN_C target itself: measured 2026-07-16, WS-2 is
at 90% (above the ~85% target) and WS-3 is at 71% (below it -- main.py's
run() loop and storage/opensearch.py's live-cluster paths are the gap, see
the M2 commit message). This gate enforces those MEASURED numbers minus a
small buffer as a regression guard, not the unmet 85% target -- claiming a
gate "blocks CI on 85%" when WS-3 demonstrably doesn't meet it would be
exactly the overclaiming SSOT.md sec2 exists to prevent. Raise WS-3's
threshold as real tests close the gap; don't lower WS-2's.

Run:  python tools/coverage_gate.py
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# service -> (coverage --source path, [test scripts run_all_tests.sh invokes], min %)
TARGETS: dict[str, tuple[str, list[str], float]] = {
    "ws2-normalization": (
        "services/ws2-normalization",
        [
            "test_contract.py",
            "parsers/test_property_hardening.py",
            "test_sanitize.py",
            "parsers/test_generic_syslog.py",
            "parsers/test_windows_eventlog.py",
            "parsers/test_registry_routing.py",
            "parsers/test_parser_hardening.py",
            "enrichment/test_enrichment.py",
            "parsers/test_timeutil.py",
            "parsers/test_db_audit.py",
            "parsers/test_mcp_agent.py",
            "parsers/test_opcua_audit.py",
            "parsers/test_n8n_audit.py",
        ],
        88.0,  # measured 90% (2026-07-16); 2pt buffer, not the unmet-elsewhere 85% target
    ),
    "ws3-indexer": (
        "services/ws3-indexer",
        [
            "test_contract.py",
            "test_triage_api.py",
            "test_storage_cas.py",
            "test_opensearch_retry.py",
            "test_auth.py",
            "test_reporting.py",
        ],
        68.0,  # measured 71% (2026-07-16); BELOW the 85% target, open gap -- see module docstring
    ),
}


def measure(service_dir: str, source: str, scripts: list[str]) -> float:
    data_file = ROOT / f".coverage.gate.{service_dir}"
    data_file.unlink(missing_ok=True)
    for script in scripts:
        subprocess.run(
            [sys.executable, "-m", "coverage", "run", f"--source={source}",
             "-a", f"--data-file={data_file}", str(ROOT / source / script)],
            cwd=ROOT, check=True, capture_output=True,
        )
    result = subprocess.run(
        [sys.executable, "-m", "coverage", "report", f"--data-file={data_file}"],
        cwd=ROOT, check=True, capture_output=True, text=True,
    )
    data_file.unlink(missing_ok=True)
    # coverage report's TOTAL line isn't always the last line of stdout -- an
    # empty-file note ("1 empty file skipped.") can follow it.
    total_line = next(ln for ln in result.stdout.splitlines() if ln.startswith("TOTAL"))
    pct = total_line.split()[-1].rstrip("%")
    return float(pct)


def main() -> int:
    failed = False
    for service_dir, (source, scripts, min_pct) in TARGETS.items():
        pct = measure(service_dir, source, scripts)
        status = "OK" if pct >= min_pct else "FAIL"
        if pct < min_pct:
            failed = True
        print(f"[{status}] {service_dir}: {pct}% (gate: >={min_pct}%)")
    if failed:
        print("\n[FAIL] coverage gate: one or more services regressed below their floor")
        return 1
    print("\n[OK] coverage gate PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
