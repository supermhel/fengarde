"""R4-#123: 'new test must be wired' gate.

Every standalone test script (test_*.py) must either be invoked by the
zero-infra CI gate (run_all_tests.sh) or be a DOCUMENTED live-only orphan
(run against a real Docker/Redis/OpenSearch stack via `make test-live`, the
live CI jobs, or a *_live.py helper). A test file that exists but no gate runs
it is a suite that silently stopped testing anything -- it can rot (or pass
vacuously) forever with nobody noticing, which is exactly the gap this repo
keeps hunting.

This scans services/, tools/ and eval/ for test_*.py, reads run_all_tests.sh's
`$PY <path>` invocations, and FAILS listing any test file that is neither
wired into the gate nor on the documented live-only orphan allowlist.

Run:  python tools/check_test_wiring.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "run_all_tests.sh"
SEARCH_DIRS = ("services", "tools", "eval")

# Documented live-only orphans: run against a REAL Docker/Redis/OpenSearch stack
# via `make test-live`, the live CI jobs, or a *_live.py harness -- deliberately
# NOT part of the zero-infra `make test`/run_all_tests.sh gate (they'd block CI
# without infra and prove nothing). If one of these is repurposed into a
# zero-infra suite, remove it from this list so the gate demands it be wired.
LIVE_ONLY_ORPHANS = {
    "services/ws3-indexer/storage/test_opensearch_cas_concurrency_live.py",   # make test-live
    "services/ws3-indexer/storage/test_opensearch_ha_failover_live.py",     # make test-live
    "services/ws3-indexer/storage/test_opensearch_live.py",                  # make test-live + CI redis-integration
    "services/ws3-indexer/storage/test_opensearch_shared_store_concurrent_live.py",  # make test-live
    "services/ws3-indexer/test_mfa_live_e2e.py",                             # CI ws3-mfa live job
    "services/ws4-detection/test_window_sentinel_failover_live.py",          # tools/sentinel_failover_live.py
    # mutmut execution targets (NOT standalone gate suites): `make mutation-test`
    # / CI's `mutmut run` invokes them as the mutation-testing harness on the
    # configured source set. They are not run by run_all_tests.sh by design --
    # they are the tests mutmut survives/mutates against, not zero-infra suite
    # members. See pyproject.toml [tool.mutmut] + Makefile mutation-test.
    "tools/test_mutmut_shared.py",
    "tools/test_mutmut_window.py",
}


def _gate_references(gate_text: str) -> set[str]:
    """Rel paths (services/<ws>/...) run_all_tests.sh invokes via `$PY ...`
    `( cd ... && $PY ... )`., plus per-service `test_contract.py` from the
    `for ws in ...` loop."""
    refs: set[str] = set()
    for m in re.finditer(r"\$PY\s+([\w./-]+\.py)", gate_text):
        refs.add(m.group(1))
    for tail in re.findall(r"\( cd services/\$ws && \$PY (\S+\.py)", gate_text):
        for ws in re.findall(r"for\s+ws\s+in\s+([^\n;]+)", gate_text):
            for w in ws.split():
                refs.add(f"services/{w}/{tail}")
    # test_contract.py is wired via the `( cd services/$ws && ... )` loop above.
    return refs


def main() -> int:
    if not GATE.exists():
        print(f"[FAIL] check_test_wiring: {GATE} not found")
        return 1
    gate_text = GATE.read_text(encoding="utf-8")
    refs = _gate_references(gate_text)

    unwired: list[str] = []
    for base in SEARCH_DIRS:
        for p in (ROOT / base).rglob("test_*.py"):
            rel = str(p.relative_to(ROOT)).replace("\\", "/")
            fn = rel.rsplit("/", 1)[-1]
            # Wired if the exact rel path, its basename, or its within-service
            # relative path appears in the gate (the loop wires test_contract.py
            # per service, so its basename won't appear literally).
            if rel in refs or fn in refs:
                continue
            # within-service rel (e.g. parsers/test_x.py) matches $PY services/<ws>/parsers/test_x.py
            parts = rel.split("/")
            if len(parts) >= 3 and "/".join(parts[2:]) in refs:
                continue
            if rel in LIVE_ONLY_ORPHANS:
                continue
            unwired.append(rel)

    if unwired:
        print(f"[FAIL] {len(unwired)} test_*.py file(s) exist but are NOT wired into "
              f"run_all_tests.sh and are not documented live-only orphans (R4-#123):")
        for u in sorted(unwired):
            print(f"    {u}")
        print("    Wire each into run_all_tests.sh (or add to its *_live/live-only "
              "documentation if it needs a real stack). An unwired test ran by nobody "
              "passes vacuously forever.")
        return 1
    print("[OK] every test_*.py is wired into run_all_tests.sh "
          "(or a documented live-only orphan). No orphan suite silently untested.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
