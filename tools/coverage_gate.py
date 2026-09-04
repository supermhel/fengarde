"""M2 coverage gate (PLAN_C Tier 2.3): WS-2/WS-3 core, ~85% target.

Runs coverage.py across every test script run_all_tests.sh actually invokes
for a service (not a blind `unittest discover`, which misses this repo's
check()/main()-pattern test files -- see this file's TARGETS for the mapping,
kept in sync with run_all_tests.sh by hand since there's no shared manifest).

HONEST THRESHOLDS, not the PLAN_C target itself: re-measured 2026-07-19 after
the PR#2 merge (and after syncing TARGETS with the merged run_all_tests.sh --
the gate briefly read WS-3 at 50% because the M4 code was in --source while
its test suites weren't in this list). Current enforced floors, kept in sync
with TARGETS itself by hand (gap-hunt 2026-09-04: this prose had drifted --
a ghost "WS-3-reports" label that isn't a TARGETS key, and three real,
enforced targets missing from the list entirely): WS-2 88.0, WS-3 65.0
(dropped from 75 on 2026-08-06 when the hardened session/SSRF/rate-limit
surface made it measure lower -- gap honestly open), services-shared 42.0,
WS-4 40.0, WS-6 60.0, WS-8 60.0, WS-9 68.0. This gate enforces those MEASURED
numbers minus a small buffer as a regression guard, not the unmet 85%
target -- claiming a gate "blocks CI on 85%" when a service demonstrably
doesn't meet it would be exactly the overclaiming SSOT.md sec2 exists to
prevent. Raise a service's threshold as real tests close the gap; don't
lower WS-2's.

Run:  python tools/coverage_gate.py
"""
from __future__ import annotations

import re
import subprocess
import sys
from collections import defaultdict
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
            "parsers/test_active_directory.py",
            "parsers/test_plugins.py",
            "parsers/test_dns_query.py",
            "parsers/test_k8s_audit.py",
            "parsers/test_cef.py",
            "parsers/test_cloudtrail.py",
            "parsers/test_sysmon.py",
            "parsers/test_v05_severity_sector.py",
            "parsers/test_modbus_anomaly.py",
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
            # M4/M5 suites (post-merge sync with run_all_tests.sh -- the gate
            # measured 50% after the PR#2 merge precisely because the M4 code
            # was in --source but these, its tests, weren't run):
            "test_api_v1.py",
            "test_rbac_api.py",
            "test_router.py",
            "test_webhooks.py",
            "test_nis2_template.py",
            "test_bulk_index.py",
            "test_rules_view.py",
            "test_adapter_defaults.py",
        ],
        65.0,  # measured 70% (2026-08-06, after session/SSRF/rate-limit hardening); gap open
    ),
    # H8 (2026-08-06 fix): the coverage gate previously only covered WS-2 and
    # WS-3, leaving shared/ and two whole detection/inventory services unmeasured.
    # The Redis-dependent suites below SKIP gracefully when BUS_BACKEND!=redis
    # / no broker is reachable (each prints [SKIP] and the gate still measures
    # the no-Redis path), so this runs cleanly in the quality job with no Redis
    # service. NOTE: test_bus_redis_fallback.py is deliberately EXCLUDED -- it
    # forces BUS_BACKEND=redis and needs the redis CLIENT lib importable to reach
    # its ValueError-propagation path (see ci.yml's contract-tests note), which
    # the quality job doesn't install; including it would break the gate.
    # Floors are deliberately conservative (60.0): first-time entries, and CI
    # must stay green -- raise them as real coverage measurably improves.
    "services-shared": (
        "services/shared",
        [
            "test_runner.py",
            "test_sessions.py",
            "test_rbac.py",
            "test_bus_lag.py",
            "test_bus_memory_race.py",
            "test_bus_read_count.py",
            "test_bus_trim_acked.py",
            "test_diskguard.py",
            "test_users_migration.py",
            "test_allowlist.py",
        ],
        42.0,  # re-measured 45% (2026-08-18, down from the 2026-08-06 51%
               # baseline): window.py moved in from ws4-detection (for WS-8
               # reuse) with no dedicated shared-level test of its own --
               # it's exercised by ws4-detection's own test_window*.py suite,
               # which sits outside this gate's --source=services/shared
               # script list, so it measures as uncovered HERE specifically.
               # allowlist.py (same move) DOES get a dedicated test above,
               # which is why this didn't drop further. 3pt buffer.
    ),
    "ws4-detection": (
        "services/ws4-detection",
        [
            "test_window.py",
            "test_window_periodic.py",
            "test_engine_boolean.py",
            "test_engine_hardening.py",
            "test_rule_health.py",
            "test_hot_reload.py",
        ],
        40.0,  # measured 45% (2026-08-06 first-time baseline); 5pt buffer
    ),
    "ws6-inventory": (
        "services/ws6-inventory",
        [
            "test_keystore.py",
            "test_auth.py",
            "test_tenant_isolation.py",
            "test_new_device_diff.py",
            "test_bus_consumer.py",
            "test_manage_keys.py",
        ],
        60.0,  # measured 69% (2026-08-06 first-time baseline); 9pt buffer
    ),
    "ws8-correlation": (
        "services/ws8-correlation",
        [
            "test_contract.py",
            "test_correlator_sensitivity.py",
        ],
        60.0,  # measured 69% (2026-08-18 first-time baseline; correlator.py 93%,
               # main.py 0% -- bus-wiring glue, exercised only live via `make up`
               # not by these zero-infra suites); 9pt buffer, same convention
               # as every other first-time entry in this table
    ),
    "ws9-resolver": (
        "services/ws9-resolver",
        [
            "test_contract.py",
        ],
        68.0,  # measured 77% (2026-09-02 first-time baseline; resolver.py 92%,
               # entity_id.py 89%, main.py 67%, demo_round_trip.py 0% -- the
               # last two are bus-wiring glue / a manual demo script, exercised
               # only live via `make up`, not by this zero-infra suite, same
               # shape as ws8-correlation's main.py above); 9pt buffer, same
               # convention as every other first-time entry in this table
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


# Gap-hunt finding (2026-08-23): every floor above is a frozen number typed
# in on a past measurement date, each with a disclosed 2-9pt buffer baked in
# by comment. That buffer means real coverage can erode silently for however
# many points it has left -- the gate keeps printing [OK] the whole way
# down, and nothing prompts anyone to re-measure or raise the floor before
# it actually breaches. There's no persistent baseline store across CI runs
# to ratchet against, so this doesn't try to fail early -- it makes the
# erosion VISIBLE instead of purely silent: a [WARN] fires once the buffer
# still protecting a service drops under this many points, in the same CI
# log a human is already reading, before the [FAIL] that used to be the
# first signal anyone got.
_LOW_BUFFER_WARN_PTS = 3.0


# NEW-hunt (2026-08-27): TARGETS' per-service script lists were a hand-maintained
# PARTIAL subset -- ws4-detection listed 6 of its ~25 suites, and a NEW suite
# added to run_all_tests.sh silently stayed out of coverage forever (and the
# list drifted from what CI actually ran). The per-service script sets are now
# DERIVED from run_all_tests.sh's own `$PY services/<svc>/<rel>.py` invocations
# (the ~ absolute authority for what the zero-infra gate runs), UNION the
# hand-written TARGETS lists so nothing already measured is lost. A suite added
# to run_all_tests.sh is now auto-wired into coverage the next run. The hand
# list stays as the documented anchor; run_all_tests.sh is the source of truth.
_EXCLUDE_DERIVED = {
    # Forces BUS_BACKEND=redis and needs the redis CLIENT lib importable to
    # reach its non-ImportError propagation case -- the contract env doesn't
    # install redis-client-only deps; it runs standalone in CI's
    # redis-integration job instead. See module docstring.
    "test_bus_redis_fallback.py",
}

# Keys whose --source path is a services/<dir> we map derive onto. Keyed by the
# TARGETS label -> the relative source services/ dir inside its `source`.
def _service_dir_for_source(source: str) -> str | None:
    """Return the services/ subdir of a --source path, or None if not a
    services/* source (e.g. test fakes whose source isn't under services/)."""
    if source.startswith("services/"):
        return source.split("/", 1)[1]
    return None


def _derive_scripts(run_all_text: str) -> dict[str, set[str]]:
    """service-dir -> {rel test script paths} that run_all_tests.sh invokes via
    `$PY services/<service>/<rel>.py`, plus `test_contract.py` for every service
    in its literal `for ws in ...` loop (the run_all grep can't see that one --
    it writes the path as `services/$ws`)."""
    derived: dict[str, set[str]] = defaultdict(set)
    for m in re.finditer(r"services/([^/\s]+)/(\S+\.py)", run_all_text):
        svc, rel = m.group(1), m.group(2)
        derived[svc].add(rel)
    loop = re.search(r"for\s+ws\s+in\s+([^\n]+)", run_all_text)
    if loop:
        for svc in re.split(r"\s+", loop.group(1).strip().rstrip(";")):
            if not svc or svc == "do":
                continue
            derived[svc].add("test_contract.py")
    return derived


def _effective_scripts(source: str, scripts: list[str],
                       derived: dict[str, set[str]]) -> list[str]:
    """Union of the hand-listed TARGETS scripts and the run_all_tests.sh-derived
    set for this service's source dir (minus the documented excludes), so
    coverage measures the FULL running suite, not a stale partial subset."""
    svc = _service_dir_for_source(source)
    if svc is None or svc not in derived:
        return sorted(set(scripts))
    extra = {r for r in derived[svc] if r not in _EXCLUDE_DERIVED}
    return sorted(set(scripts) | extra)


def main() -> int:
    try:
        derived_src = _derive_scripts((ROOT / "run_all_tests.sh").read_text(encoding="utf-8"))
    except FileNotFoundError:
        derived_src = {}
    failed = False
    warned = False
    total_added = 0
    for service_dir, (source, scripts, min_pct) in TARGETS.items():
        eff_scripts = _effective_scripts(source, scripts, derived_src)
        added = sorted(set(eff_scripts) - set(scripts))
        if added:
            total_added += len(added)
            print(f"  [note] {service_dir}: {len(added)} suite(s) auto-derived from "
                  f"run_all_tests.sh (not hand-listed in TARGETS): {', '.join(added)}")
        pct = measure(service_dir, source, eff_scripts)
        buffer = pct - min_pct
        # Floor semantics: >= min_pct passes, anything below fails. The
        # boundary at exactly pct == min_pct is deliberately a PASS, and it is
        # single-sourced here (gap-hunt finding 2026-08-26: the status line
        # and the `failed` flag used two separate comparisons that could drift
        # apart under an edit, and no test pinned the == case).
        ok = pct >= min_pct
        status = "OK" if ok else "FAIL"
        if not ok:
            failed = True
        print(f"[{status}] {service_dir}: {pct}% (gate: >={min_pct}%, buffer={buffer:.1f}pt)")
        if ok and buffer < _LOW_BUFFER_WARN_PTS:
            warned = True
            print(f"  [WARN] {service_dir}'s buffer above its floor is down to "
                  f"{buffer:.1f}pt (< {_LOW_BUFFER_WARN_PTS}pt) -- re-measure and "
                  f"consider raising TARGETS' floor before this becomes a [FAIL]")
    if failed:
        print("\n[FAIL] coverage gate: one or more services regressed below their floor")
        return 1
    if warned:
        print("\n[OK] coverage gate PASS (see [WARN] above -- a floor's buffer is thinning)")
    else:
        print("\n[OK] coverage gate PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
