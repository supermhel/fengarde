"""WP-0.1-A: the Lane-Coverage Meta-Guard for FENGARDE.

The project gates every workstream with a battery of standalone checks
(check_rule_producers.py, check_test_wiring.py, ...) that are individually
surgical. This guard is the *meta-guard*: it asserts that the components each
of those checks claims to cover cannot silently sit OUTSIDE the gate that
claims to cover them. The anti-dormancy lesson it encodes is the same one
check_rule_producers.py hit (collect_producible() was never called, so a
registered parser sat unchecked for a month while printing [OK]): a coverage
check that does not actually run over its operand set is worse than none.

It enforces SIX lane-coverage assertions:

  #1 SERVICES     -- every infra/docker-compose.yml service that has a BUS
                      dependency (BUS_BACKEND=redis / REDIS_URL) must appear in
                      KILL_TARGETS (tools/chaos_test.py) OR carry an inline
                      exclusion comment naming a reason (BUS_EXCLUSIONS below,
                      same shape chaos_test.py already uses for ws6/ws7).
  #2 PARSERS      -- every parser registered in services/ws2-normalization/
                      parsers/__init__.py (the _REGISTRY) must have (a) a
                      fixture in the ws2 normalization test suite, (b) an
                      atheris harness tools/fuzz/fuzz_<source_type>.py, and
                      (c) an entry in the .github/workflows/fuzz.yml matrix.
  #3 RULES        -- every contracts/rules/*.yml must appear in the ATT&CK
                      scorecard input, i.e. be consumed by
                      eval/attack/coverage_layer.load_rules() (the scorecard
                      drops any rule that fails to YAML-parse into a dict, so
                      a rule can exit the scorecard silently while the file
                      stays committed -- this assertion catches that).
  #4 LIVE TESTS   -- every test_*_live*.py in the repo must be referenced by a
                      CI job (.github/workflows/*) OR be on the explicit
                      opt-in LIVE_TEST_ALLOWLIST below with a stated reason.
  #5 HTTP-SURFACE -- every service file with an HTTP listener must call a
                      require_auth_or_die/_check_auth/check_api_key variant at
                      startup OR carry the FENGARDE-OPEN-BY-DESIGN marker
                      comment (an accepted, documented open surface). folds in
                      WP-0.1-B. services/shared/runner.py /metrics is an
                      ACCEPTED OPEN SURFACE (counters/gauges only, no tenant
                      data, loopback-bound); its marker lives next to the
                      /metrics route.
  #6 PIN CONSISTENCY -- all services/*/requirements.txt must agree on the same
                      PyYAML pin and the same redis pin. (Folded from WP-0.3-A2;
                      the unification is a sibling agent's job -- this guard is
                      RED until it lands, by design.)

A [FAIL] line makes run_all_tests.sh exit non-zero (HARD FAIL). Every
assertion has a proven negative -- including the guard itself:

SELF-TEST (--self-test): injects a guaranteed violation into each assertion's
operand set in-memory and asserts the guard turns RED for each one. If the
assertion loop in main()/run_checks() is stubbed out or an assertion is never
called, its injected violation produces no [FAIL] and the self-test goes RED
-- the check_rule_producers.py collect_producible() lesson, applied to THIS
tool so it cannot itself go dormant. It also verifies this script is still
wired into run_all_tests.sh (grep for both the normal and --self-test
invocation), so a guard deleted from the gate is caught the next time the
remaining invocation runs. run_all_tests.sh invokes both modes as HARD FAILS.

Run:
    python tools/check_lane_coverage.py            # the six-assertion gate
    python tools/check_lane_coverage.py --self-test  # negative proof of each
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SERVICES = ROOT / "services"
WS2 = SERVICES / "ws2-normalization"
RULES_DIR = ROOT / "contracts" / "rules"
FUZZ_DIR = ROOT / "tools" / "fuzz"
WORKFLOWS_DIR = ROOT / ".github" / "workflows"
GATE_SH = ROOT / "run_all_tests.sh"
COMPOSE_FILE = ROOT / "infra" / "docker-compose.yml"
CHAOS_TEST = ROOT / "tools" / "chaos_test.py"

sys.path.insert(0, str(WS2))
sys.path.insert(0, str(SERVICES))
sys.path.insert(0, str(ROOT / "eval" / "attack"))

from parsers import _REGISTRY  # noqa: E402
import coverage_layer  # noqa: E402


# ---------------------------------------------------------------------------
# Assertion #1: services with a BUS dependency must be chaos kill-targeted.
# ---------------------------------------------------------------------------
# Inline exclusions, mirroring the reason-comment convention chaos_test.py
# already uses (see its KILL_TARGETS comment block, corrected 2026-08-23).
BUS_EXCLUSIONS: dict[str, str] = {
    # chaos_test.py comment: these scenarios are SSH brute-force bursts over
    # 203.0.113.0/24, never an assets.updates sighting, so ws6's raw.events
    # producing path (gated on is_new_device) never fires during a chaos run --
    # killing ws6 exercises nothing verify() can observe (the test-that-can't-
    # fail anti-pattern); its own crash-recovery gap is tracked separately.
    "ws6-inventory": (
        "not a chaos kill target: its bus path (assets.updates -> raw.events) "
        "never fires on the SSH/brute-force scenarios this harness replays, so "
        "killing it exercises nothing verify() can observe (chaos_test.py "
        "comment, 2026-08-23); crash-recovery tracked separately."
    ),
    # one-shot bootstrap feeder, restart:no -- produces the demo burst then
    # exits; it is not a long-running in-replay service to kill.
    "devkit-feeder": (
        "one-shot feeder (restart: no): injects a demo burst onto raw.events "
        "then exits; not a long-running in-replay kill target."
    ),
}


def _find_bus_services() -> set[str]:
    """Compose services with a BUS dependency (BUS_BACKEND=redis / REDIS_URL)."""
    if not COMPOSE_FILE.exists():
        return set()
    data = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
    out: set[str] = set()
    for name, svc in (data or {}).get("services", {}).items():
        env = svc.get("environment", [])
        blob = str(env)
        # environment may be a list of "KEY=val" strings or a dict
        if isinstance(env, dict):
            blob = str({k: v for k, v in env.items()})
        if "BUS_BACKEND=redis" in blob or "REDIS_URL" in blob:
            out.add(name)
    return out


def _find_kill_targets() -> set[str]:
    if not CHAOS_TEST.exists():
        return set()
    text = CHAOS_TEST.read_text(encoding="utf-8")
    m = re.search(r"KILL_TARGETS\s*=\s*\[(.*?)\]", text, re.DOTALL)
    if not m:
        return set()
    return set(re.findall(r'"([^"]+)"', m.group(1)))


def _assert_services() -> list[str]:
    bus = _find_bus_services()
    if not bus:
        return ["[FAIL] A1: zero compose services carry a BUS dependency "
                "(BUS_BACKEND=redis/REDIS_URL) -- vacuous green; nothing to cover"]
    kills = _find_kill_targets()
    problems = []
    for svc in sorted(bus):
        if svc in kills:
            continue
        if svc in BUS_EXCLUSIONS:
            continue
        problems.append(
            f"[FAIL] A1: service {svc!r} has a BUS dependency but is NOT in "
            f"KILL_TARGETS (tools/chaos_test.py) and has no exclusion comment. "
            f"Either add it to KILL_TARGETS or record an inline exclusion with "
            f"a reason.")
    if not problems:
        print(f"[OK] A1: all {len(bus)} bus-dependent compose services are "
              f"chaos kill-targeted or carry a documented exclusion "
              f"(killed={len(kills)}).")
    return problems


# ---------------------------------------------------------------------------
# Assertion #2: every registered parser has a fixture, a fuzz harness, and a
#               fuzz.yml matrix entry.
# ---------------------------------------------------------------------------
def _registry_sources() -> set[str]:
    return set(_REGISTRY)


def _find_harness_sources() -> set[str]:
    return {p.name[len("fuzz_"):-3] for p in FUZZ_DIR.glob("fuzz_*.py")}


def _find_matrix_sources() -> set[str]:
    if not (WORKFLOWS_DIR / "fuzz.yml").exists():
        return set()
    w = yaml.safe_load((WORKFLOWS_DIR / "fuzz.yml").read_text(encoding="utf-8"))
    try:
        return set(w["jobs"]["fuzz"]["strategy"]["matrix"]["target"])
    except (KeyError, TypeError):
        return set()


def _find_fixture_sources() -> set[str]:
    """source_types with a test fixture anywhere in the ws2 test suite."""
    tests = list(WS2.rglob("test_*.py")) + list(WS2.rglob("mocks/*.json"))
    buf = ""
    for p in tests:
        try:
            buf += p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            pass
    return {st for st in _registry_sources() if st in buf}


def _assert_parsers() -> list[str]:
    registered = _registry_sources()
    if not registered:
        return ["[FAIL] A2: parser registry is empty -- vacuous green; "
                "no parser is covered by this gate"]
    harness = _find_harness_sources()
    matrix = _find_matrix_sources()
    fixtures = _find_fixture_sources()
    problems = []
    for st in sorted(registered):
        if st not in fixtures:
            problems.append(f"[FAIL] A2(a): parser {st!r} has no test fixture "
                            f"in the ws2 normalization test suite")
        if st not in harness:
            problems.append(f"[FAIL] A2(b): parser {st!r} has no atheris "
                            f"harness tools/fuzz/fuzz_{st}.py")
        if st not in matrix:
            problems.append(f"[FAIL] A2(c): parser {st!r} has no "
                            f"fuzz.yml matrix entry (.github/workflows/fuzz.yml)")
    if not problems:
        print(f"[OK] A2: all {len(registered)} registered parsers have a "
              f"fixture, a fuzz harness, and a fuzz.yml matrix entry.")
    return problems


# ---------------------------------------------------------------------------
# Assertion #3: every rule file must appear in the ATT&CK scorecard input.
# ---------------------------------------------------------------------------
def _find_rules_on_disk() -> set[str]:
    return {f.name for f in RULES_DIR.glob("*.yml")}


def _find_scorecard_sources() -> set[str]:
    try:
        return {r["file"] for r in coverage_layer.load_rules()}
    except Exception as exc:  # coverage_layer crashed -> cannot verify coverage
        return {"__SCORECARD_LOAD_ERROR__:" + str(exc)}


def _assert_rules() -> list[str]:
    ondisk = _find_rules_on_disk()
    if not ondisk:
        return ["[FAIL] A3: ZERO rule files in contracts/rules -- vacuous "
                "green; the ATT&CK scorecard covered nothing"]
    scorecard = _find_scorecard_sources()
    if ondisk == {"__SCORECARD_LOAD_ERROR__:"}:
        pass
    missing = sorted(ondisk - scorecard)
    if missing:
        return (["[FAIL] A3: rule file(s) present in contracts/rules but NOT "
                 "consumed by the ATT&CK scorecard "
                 "(eval/attack/coverage_layer.load_rules, which silently drops "
                 "any rule that fails to YAML-parse into a dict):"] +
                [f"    {r}" for r in missing] +
                ["    A committed rule outside the declared-coverage input is "
                 "a rule the scorecard claims nothing about."])
    print(f"[OK] A3: all {len(ondisk)} rule files appear in the ATT&CK "
          f"scorecard input (coverage_layer.load_rules).")
    return []


# ---------------------------------------------------------------------------
# Assertion #4: every test_*_live*.py is CI-referenced or on the allowlist.
# ---------------------------------------------------------------------------
# Intentionally-not-CI live tests, with the stated reason each entry exists.
LIVE_TEST_ALLOWLIST: dict[str, str] = {
    # make test-live only (ci.yml comments): requires a multi-node HA
    # OpenSearch cluster CI does not cheaply provision for the sentinel/HA
    # failover path.
    "services/ws3-indexer/storage/test_opensearch_ha_failover_live.py": (
        "make test-live only -- needs a multi-node HA OpenSearch cluster "
        "(sentinel/HA failover path); CI runs single-node only."
    ),
    # driven by tools/sentinel_failover_live.py against a REAL Redis Sentinel
    # quorum; requires live Sentinel HA infra (check_test_wiring also lists it
    # as a documented live-only orphan).
    "services/ws4-detection/test_window_sentinel_failover_live.py": (
        "run via tools/sentinel_failover_live.py against a live Redis Sentinel "
        "quorum; requires real Sentinel HA infra CI doesn't host."
    ),
}


def _find_live_tests() -> set[str]:
    out: set[str] = set()
    for base in (SERVICES, ROOT / "tools", ROOT / "eval"):
        for p in base.rglob("test_*_live*.py"):
            out.add(str(p.relative_to(ROOT)).replace("\\", "/"))
    return out


def _find_ci_live_tests() -> set[str]:
    if not WORKFLOWS_DIR.exists():
        return set()
    out: set[str] = set()
    for wf in WORKFLOWS_DIR.glob("*.yml"):
        for line in wf.read_text(encoding="utf-8", errors="ignore").splitlines():
            if "test_" not in line or "_live" not in line:
                continue
            # only real invocations count (python .../x.py, docker exec ... x.py)
            if ("python " in line or "docker exec" in line) and ".py" in line:
                m = re.search(r"([\w/.\-]+test_\w*_live\w*\.py)", line)
                if m:
                    out.add(Path(m.group(1)).name)
    return out


def _assert_live_tests() -> list[str]:
    live = _find_live_tests()
    if not live:
        return ["[FAIL] A4: zero test_*_live*.py files discovered -- vacuous "
                "green over an empty lent set; nothing verified"]
    ci = _find_ci_live_tests()
    problems = []
    for rel in sorted(live):
        fn = rel.rsplit("/", 1)[-1]
        if fn in ci or rel in ci or any(rel.endswith(c) for c in ci):
            continue
        if rel in LIVE_TEST_ALLOWLIST:
            continue
        problems.append(
            f"[FAIL] A4: live test {rel!r} is neither referenced by a CI job "
            f"(.github/workflows/*) nor on the LIVE_TEST_ALLOWLIST in "
            f"check_lane_coverage.py. Wire it into CI or record a stated "
            f"reason for excluding it.")
    if not problems:
        print(f"[OK] A4: every test_*_live*.py ({len(live)}) is CI-referenced "
              f"or on the documented allowlist "
              f"({len(LIVE_TEST_ALLOWLIST)} allowed).")
    return problems


# ---------------------------------------------------------------------------
# Assertion #5: every HTTP-surface file has an auth call or the open-by-design
#               marker (folds in WP-0.1-B).
# ---------------------------------------------------------------------------
HTTP_SERVER_TOKENS = (
    "ThreadingHTTPServer(", "HTTPServer(", "make_server(", "serve_forever(",
    "app.run(", "BaseHTTPRequestHandler", "aiohttp", "FastAPI", "Flask(",
    "Tornado",
)
HTTP_AUTH_TOKENS = (
    "require_auth_or_die", "check_api_key", "_check_auth", "Authorization",
    "FENGARDE_API_KEY", "api_key",
)
OPEN_BY_DESIGN_MARKER = "fengarde-open-by-design"  # token used in runner.py too


def _find_http_surfaces() -> dict[str, str]:
    """non-test service .py files that host an HTTP listener -> file text."""
    out: dict[str, str] = {}
    for p in SERVICES.rglob("*.py"):
        if "__pycache__" in str(p) or "test" in p.name.lower():
            continue
        text = p.read_text(encoding="utf-8", errors="ignore")
        if any(tok in text for tok in HTTP_SERVER_TOKENS):
            out[str(p.relative_to(ROOT)).replace("\\", "/")] = text
    return out


def _assert_http_surfaces() -> list[str]:
    surfaces = _find_http_surfaces()
    if not surfaces:
        return ["[FAIL] A5: zero HTTP listener surfaces discovered -- vacuous "
                "green; nothing verified"]
    problems = []
    for rel, text in sorted(surfaces.items()):
        if any(tok in text for tok in HTTP_AUTH_TOKENS):
            continue
        if OPEN_BY_DESIGN_MARKER.lower() in text.lower():
            continue
        problems.append(
            f"[FAIL] A5: HTTP listener in {rel!r} calls no "
            f"require_auth_or_die/_check_auth/check_api_key variant and carries "
            f"no FENGARDE-OPEN-BY-DESIGN marker. Gate the surface or record it "
            f"as an accepted open surface (marker comment).")
    if not problems:
        print(f"[OK] A5: all {len(surfaces)} HTTP-surface files are "
              f"authenticated or carry a documented open-by-design marker.")
    return problems


# ---------------------------------------------------------------------------
# Assertion #6: cross-service pip pin consistency (PyYAML + redis).
# ---------------------------------------------------------------------------
def _find_pins() -> dict[str, dict[str, str]]:
    """service_name -> {pkg: pin} for PyYAML and redis across requirements.txt."""
    out: dict[str, dict[str, str]] = {}
    for req in SERVICES.rglob("requirements*.txt"):
        name = req.parent.name
        pins: dict[str, str] = {}
        for line in req.read_text(encoding="utf-8", errors="ignore").splitlines():
            m = re.match(r"\s*(PyYAML|redis)==([\d.]+)", line)
            if m:
                pins[m.group(1)] = m.group(2)
        if pins:
            out[name] = pins
    return out


def _assert_pin_consistency() -> list[str]:
    pins = _find_pins()
    if not pins:
        return ["[FAIL] A6: no services/*/requirements.txt found -- vacuous "
                "green; nothing checked for pin drift"]
    problems: list[str] = []
    for pkg in ("PyYAML", "redis"):
        versions = {}
        for svc, svcpins in pins.items():
            if pkg in svcpins:
                versions.setdefault(svcpins[pkg], []).append(svc)
        if len(versions) <= 1:
            continue
        problems.append(
            f"[FAIL] A6: {pkg} pin is not consistent across services: "
            + "; ".join(f"{v!r} in {', '.join(s)}" for v, s in sorted(versions.items()))
            + ". Align every service requirements.txt to one version "
              "(WP-0.3-A2).")
    if not problems:
        print(f"[OK] A6: PyYAML and redis pins are consistent across all "
              f"{len(pins)} services' requirements.txt.")
    return problems


# ---------------------------------------------------------------------------
# Self-wiring / anti-dormancy checks for the guard itself.
# ---------------------------------------------------------------------------
def _assert_gate_wiring() -> list[str]:
    """The meta-guard must itself stay wired into run_all_tests.sh."""
    if not GATE_SH.exists():
        return ["[FAIL] SELF: run_all_tests.sh not found -- cannot confirm this "
                "guard is wired into the gate"]
    text = GATE_SH.read_text(encoding="utf-8")
    problems = []
    if "check_lane_coverage.py" not in text:
        problems.append("[FAIL] SELF: run_all_tests.sh no longer invokes "
                        "tools/check_lane_coverage.py -- this guard has been "
                        "dropped from the gate and nothing will fail when a "
                        "lane goes uncovered (anti-dormancy).")
    if "--self-test" not in text:
        problems.append("[FAIL] SELF: run_all_tests.sh no longer invokes "
                        "tools/check_lane_coverage.py --self-test -- the "
                        "negative-proof self-test has been dropped.")
    return problems


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
def run_checks() -> list[str]:
    """Run every assertion; listeners (self-test) can inject violations via
    the source-function globals above. Returns the flat list of problems."""
    problems: list[str] = []
    problems += _assert_services()
    problems += _assert_parsers()
    problems += _assert_rules()
    problems += _assert_live_tests()
    problems += _assert_http_surfaces()
    problems += _assert_pin_consistency()
    return problems


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return run_self_test()
    self_wiring = _assert_gate_wiring()
    problems = run_checks()
    all_problems = problems + self_wiring
    for p in all_problems:
        print(p)
    if all_problems:
        print(f"[GATE] {len(all_problems)} lane-coverage violation(s) -- "
              f"failing the gate.")
        return 1
    print("[GATE] lane-coverage meta-guard: all six assertions green.")
    return 0


def _check_injected(label: str, injected: list[tuple[str, object]]):
    """Run run_checks() with monkeypatched source functions that inject a
    guaranteed violation for `label`, and assert that label actually FAILed.
    The non-injected assertions are expected to stay green, so their [OK]
    chatter is suppressed. Returns all problems."""
    import contextlib
    import io
    originals = {k: globals()[k] for k, _ in injected}
    try:
        for name, value in injected:
            globals()[name] = value
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            allp = run_checks()
    finally:
        for name, value in originals.items():
            globals()[name] = value
    return allp


def run_self_test() -> int:
    """Mandatory anti-dormancy negative proof. For EACH assertion, inject a
    guaranteed violation in-memory and assert the guard turns RED for it. If
    the assertion loop in run_checks() is stubbed or an assertion is never
    called, its injected violation stops producing a [FAIL] and THIS self-test
    goes red -- the same dormancy this tool exists to catch."""
    fails: list[str] = []

    # A1: fake a bus service left out of KILL_TARGETS and exclusions.
    def fake_bus_services(): return {"ws1-collectors", "ws2-normalization", "ghost-svc"}
    def fake_kill_targets(): return {"ws1-collectors", "ws2-normalization"}
    p = _check_injected("A1", [("_find_bus_services", fake_bus_services),
                               ("_find_kill_targets", fake_kill_targets)])
    if not any("[FAIL] A1:" in x for x in p):
        fails.append("A1 injection did not produce a [FAIL] -- assertion #1 "
                     "is dormant/unwired")

    # A2: fake a registered parser with no harness/matrix/fixture.
    def fake_registry(): return set(_REGISTRY) | {"ghost_parser"}
    def fake_fixture(): return set(_REGISTRY)
    def fake_harness(): return _find_harness_sources()
    def fake_matrix(): return _find_matrix_sources()
    p = _check_injected("A2", [("_registry_sources", fake_registry),
                               ("_find_fixture_sources", fake_fixture)])
    if not any("[FAIL] A2(b):" in x or "[FAIL] A2(c):" in x for x in p):
        fails.append("A2 injection did not produce a [FAIL] -- assertion #2 "
                     "is dormant/unwired")

    # A3: fake a committed rule the scorecard does not consume.
    def fake_rules_disk(_orig=_find_rules_on_disk): return _orig() | {"ghost_rule.yml"}
    def fake_scorecard(_orig=_find_scorecard_sources): return _orig()
    p = _check_injected("A3", [("_find_rules_on_disk", fake_rules_disk),
                               ("_find_scorecard_sources", fake_scorecard)])
    if not any("[FAIL] A3:" in x for x in p):
        fails.append("A3 injection did not produce a [FAIL] -- assertion #3 "
                     "is dormant/unwired")

    # A4: fake a live test that is neither CI-wired nor allowlisted.
    def fake_live(_orig=_find_live_tests): return _orig() | {"services/ws1-collectors/test_ghost_live.py"}
    def fake_ci(_orig=_find_ci_live_tests): return _orig()
    p = _check_injected("A4", [("_find_live_tests", fake_live),
                               ("_find_ci_live_tests", fake_ci)])
    if not any("[FAIL] A4:" in x for x in p):
        fails.append("A4 injection did not produce a [FAIL] -- assertion #4 "
                     "is dormant/unwired")

    # A5: fake a bare HTTP listener with no auth call and no marker.
    def fake_surfaces(): return {"services/ws1-collectors/_ghost_http.py":
                                 "from http.server import HTTPServer\n"
                                 "HTTPServer(('127.0.0.1',0), BaseHTTPRequestHandler)\n"}
    p = _check_injected("A5", [("_find_http_surfaces", fake_surfaces)])
    if not any("[FAIL] A5:" in x for x in p):
        fails.append("A5 injection did not produce a [FAIL] -- assertion #5 "
                     "is dormant/unwired")

    # A6: fake divergent pins. Because the REAL tree already has PyYAML drift,
    # inject a fresh divergence that cannot be masked by the real state.
    def fake_pins():
        return {"svc_a": {"PyYAML": "6.0.2", "redis": "8.1.0"},
                "svc_b": {"PyYAML": "6.0.2", "redis": "7.9.0"}}
    p = _check_injected("A6", [("_find_pins", fake_pins)])
    if not any("[FAIL] A6:" in x for x in p):
        fails.append("A6 injection did not produce a [FAIL] -- assertion #6 "
                     "is dormant/unwired")

    # self-wiring: the guard must be referenced by run_all_tests.sh.
    wiring = _assert_gate_wiring()
    if wiring:
        fails.extend(wiring)

    if fails:
        for f in fails:
            print(f"[FAIL] SELF-TEST: {f}")
        print("[SELF-TEST] FAIL -- the lane-coverage meta-guard is "
              "dormant or unwired.")
        return 1
    print("[SELF-TEST] OK -- every assertion provably turns RED on an "
          "injected violation; all six are wired into the gate; the guard "
          "remains referenced by run_all_tests.sh.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
