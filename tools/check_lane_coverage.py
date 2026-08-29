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
                      all services/*/requirements.txt now agree, and both
                      packages are Dependabot-ignored -- see .github/
                      dependabot.yml -- so a future bump must realign every
                      service by hand in one PR, not drift one service at a
                      time and red this gate.)

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

import json
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
        # Compose `environment` may be a list of "KEY=val" strings or a dict.
        # PR #80 review (finding 9): the old dict branch did `str(dict)`,
        # which yields "{'KEY': 'val'}" -- a blob that can NEVER contain the
        # literal "KEY=val" substring, so dict-form env services were
        # invisible to A1. Flatten dict entries into "KEY=val" lines.
        if isinstance(env, dict):
            blob = "\n".join(f"{k}={v}" for k, v in env.items())
        else:
            blob = str(env)
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
    """source_types with a REAL fixture, from the actual fixture corpora.

    Two honest sources, both parsed (never raw-text substrings):
      1. tools/check_rule_producers.py::FIXTURES -- the per-parser real raw
         fixture dict the rule-producer gate feeds every parser (all 17).
      2. services/ws2-normalization/mocks/*.json -- the contract-test sample
         corpus (parsed `samples[].source_type` values).

    The old rule scanned concatenated test-file text for the source_type
    string, so deleting a parser's real fixture stayed green because a test
    merely mentioned the string (adversarial review D1).
    """
    sources: set[str] = set()
    # 1) check_rule_producers.FIXTURES keys (real per-parser raw fixtures).
    try:
        import check_rule_producers  # tools/ on sys.path? no -- it sits beside us
    except Exception:
        check_rule_producers = None  # type: ignore[assignment]
    if check_rule_producers is None:
        # Import via file path (check_rule_producers lives in tools/).
        import importlib.util
        crp = ROOT / "tools" / "check_rule_producers.py"
        if crp.exists():
            spec = importlib.util.spec_from_file_location("crp_fixtures", crp)
            if spec is not None and spec.loader is not None:
                mod = importlib.util.module_from_spec(spec)
                try:
                    spec.loader.exec_module(mod)
                    sources |= set(getattr(mod, "FIXTURES", {}))
                except Exception:
                    pass
    else:
        sources |= set(getattr(check_rule_producers, "FIXTURES", {}))
    # 2) parsed ws2 contract-test samples (mocks/*.json).
    for mock in WS2.glob("mocks/*.json"):
        try:
            data = json.loads(mock.read_text(encoding="utf-8", errors="ignore"))
            for s in data.get("samples", []):
                st = s.get("source_type")
                if st:
                    sources.add(st)
        except (OSError, ValueError):
            continue
    return sources & _registry_sources()


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


# PR #80 review (finding 7): the engine check above (ondisk - load_rules) is
# structurally unable to fail for an uncovered rule -- load_rules() globs the
# SAME contracts/rules/ directory, so any on-disk rule that parses into a dict
# is definitionally "in the scorecard". The two operands derive from one
# source, so the only thing it can catch is a file that YAML-parses to a
# non-dict. The human-readable scorecard -- contracts/detection-coverage.md's
# rule-by-rule table -- is INDEPENDENT of the directory glob, so checking each
# shipped rule appears there is what makes A3 genuinely fail for an uncovered
# rule.
COVERAGE_DOC = ROOT / "contracts" / "detection-coverage.md"


def _find_coverage_doc_sources() -> set[str]:
    """Rule base-names listed in contracts/detection-coverage.md's
    rule-by-rule table (the human-readable ATT&CK scorecard document). Parsed
    from the table, never a substring scan. ``__COVERAGE_DOC_MISSING__`` when
    the file is absent (the gate must fail rather than silently skip)."""
    if not COVERAGE_DOC.exists():
        return {"__COVERAGE_DOC_MISSING__"}
    out: set[str] = set()
    in_table = False
    for line in COVERAGE_DOC.read_text(encoding="utf-8").splitlines():
        if line.startswith("| Rule |"):
            in_table = True
            continue
        if not in_table:
            continue
        if line.startswith("|---"):
            continue
        if not line.startswith("|"):
            if line.strip():
                in_table = False  # left the table
            continue
        m = re.match(r"\|\s*([A-Za-z0-9_]+)\s*\|", line)
        if m:
            out.add(m.group(1))
    return out


def _assert_rules() -> list[str]:
    ondisk = _find_rules_on_disk()
    if not ondisk:
        return ["[FAIL] A3: ZERO rule files in contracts/rules -- vacuous "
                "green; the ATT&CK scorecard covered nothing"]
    problems: list[str] = []
    scorecard = _find_scorecard_sources()
    error = next((s for s in scorecard if s.startswith("__SCORECARD_LOAD_ERROR__:")), None)
    if error is not None:
        problems.append(f"[FAIL] A3: eval/attack/coverage_layer.load_rules() crashed, "
                        f"so rule-file coverage cannot be verified: {error!r}")
    else:
        missing = sorted(ondisk - scorecard)
        if missing:
            problems.extend([
                "[FAIL] A3: rule file(s) present in contracts/rules but NOT "
                "consumed by the ATT&CK scorecard "
                "(eval/attack/coverage_layer.load_rules, which silently drops "
                "any rule that fails to YAML-parse into a dict):"] +
                [f"    {r}" for r in missing] +
                ["    A committed rule outside the declared-coverage input is "
                 "a rule the scorecard claims nothing about."])

    # PR #80 review (finding 7): the scorecard DOCUMENT check -- every shipped
    # rule must have a row in contracts/detection-coverage.md.
    doc = _find_coverage_doc_sources()
    if "__COVERAGE_DOC_MISSING__" in doc:
        problems.append("[FAIL] A3: contracts/detection-coverage.md is missing "
                        "-- the rule-by-rule scorecard document that every "
                        "contracts/rules/*.yml must be listed in.")
    else:
        base_names = {f[:-4] if f.endswith(".yml") else f for f in ondisk}
        missing_doc = sorted(base_names - doc)
        if missing_doc:
            problems.extend([
                "[FAIL] A3: rule(s) present in contracts/rules but NOT listed "
                "in contracts/detection-coverage.md's rule-by-rule table (the "
                "human-readable ATT&CK scorecard):"] +
                [f"    {r}" for r in missing_doc] +
                ["    Update the matrix in the same PR that adds the rule "
                 "(see its header: 'Update this file in the same PR as any "
                 "rule change')."])

    if not problems:
        print(f"[OK] A3: all {len(ondisk)} rule files appear in the ATT&CK "
              f"scorecard input (coverage_layer.load_rules) AND in the "
              f"contracts/detection-coverage.md rule-by-rule matrix.")
    return problems


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
    """Full repo-relative paths (and, as a fallback for `cd`-relative
    invocations, bare basenames) of live tests actually referenced by a CI
    job. Keeping the full captured path -- not just its basename -- is what
    lets _assert_live_tests match on full path first, so two same-named live
    tests in different services (only one CI-wired) are not conflated."""
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
                    out.add(m.group(1))          # full captured path/expression
                    out.add(Path(m.group(1)).name)  # basename fallback (cd-relative invocations)
    return out


def _assert_live_tests() -> list[str]:
    live = _find_live_tests()
    if not live:
        return ["[FAIL] A4: zero test_*_live*.py files discovered -- vacuous "
                "green over an empty lent set; nothing verified"]
    ci = _find_ci_live_tests()
    # Basename-only CI matches (from a `cd`-relative workflow invocation) are
    # only trusted when that basename is UNIQUE across every discovered live
    # test -- otherwise a CI reference to one service's test_foo_live.py
    # would also "cover" an unrelated, un-wired test_foo_live.py in a
    # different service that merely shares the filename.
    basename_counts: dict[str, int] = {}
    for rel in live:
        fn = rel.rsplit("/", 1)[-1]
        basename_counts[fn] = basename_counts.get(fn, 0) + 1
    problems = []
    for rel in sorted(live):
        fn = rel.rsplit("/", 1)[-1]
        if rel in ci or (basename_counts[fn] == 1 and fn in ci):
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

# PR #80 review (finding 4): server-CREATION tokens -- statements that open a
# listener/bind. Deliberately excludes the no-parenthesis base-class markers
# (`BaseHTTPRequestHandler`) and the `serve_forever(`/threading calls that are
# PART of one listener, so a single-listener file isn't over-counted. Used to
# scope the OPEN_BY_DESIGN marker exemption PER LISTENER instead of letting one
# marker comment exempt a whole file.
HTTP_LISTENER_CREATION_TOKENS = (
    "ThreadingHTTPServer(", "HTTPServer(", "make_server(",
    "app.run(", "FastAPI(", "Flask(", "Tornado(",
)


def _listener_creations(code: str) -> int:
    """Count distinct listener-creation statements (per line, deduped) in
    CODE-ONLY text. `ThreadingHTTPServer(` contains `HTTPServer(` as a
    substring, so the `any(...)` per line is what keeps that one statement
    from being counted twice."""
    return sum(1 for line in code.splitlines()
               if any(tok in line for tok in HTTP_LISTENER_CREATION_TOKENS))


def _code_only(text: str) -> str:
    """Blank out comments and string-literal contents IN PLACE (by character
    span), leaving every other character exactly where it was. A5 must not
    be satisfied by a docstring or a `# TODO: add auth` comment mentioning
    the token -- only an actual call/identifier counts. Blanking spans
    in-place (rather than dropping COMMENT/STRING tokens and rejoining the
    rest with a separator) is deliberate: rejoining with a space turns
    `HTTPServer(` into `HTTPServer (`, which can never match a literal
    `"HTTPServer("` token again -- a false-green hole in the exact check
    this function exists to harden."""
    import io
    import tokenize

    lines = text.splitlines(keepends=True)
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, SyntaxError, IndentationError):
        return text  # unparseable -- fall back to raw text (fail toward scanning more, not less)

    for tok in tokens:
        if tok.type not in (tokenize.COMMENT, tokenize.STRING):
            continue
        (srow, scol), (erow, ecol) = tok.start, tok.end
        if srow == erow:
            line = lines[srow - 1]
            lines[srow - 1] = line[:scol] + (" " * (ecol - scol)) + line[ecol:]
            continue
        # Multi-line string: blank the tail of the first line, every full
        # middle line, and the head of the last line, preserving newlines.
        first = lines[srow - 1]
        nl = "\n" if first.endswith("\n") else ""
        lines[srow - 1] = first[:scol] + (" " * (len(first) - scol - len(nl))) + nl
        for i in range(srow, erow - 1):
            mid = lines[i]
            mnl = "\n" if mid.endswith("\n") else ""
            lines[i] = (" " * (len(mid) - len(mnl))) + mnl
        last = lines[erow - 1]
        lines[erow - 1] = (" " * ecol) + last[ecol:]

    return "".join(lines)


def _find_http_surfaces() -> dict[str, tuple[str, str]]:
    """non-test service .py files that host an HTTP listener -> (raw text,
    CODE-ONLY text). Server-detection and auth-detection run against the
    CODE-ONLY text (comments/docstrings stripped, see _code_only) so a
    comment can't fake an auth call; the OPEN_BY_DESIGN_MARKER exemption is
    intentionally a comment marker (see its module-level definition) and is
    checked against the RAW text instead."""
    out: dict[str, tuple[str, str]] = {}
    for p in SERVICES.rglob("*.py"):
        if "__pycache__" in str(p) or "test" in p.name.lower():
            continue
        raw = p.read_text(encoding="utf-8", errors="ignore")
        code = _code_only(raw)
        if any(tok in code for tok in HTTP_SERVER_TOKENS):
            out[str(p.relative_to(ROOT)).replace("\\", "/")] = (raw, code)
    return out


def _assert_http_surfaces() -> list[str]:
    surfaces = _find_http_surfaces()
    if not surfaces:
        return ["[FAIL] A5: zero HTTP listener surfaces discovered -- vacuous "
                "green; nothing verified"]
    problems = []
    for rel, (raw, code) in sorted(surfaces.items()):
        if any(tok in code for tok in HTTP_AUTH_TOKENS):
            continue
        marker_count = raw.lower().count(OPEN_BY_DESIGN_MARKER)
        listeners = _listener_creations(code)
        # PR #80 review (finding 4): the OPEN_BY_DESIGN marker must be PRESENT
        # PER LISTENER -- one marker no longer exempts the whole file. A file
        # with no detectable listener-creation statement (e.g. only a handler
        # class) keeps the single-marker exemption; a file with N listeners
        # needs N markers.
        exempt = marker_count >= 1 if listeners == 0 else marker_count >= listeners
        if exempt:
            continue
        if marker_count == 0:
            problems.append(
                f"[FAIL] A5: HTTP listener in {rel!r} calls no "
                f"require_auth_or_die/_check_auth/check_api_key variant and "
                f"carries no FENGARDE-OPEN-BY-DESIGN marker. Gate the surface "
                f"or record it as an accepted open surface (marker comment).")
        else:
            problems.append(
                f"[FAIL] A5: HTTP listeners in {rel!r}: the "
                f"FENGARDE-OPEN-BY-DESIGN marker is FILE-scoped and covers "
                f"only {marker_count} of {listeners} listener(s) (PR #80 "
                f"finding 4) -- a single marker must not exempt every listener "
                f"in the file. Add a marker for each listener or gate the "
                f"surface.")
    if not problems:
        print(f"[OK] A5: all {len(surfaces)} HTTP-surface files are "
              f"authenticated or carry a documented open-by-design marker "
              f"per listener.")
    return problems


# ---------------------------------------------------------------------------
# Assertion #6: cross-service pip pin consistency + hash presence.
# ---------------------------------------------------------------------------
# Services that legitimately carry no requirements.txt (see infra/docker-compose
# service declarations). Each entry must name a concrete reason.
REQUIREMENTS_EXCLUSIONS: dict[str, str] = {
    "ws7-dashboard": (
        "static nginx frontend: serves index.html + assets from a base image; "
        "no Python runtime, nothing to pin (Dockerfile has no pip install)."
    ),
    "devkit-feeder": (
        "has its own requirements.txt under services/devkit-feeder/ -- "
        "included by _find_pins via rglob; listed here only for completeness "
        "of the per-service scan."
    ),
}


# PR #80 review (finding 8): package pins are matched case-INSENSITIVELY
# (pip's distribution names are case-insensitive, so `pyyaml==` or `Redis==`
# are legitimate spellings a case-sensitive regex silently skipped, escaping
# BOTH the version-consistency and the hash-presence checks).
_PIN_RE = re.compile(r"\s*(pyyaml|redis)==([\d.]+)", re.IGNORECASE)
_CANON_PKG = {"pyyaml": "PyYAML", "redis": "redis"}
# Intra-service multi-file pin conflicts found by the last _find_pins() run
# (a service with two requirements files pinning the same pkg differently).
_PIN_CONFLICTS: list[str] = []


def _find_pins() -> dict[str, dict[str, str]]:
    """service_name -> {pkg: pin} for PyYAML and redis across requirements.txt.

    PR #80 review (finding 8): reads case-INSENSITIVELY so a lowercase pin
    can't silently escape the checks, and records INTRA-SERVICE conflicts -- a
    service carrying multiple requirements files that pin the same package to
    different versions -- which the old last-write-wins dict merge silently
    masked (a future drift could hide inside one service's own files).
    """
    global _PIN_CONFLICTS
    _PIN_CONFLICTS = []
    out: dict[str, dict[str, str]] = {}
    versions_seen: dict[tuple[str, str], set[str]] = {}
    for req in SERVICES.rglob("requirements*.txt"):
        name = req.parent.name
        pins: dict[str, str] = {}
        for line in req.read_text(encoding="utf-8", errors="ignore").splitlines():
            m = _PIN_RE.match(line)
            if m is None or m.group(1) is None or m.group(2) is None:
                continue
            key = _CANON_PKG[m.group(1).lower()]
            pins[key] = m.group(2)
            versions_seen.setdefault((name, key), set()).add(m.group(2))
        if pins:
            out[name] = pins
    for (svc, key), versions in sorted(versions_seen.items()):
        if len(versions) > 1:
            _PIN_CONFLICTS.append(
                f"[FAIL] A6(collision): {key} pinned to different versions "
                f"({', '.join(sorted(versions))}) across multiple "
                f"requirements files in service {svc!r} -- the intra-service "
                f"drift is masked; pick one version per service.")
    return out


def _find_requirements_services() -> dict[str, str]:
    """Every service dir with a Dockerfile -> its requirements.txt path or ''."""
    out: dict[str, str] = {}
    for dockerfile in SERVICES.glob("*/Dockerfile"):
        svc = dockerfile.parent.name
        reqs = sorted(dockerfile.parent.glob("requirements*.txt"))  # deterministic
        out[svc] = str(reqs[0].relative_to(dockerfile.parent)) if reqs else ""
    return out


def _require_hashes(pins: dict[str, str], req: Path) -> list[str]:
    """Ensure every pinned pkg==version line is followed by --hash= lines.

    Pin matching is case-insensitive (``pyyaml==`` is a legitimate spellings --
    PR #80 finding 8) so a lowercased pin cannot silently skip the hash check.
    """
    problems: list[str] = []
    lines = req.read_text(encoding="utf-8", errors="ignore").splitlines()
    for i, line in enumerate(lines):
        if _PIN_RE.match(line) is None:
            continue
        m = _PIN_RE.match(line)
        if m is None or m.group(1) is None:
            continue
        pkg = _CANON_PKG[m.group(1).lower()]
        # continuation: the next line (or a following indented line) must be
        # a --hash= entry for this same package block.
        has_hash = False
        for nxt in lines[i + 1:]:
            if nxt.strip() == "" or nxt.rstrip().endswith("\\"):
                continue
            if "--hash=" in nxt:
                has_hash = True
                break
            # a bare non-hash continuation after the pin means no hash block
            if re.match(r"\s*(pyyaml|redis)==|^\s*#", nxt, re.IGNORECASE):
                break
            break
        if not has_hash:
            problems.append(f"[FAIL] A6(hash): {pkg} pinned in {req.parent.name} "
                            f"({lines[i].strip()}) has NO --hash= pin -- a "
                            f"tampered wheel is installable. Hash-pin it "
                            f"(WP-0.3-A2).")
    return problems


def _assert_pin_consistency() -> list[str]:
    pins = _find_pins()
    if not pins:
        return ["[FAIL] A6: no services/*/requirements.txt found -- vacuous "
                "green; nothing checked for pin drift"]
    problems: list[str] = []

    # 6a: every service dir must either carry requirements.txt or be excluded.
    have_reqs = set(pins) | set(REQUIREMENTS_EXCLUSIONS)
    for svc, reqpath in _find_requirements_services().items():
        if svc in pins or svc in REQUIREMENTS_EXCLUSIONS:
            continue
        problems.append(f"[FAIL] A6(completeness): service {svc} has a "
                        f"Dockerfile but NO requirements.txt and no documented "
                        f"exclusion -- add one or record the reason in "
                        f"REQUIREMENTS_EXCLUSIONS.")
    # devkit-feeder lives under services/ and _find_pins catches its reqs;
    # ensure our exclusions don't mask a real missing file.
    for svc, reason in REQUIREMENTS_EXCLUSIONS.items():
        if svc == "devkit-feeder":
            continue
        if svc not in have_reqs:
            problems.append(f"[FAIL] A6(completeness): exclusion for {svc} "
                            f"listed but no requirements.txt exists -- the "
                            f"reason may be stale.")

    # 6b: every pinned pkg must carry a --hash=.
    for req in SERVICES.rglob("requirements*.txt"):
        problems += _require_hashes({}, req)

    # 6b2: intra-service pin collisions (PR #80 finding 8) -- two requirements
    # files inside ONE service pinning the same pkg to different versions.
    problems += list(_PIN_CONFLICTS)

    # 6c+d: version consistency (unchanged) + accurate message.
    pkg_counts: dict[str, int] = {}
    for pkg in ("PyYAML", "redis"):
        versions: dict[str, list[str]] = {}
        for svc, svcpins in pins.items():
            if pkg in svcpins:
                pkg_counts[pkg] = pkg_counts.get(pkg, 0) + 1
                versions.setdefault(svcpins[pkg], []).append(svc)
        if len(versions) <= 1:
            continue
        problems.append(
            f"[FAIL] A6: {pkg} pin is not consistent across services: "
            + "; ".join(f"{v!r} in {', '.join(s)}" for v, s in sorted(versions.items()))
            + ". Align every service requirements.txt to one version "
              "(WP-0.3-A2).")
    if not problems:
        detail = ", ".join(f"{pkg} in {n} services" for pkg, n in sorted(pkg_counts.items()))
        print(f"[OK] A6: pin versions consistent across services "
              f"({detail}); every pinned package carries a --hash= and every "
              f"Python service dir has a requirements file.")
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

    # A2: fake a registered parser with no harness/matrix/fixture, proving all
    # three sub-checks (a/b/c) can independently turn red.
    def fake_registry(): return set(_REGISTRY) | {"ghost_parser"}
    def fake_fixture(): return set(_REGISTRY)
    p = _check_injected("A2", [("_registry_sources", fake_registry),
                               ("_find_fixture_sources", fake_fixture)])
    if not any("[FAIL] A2(a):" in x for x in p):
        fails.append("A2(a) injection did not produce a [FAIL] -- the fixture "
                     "sub-check is dormant/unwired")
    if not any("[FAIL] A2(b):" in x for x in p):
        fails.append("A2(b) injection did not produce a [FAIL] -- the fuzz-"
                     "harness sub-check is dormant/unwired")
    if not any("[FAIL] A2(c):" in x for x in p):
        fails.append("A2(c) injection did not produce a [FAIL] -- the fuzz.yml "
                     "matrix sub-check is dormant/unwired")

    # A3: fake a committed rule the scorecard does not consume.
    def fake_rules_disk(_orig=_find_rules_on_disk): return _orig() | {"ghost_rule.yml"}
    def fake_scorecard(_orig=_find_scorecard_sources): return _orig()
    p = _check_injected("A3", [("_find_rules_on_disk", fake_rules_disk),
                               ("_find_scorecard_sources", fake_scorecard)])
    if not any("[FAIL] A3:" in x for x in p):
        fails.append("A3 injection did not produce a [FAIL] -- assertion #3 "
                     "is dormant/unwired")

    # A3(doc) (PR #80 finding 7): the coverage DOCUMENT check must go red when
    # a committed rule is missing from contracts/detection-coverage.md --
    # this is the only A3 operand INDEPENDENT of the directory glob, so it is
    # the failure mode that can actually catch an uncovered real rule.
    def fake_doc_drops_one(_orig=_find_coverage_doc_sources):
        doc = _orig()
        # drop one genuinely-listed rule from the doc -> a committed rule is
        # now "uncovered" by the scorecard document.
        return (doc - {"ot_modbus_unauthorized_write"}) if "ot_modbus_unauthorized_write" in doc else doc
    p = _check_injected("A3(doc)", [("_find_coverage_doc_sources", fake_doc_drops_one)])
    if not any("[FAIL] A3:" in x for x in p):
        fails.append("A3(doc) injection did not produce a [FAIL] -- the "
                     "detection-coverage.md matrix check is dormant/unwired")

    # A4: fake a live test that is neither CI-wired nor allowlisted.
    def fake_live(_orig=_find_live_tests): return _orig() | {"services/ws1-collectors/test_ghost_live.py"}
    def fake_ci(_orig=_find_ci_live_tests): return _orig()
    p = _check_injected("A4", [("_find_live_tests", fake_live),
                               ("_find_ci_live_tests", fake_ci)])
    if not any("[FAIL] A4:" in x for x in p):
        fails.append("A4 injection did not produce a [FAIL] -- assertion #4 "
                     "is dormant/unwired")

    # A5: fake a bare HTTP listener with no auth call and no marker.
    def fake_surfaces():
        code = ("from http.server import HTTPServer\n"
                "HTTPServer(('127.0.0.1',0), BaseHTTPRequestHandler)\n")
        return {"services/ws1-collectors/_ghost_http.py": (code, code)}
    p = _check_injected("A5", [("_find_http_surfaces", fake_surfaces)])
    if not any("[FAIL] A5:" in x for x in p):
        fails.append("A5 injection did not produce a [FAIL] -- assertion #5 "
                     "is dormant/unwired")

    # A5(per-listener) (PR #80 finding 4): a SINGLE open-by-design marker must
    # not exempt a file with multiple listeners -- each listener needs its own
    # marker. This is the exact hole the file-scoped exemption used to leave.
    def fake_surfaces_multi():
        code = ("from http.server import HTTPServer\n"
                "HTTPServer(('0.0.0.0',1), H)\n"
                "HTTPServer(('0.0.0.0',2), H2)\n")
        raw = "x FENGARDE-OPEN-BY-DESIGN (covers /metrics) x\n" + code
        return {"services/ws1-collectors/_ghost_http2.py": (raw, code)}
    p = _check_injected("A5(per-listener)",
                        [("_find_http_surfaces", fake_surfaces_multi)])
    if not any("[FAIL] A5:" in x for x in p):
        fails.append("A5(per-listener) injection did not produce a [FAIL] -- "
                     "one marker is exempting multiple listeners in a file")

    # A6: fake divergent pins (the real tree's pins are now consistent, so
    # this injection is the only way to prove the assertion can go red).
    def fake_pins():
        return {"svc_a": {"PyYAML": "6.0.2", "redis": "8.1.0"},
                "svc_b": {"PyYAML": "6.0.2", "redis": "7.9.0"}}
    p = _check_injected("A6", [("_find_pins", fake_pins)])
    if not any("[FAIL] A6:" in x for x in p):
        fails.append("A6 injection did not produce a [FAIL] -- assertion #6 "
                     "is dormant/unwired")

    # A6(hash): fake a requirements file that pins redis with NO --hash=.
    def fake_reqs1():
        return {"svc_a": {"redis": "8.1.0"}}
    def fake_hashes1(_orig=_require_hashes, _req=None):
        return ["[FAIL] A6(hash): redis pinned in svc_a (redis==8.1.0) has "
                "NO --hash= pin -- a tampered wheel is installable."]
    p = _check_injected("A6(hash)", [("_find_pins", fake_reqs1),
                                     ("_require_hashes", fake_hashes1)])
    if not any("[FAIL] A6(hash):" in x for x in p):
        fails.append("A6(hash) injection did not produce a [FAIL] -- the "
                     "hash-presence sub-check is dormant/unwired")

    # A6(completeness): fake a service with a Dockerfile but no requirements.
    def fake_svcs():
        return {"svc_a": {"redis": "8.1.0"}}
    def fake_dockers():
        return {"ghost-svc": ""}
    p = _check_injected("A6(completeness)", [("_find_pins", fake_svcs),
                                             ("_find_requirements_services", fake_dockers)])
    if not any("[FAIL] A6(completeness):" in x for x in p):
        fails.append("A6(completeness) injection did not produce a [FAIL] -- "
                     "the missing-requirements sub-check is dormant/unwired")

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
