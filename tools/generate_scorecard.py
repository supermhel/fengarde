"""generate_scorecard -- render ``eval/SCORECARD.md`` from the gate's own artifacts.

The card is COMMITTED and generated. It is never hand-edited: ``--check``
re-renders from the JSON artifacts the gate just produced and fails on any
difference, printing a unified diff plus a cell-level summary that names the
metric and both values.

Usage (see also ``make scorecard``)
-----------------------------------
    python tools/generate_scorecard.py --run --write   # refresh artifacts AND the committed card
    python tools/generate_scorecard.py --check      # exit 1 if the card is stale
    python tools/generate_scorecard.py --lint-docs  # README/SSOT quote only card numbers
    python tools/generate_scorecard.py --print      # render to stdout

``--run`` re-executes EVERY instrument in the gate's order. It writes the
SHARED gitignored artifacts (``eval/adversarial/out/``, ``eval/attack/out/``,
``eval/twin/report.latest.json``, ``eval/twin/out/``), so it MUST NOT be run
concurrently with ``run_all_tests.sh`` -- two concurrent writers would race on
the same paths and both could then read the other's half-written file. The
cost is several minutes (it is the scorecard, twin, mutation, corpus and
evasion lanes); the in-gate ``--check`` is the cheap path and is what
``make test`` uses. ``report.py`` keeps ``--no-trend`` so a run never dirties
the committed ``eval/trend.jsonl``.

Determinism
-----------
Two renders from the same artifacts are byte-identical, and a render is
invariant to the JSON key ORDER in every artifact (the renderer sorts what it
iterates). No wall-clock value, date, ISO timestamp, backslash or ``C:`` path
appears in the output; a test asserts each of those absences.
"""
from __future__ import annotations

import argparse
import ast
import difflib
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "eval"))

import scorecard_registry as reg  # noqa: E402

REGISTRY_PATH = ROOT / "eval" / "scorecard_registry.py"
CARD = ROOT / reg.CARD_PATH
GATE = ROOT / reg.GATE_SH


# ==========================================================================
# Loading
# ==========================================================================
def load_artifacts(root: Path = ROOT) -> tuple[dict, list[str]]:
    """Read every artifact. Returns (arts, problems). A missing or unparseable
    artifact is a problem, never a silent skip: a card rendered over a missing
    artifact would report 'not measured' as if it were a measurement."""
    arts: dict = {}
    problems: list[str] = []
    for spec in reg.ARTIFACTS:
        p = root / spec.path
        if not p.exists():
            problems.append(f"[MISSING] {spec.key}: {spec.path} does not exist "
                            f"(producer: {spec.producer})")
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            problems.append(f"[UNREADABLE] {spec.key}: {spec.path}: {exc}")
            continue
        if spec.kind == "list" and not isinstance(data, list):
            problems.append(f"[SHAPE] {spec.key}: {spec.path} is a "
                            f"{type(data).__name__}, expected a list")
            continue
        if spec.kind == "dict" and not isinstance(data, dict):
            problems.append(f"[SHAPE] {spec.key}: {spec.path} is a "
                            f"{type(data).__name__}, expected a dict")
            continue
        if not data:
            problems.append(f"[EMPTY] {spec.key}: {spec.path} is empty -- a vacuous "
                            f"green; nothing to render")
            continue
        if spec.kind == "dict":
            missing = [k for k in spec.required_keys if k not in data]
            if missing:
                problems.append(f"[SHAPE] {spec.key}: {spec.path} is missing "
                                f"top-level key(s) {missing}")
                continue
        elif spec.required_keys:
            missing = [k for k in spec.required_keys if k not in data[0]]
            if missing:
                problems.append(f"[SHAPE] {spec.key}: {spec.path}[0] is missing "
                                f"key(s) {missing}")
                continue
        arts[spec.key] = data
    return arts, problems


def _dig(data, dotted: str):
    node = data
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def validate_provenance(arts: dict, root: Path = ROOT, *,
                        mtimes: dict[str, float] | None = None,
                        inputs_mtime: float | None = None,
                        seed: int = 7) -> list[str]:
    """Every artifact's OWN seed/basis rule, plus the mtime freshness guard.

    The artifacts do not share a shape, so there is no single check:
      * layer_a / scenario_matrix / evasion / corpus_b -- seed and basis at the
        TOP level.
      * twin -- seed and basis under ``report.``.
      * fire_check -- a bare LIST with no seed and no basis anywhere.
      * oracle_consistency -- seed and basis PER SCENARIO, none at the top.
    """
    problems: list[str] = []
    for spec in reg.ARTIFACTS:
        data = arts.get(spec.key)
        if data is None:
            continue  # load_artifacts already reported it
        if spec.seed_per_scenario:
            if not data:
                problems.append(f"[PROVENANCE] {spec.key}: no scenarios")
            for sc, f in sorted(data.items()):
                if not isinstance(f, dict):
                    problems.append(f"[PROVENANCE] {spec.key}.{sc}: not an object")
                    continue
                if f.get("scenario") != sc:
                    problems.append(f"[PROVENANCE] {spec.key}.{sc}: scenario={f.get('scenario')!r}")
                if f.get("seed") != seed:
                    problems.append(f"[PROVENANCE] {spec.key}.{sc}: seed="
                                    f"{f.get('seed')!r}, expected {seed}")
                if f.get("basis") != "harness-measured":
                    problems.append(f"[PROVENANCE] {spec.key}.{sc}: basis="
                                    f"{f.get('basis')!r}, expected 'harness-measured'")
            continue
        if spec.seed_path is None:
            # a bare list: nothing to assert about seed/basis (by design)
            continue
        got_seed = _dig(data, spec.seed_path)
        got_basis = _dig(data, spec.basis_path) if spec.basis_path else None
        if got_seed != seed:
            problems.append(f"[PROVENANCE] {spec.key}: {spec.seed_path}={got_seed!r}, "
                            f"expected {seed}")
        if got_basis != "harness-measured":
            problems.append(f"[PROVENANCE] {spec.key}: {spec.basis_path}="
                            f"{got_basis!r}, expected 'harness-measured'")
    problems += _check_artifact_count(arts)
    problems += check_freshness(arts, root, mtimes=mtimes, inputs_mtime=inputs_mtime)
    return problems


def _check_artifact_count(arts: dict) -> list[str]:
    problems: list[str] = []
    n = sum(1 for k in reg.ARTIFACTS_BY_KEY if k in arts)
    if n != len(reg.ARTIFACTS):
        problems.append(
            f"[PROVENANCE] {n} of {len(reg.ARTIFACTS)} artifact(s) loaded "
            f"(a card over a partial artifact set would read 'not measured' as a fact)")
    return problems


def _newest_input_mtime(root: Path) -> tuple[float, str]:
    newest = 0.0
    newest_name = "<none>"
    for pattern in reg.FRESHNESS_INPUT_GLOBS:
        for p in root.glob(pattern):
            if not p.is_file():
                continue
            try:
                m = p.stat().st_mtime
            except OSError:
                continue
            if m > newest:
                newest, newest_name = m, str(p.relative_to(root)).replace("\\", "/")
    return newest, newest_name


def check_freshness(arts: dict, root: Path = ROOT, *,
                    mtimes: dict[str, float] | None = None,
                    inputs_mtime: float | None = None) -> list[str]:
    """An artifact older than any input the instruments read is STALE: it was
    produced by an earlier tree and cannot validate this one.

    It fails safe -- it can reject a valid card but never pass a stale one.
    ``mtimes`` (per artifact key) and ``inputs_mtime`` are injectable so a test
    can prove the guard can go red without touching the real filesystem.
    """
    if inputs_mtime is None:
        inputs_mtime, newest_name = _newest_input_mtime(root)
    else:
        newest_name = "<injected>"
    if inputs_mtime == 0.0:
        return [f"[STALE] no freshness input file matched {reg.FRESHNESS_INPUT_GLOBS!r} "
                f"-- vacuous green, so staleness cannot be detected"]
    problems: list[str] = []
    for spec in reg.ARTIFACTS:
        if spec.key not in arts:
            continue
        if mtimes is not None and spec.key in mtimes:
            m = mtimes[spec.key]
        else:
            p = root / spec.path
            if not p.exists():
                continue
            m = p.stat().st_mtime
        if m < inputs_mtime:
            problems.append(
                f"[STALE] {spec.key}: stale artifact, rerun the gate "
                f"({spec.path} is older than the newest input {newest_name})")
    return problems


# ==========================================================================
# Controls
# ==========================================================================
def _gate_references(gate_text: str) -> set[str]:
    """Repo-relative test files the gate runs, read from its ACTIVE
    (uncommented) lines; ``(cd DIR && $PY NAME.py)`` resolves to
    ``DIR/NAME.py``. A commented-out line used to count as wired, and a bare
    basename matched any file of that name (every service has a
    ``test_contract.py``) -- external review 2026-10-14."""
    text = reg.active_gate_text(gate_text)
    refs = set()
    for m in re.finditer(r"cd\s+([\w./-]+)\s*&&\s*\$PY\s+([\w./-]+\.py)", text):
        refs.add(f"{m.group(1).rstrip('/')}/{m.group(2)}")
    for m in re.finditer(r"\$PY\s+([\w./-]+\.py)", text):
        refs.add(m.group(1))
    return refs


def _enclosing_function(tree: ast.AST, needle: str, lines: list[str]):
    """Resolve the function a needle sits in, using stdlib ast.

    A needle that IS a ``def`` line (the easiest shape to keep unique and
    readable) resolves to that FunctionDef; otherwise it resolves to the
    INNERMOST function whose body spans the needle's line.
    """
    # 1) the needle is on a def line
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            line = lines[node.lineno - 1] if node.lineno <= len(lines) else ""
            if needle in line:
                return node
    # 2) innermost function whose body contains the needle
    idx = next((i for i, ln in enumerate(lines, start=1) if needle in ln), None)
    if idx is None:
        return None
    best = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", node.lineno) or node.lineno
            if node.lineno <= idx <= end:
                if best is None or node.lineno >= best.lineno:
                    best = node
    return best


def _names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _called_from_entry(tree: ast.Module) -> set[str]:
    """Module-level functions REACHABLE from the ``if __name__ == "__main__":``
    block: named there (called, or listed -- ``tests = [test_a, ...]`` counts),
    then transitively through every reachable function's body. A needle can
    exist and the file can be gate-wired while the enclosing function is never
    executed -- the dormant-test class this repo already fixed (a9b9313).

    External review 2026-10-14: the first version also counted every
    expression-statement call ANYWHERE in the module, so a test called only from
    another never-called function passed as "called from main()". Only
    reachability from the entry block counts now. ``unittest.main()`` in the
    entry block makes every ``test*`` method of the module's classes reachable."""
    defs = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    entry: list[ast.AST] = [
        n for n in tree.body
        if isinstance(n, ast.If) and isinstance(n.test, ast.Compare)
        and isinstance(n.test.left, ast.Name) and n.test.left.id == "__name__"]
    reach: set[str] = set()
    todo = set().union(*(_names_in(e) for e in entry)) if entry else set()
    while todo:
        name = todo.pop()
        if name in reach:
            continue
        reach.add(name)
        if name in defs:
            todo |= _names_in(defs[name]) - reach
    scopes = entry + [defs[n] for n in reach if n in defs]
    runs_unittest = any(isinstance(a, ast.Attribute) and a.attr == "main"
                        and isinstance(a.value, ast.Name) and a.value.id == "unittest"
                        for s in scopes for a in ast.walk(s))
    if runs_unittest:
        for cls in (n for n in tree.body if isinstance(n, ast.ClassDef)):
            reach |= {m.name for m in cls.body
                      if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
                      and m.name.startswith("test")}
    return reach


def check_one_control(ref: "reg.ControlRef", root: Path = ROOT,
                      gate_text: str | None = None) -> list[str]:
    problems: list[str] = []
    p = root / ref.test_file
    if not p.exists():
        return [f"[CONTROL] {ref.test_file}: file does not exist"]
    src = p.read_text(encoding="utf-8")
    if gate_text is None:
        gate_text = GATE.read_text(encoding="utf-8") if GATE.exists() else ""
    if ref.test_file not in _gate_references(gate_text):
        problems.append(f"[CONTROL] {ref.test_file}: not invoked by {reg.GATE_SH} "
                        f"via `$PY` -- a control in an unwired file proves nothing")
    lines = src.splitlines()
    hits = sum(1 for ln in lines if ref.needle in ln)
    if not hits:
        problems.append(f"[CONTROL] {ref.test_file}: needle {ref.needle!r} not found")
        return problems
    if hits > 1:
        # "def test_x" is also a prefix of "def test_x_more": the first match
        # would silently decide which function the control means
        problems.append(f"[CONTROL] {ref.test_file}: needle {ref.needle!r} is on {hits} "
                        f"lines -- it must be unique")
        return problems
    try:
        tree = ast.parse(src)
    except SyntaxError as exc:
        problems.append(f"[CONTROL] {ref.test_file}: cannot parse ({exc})")
        return problems
    fn = _enclosing_function(tree, ref.needle, lines)
    if fn is None:
        problems.append(f"[CONTROL] {ref.test_file}: needle {ref.needle!r} is not "
                        f"inside any function")
        return problems
    called = _called_from_entry(tree)
    if fn.name not in called:
        problems.append(
            f"[CONTROL] {ref.test_file}: {ref.needle!r} sits in {fn.name}() which is "
            f"never CALLED from main()/__main__ -- a dormant control, not a control")
    return problems


def verify_controls(root: Path = ROOT, gate_text: str | None = None) -> list[str]:
    problems: list[str] = []
    for key, ref in sorted(reg.CONTROLS.items()):
        for pr in check_one_control(ref, root, gate_text):
            problems.append(f"{pr} (control {key!r})")
    return problems


# ==========================================================================
# Limits
# ==========================================================================
def verify_limits(arts: dict, root: Path = ROOT) -> list[tuple[str, bool, str, bool]]:
    out = []
    for lim in reg.LIMITS:
        if lim.guard is None:
            out.append((lim.key, True, "static (unguarded)", True))
            continue
        try:
            ok, evidence = lim.guard(arts, root)
        except Exception as exc:  # a broken guard must not read as green
            ok, evidence = False, f"guard raised {type(exc).__name__}: {exc}"
        out.append((lim.key, bool(ok), evidence, False))
    return out


# ==========================================================================
# Gate wiring
# ==========================================================================
LAST_INSTRUMENT = reg.INSTRUMENTS_RUN_BEFORE_CHECK[-1][1][0]


def assert_gate_wiring(gate_text: str) -> list[str]:
    """``--check`` must run AFTER the last instrument stanza, or it renders a
    card from the PREVIOUS run's artifacts and passes. Reads the gate's ACTIVE
    lines only (a commented-out stanza is not a stanza)."""
    gate_text = reg.active_gate_text(gate_text)
    if reg.CHECK_STANZA not in gate_text:
        return [f"[WIRING] {reg.GATE_SH} does not invoke {reg.CHECK_STANZA!r} -- the "
                f"scorecard is checked by nobody"]
    idx = gate_text.index(reg.CHECK_STANZA)
    problems: list[str] = []
    for key, cmd in reg.INSTRUMENTS_RUN_BEFORE_CHECK:
        needle = f"$PY {cmd[0]}"
        j = gate_text.find(needle)
        if j < 0:
            problems.append(f"[WIRING] instrument {key} ({needle}) is not in "
                            f"{reg.GATE_SH} -- the check cannot be proven to run after it")
            continue
        if j > idx:
            problems.append(f"[WIRING] instrument {key} runs AFTER the scorecard "
                            f"--check stanza; the card would be rendered from a "
                            f"previous run's artifacts")
    return problems


# ==========================================================================
# Model + render
# ==========================================================================
def _clean(s: str) -> str:
    return " ".join(str(s).split()).replace("|", "/").replace("\\", "/")


_DASH = {"higher_better": "higher-better", "lower_better": "lower-better",
         "flag": "flag", "info": "info"}


def _control_cell(m: "reg.MetricSpec") -> str:
    if m.control_key is None:
        return "**NONE**"
    ref = reg.CONTROLS.get(m.control_key)
    if ref is None:
        return "**NONE**"
    return f"`{ref.test_file}::{ref.needle.replace('def ', '')}`"


def _value_cell(m: "reg.MetricSpec", raw) -> str:
    return reg._f(raw)


def _extract(m: "reg.MetricSpec", arts: dict, storyline: str, errors: list[str]):
    """One cell's raw value. An extractor that RAISES is a shape the card cannot
    read: it is recorded in ``errors`` (main() then refuses to render) instead of
    being rendered as ``null`` -- which read exactly like a measured null, and
    ``--write`` would have committed it (external review 2026-10-14)."""
    try:
        return m.extract(arts[m.source], storyline)
    except Exception as exc:  # noqa: BLE001 -- every failure is reported, none is hidden
        errors.append(f"[EXTRACT] {m.key} ({storyline or 'global'}): "
                      f"{type(exc).__name__}: {exc}")
        return None


def _storyline_rows(arts: dict, errors: list[str] | None = None) -> dict[str, list[tuple]]:
    errors = [] if errors is None else errors
    rows: dict[str, list[tuple]] = {s: [] for s in reg.STORYLINES}
    denominator = arts.get("__denominator__", {})
    for m in reg.METRICS:
        if m.scope != "storyline":
            continue
        for s in reg.STORYLINES:
            raw = _extract(m, arts, s, errors)
            val = _value_cell(m, raw)
            if m.key == "tpr":
                non_gap, n_steps, n_gaps = denominator.get(s, (0, 0, 0))
                # the numerator is the measured TPR times the non-gap denominator;
                # printing "{non_gap}/{non_gap}" claimed full coverage whatever TPR was
                hit = round(raw * non_gap) if isinstance(raw, (int, float)) and not \
                    isinstance(raw, bool) else "?"
                val = (f"{val} (non-gap steps detected {hit}/{non_gap}; oracle declares "
                       f"{n_steps} step(s) and {n_gaps} gap(s))")
            rows[s].append((m, val))
    return rows


def _non_gap_denominator(arts: dict) -> dict[str, tuple[int, int]]:
    """Deprecated shim kept for external callers; the renderer reads
    ``__denominator__`` directly."""
    return arts.get("__denominator__", {})


def _technique_rows(arts: dict) -> list[dict]:
    fc = arts.get("fire_check") or []
    oracle_index = arts.get("__oracle_index_rules__", {})
    e2e_steps: dict[str, list[str]] = {}
    for step_key, meta in oracle_index.items():
        for rid in meta["rule_ids"]:
            e2e_steps.setdefault(rid, []).append(step_key)

    groups: dict[str, list[dict]] = {}
    for r in fc:
        groups.setdefault(r.get("technique") or "<untagged>", []).append(r)

    # technique -> the storyline/step labels that declare a rule of that technique
    tech_by_rule: dict[str, str] = {}
    for r in fc:
        rid = r.get("id")
        if rid:
            tech_by_rule[str(rid)] = str(r.get("technique") or "<untagged>")
    step_tech: dict[str, set] = {}
    for step_key, meta in oracle_index.items():
        for rid in meta["rule_ids"]:
            t = tech_by_rule.get(str(rid))
            if t:
                step_tech.setdefault(step_key, set()).add(t)

    sm = arts.get("scenario_matrix") or {}
    applicable_rows: list[tuple[str, dict]] = []
    for s, node in sorted((sm.get("scenarios") or {}).items()):
        for r in node.get("rows", []):
            if r.get("applicable") is True:
                applicable_rows.append((s, r))

    companions = arts.get("__companions__", set())
    out = []
    for tech in sorted(groups):
        rules = groups[tech]
        n = len(rules)
        n_comp = sum(1 for r in rules if r.get("id") in companions)
        verified = 0
        unheld = []
        for r in rules:
            b = r.get("boundary") or {}
            nm = r.get("near_miss") or {}
            held = ((b.get("applicable") and b.get("fully_held")) or
                    (nm.get("applicable") and nm.get("fully_held")))
            if r.get("fired") and held:
                verified += 1
            elif not held:
                unheld.append(r.get("id"))
        steps = sorted({s for r in rules for s in e2e_steps.get(str(r.get("id")), [])})
        # steps lost for this technique, over the applicable variant denominator
        lost_variants = []
        for s, r in applicable_rows:
            hit = sorted({st for st in (r.get("expected_rule_lost_steps") or [])
                          if tech in step_tech.get(f"{s}/{st}", set())})
            if hit:
                lost_variants.append(f"{s}/{r.get('variant')}")
        lost_variants.sort()
        framework = sorted({str(r.get("framework")) for r in rules})
        tactic = sorted({str(r.get("tactic")) for r in rules})
        out.append({
            "technique": tech,
            "framework": "/".join(framework),
            "tactic": "/".join(tactic),
            "n_rules": n,
            "n_companion": n_comp,
            "verified": verified,
            "end_to_end": bool(steps),
            "steps": steps,
            "unheld": unheld,
            "lost": lost_variants,
            "lost_denom": len(applicable_rows),
        })
    return out


def build_model(arts: dict, root: Path = ROOT) -> dict:
    digest = hashlib.sha256(REGISTRY_PATH.read_bytes()).hexdigest()
    gate_text = (root / reg.GATE_SH).read_text(encoding="utf-8")
    limits = verify_limits(arts, root)
    extract_errors: list[str] = []

    twin_rows = []
    global_rows = []
    for m in reg.METRICS:
        if m.scope == "twin_only":
            raw = _extract(m, arts, reg.TWIN_STORYLINE, extract_errors)
            twin_rows.append((m, _value_cell(m, raw)))
        elif m.scope == "global":
            raw = _extract(m, arts, "", extract_errors)
            global_rows.append((m, _value_cell(m, raw)))

    stories = []
    sm = arts.get("scenario_matrix") or {}
    per_story = _storyline_rows(arts, extract_errors)
    for s in reg.STORYLINES:
        node = (sm.get("scenarios") or {}).get(s) or {}
        non_gap, steps, gaps = arts.get("__denominator__", {}).get(s, (0, 0, 0))
        stories.append({
            "name": s,
            "summary": _clean(node.get("summary") or ""),
            "n_steps": steps,
            "n_gaps": gaps,
            "n_non_gap": non_gap,
            "rows": per_story.get(s, []),
        })

    techniques = _technique_rows(arts)
    none_register = []
    for m in reg.METRICS:
        if m.control_key is None:
            if m.scope == "storyline":
                for s in reg.STORYLINES:
                    none_register.append((f"{s}/{m.label}", m.blind_spot))
            elif m.scope == "twin_only":
                none_register.append((f"{reg.TWIN_STORYLINE}/{m.label}", m.blind_spot))
            else:
                none_register.append((m.label, m.blind_spot))
    # Rendered cells with no control, counted BEFORE the 'not measured' entries:
    # those cells are not rendered anywhere, and the old sentence counted them as
    # "rendered metric cells" (70 of 91, when 10 rendered cells lacked a control).
    none_rendered = len(none_register)
    # twin-only metrics are 'not measured' for the other storylines
    for m in reg.METRICS:
        if m.scope == "twin_only":
            for s in reg.STORYLINES:
                if s != reg.TWIN_STORYLINE:
                    none_register.append(
                        (f"{s}/{m.label}",
                         "not measured: this metric is twin-only (AI-to-OT). "
                         "report.py is not generalised to the other storylines yet."))

    gaps = []
    for s, lst in sorted(arts.get("__gap_steps__", {}).items()):
        for step, reason in lst:
            gaps.append((s, step, _clean(reason)[:180]))

    model = {
        "digest": digest,
        "seed": arts.get("__seed__", 7),
        "basis": "harness-measured",
        "stories": stories,
        "twin_rows": twin_rows,
        "global_rows": global_rows,
        "techniques": techniques,
        "none_register": none_register,
        "none_rendered": none_rendered,
        "extract_errors": extract_errors,
        "gaps": gaps,
        "limits": limits,
        "pooled": (arts.get("scenario_matrix") or {}).get("pooled", {}),
        "gate_wiring": assert_gate_wiring(gate_text),
        "counts": {
            "tagged_rules": len(arts.get("fire_check") or []),
            "techniques": len(techniques),
            "storylines": len(reg.STORYLINES),
            "metrics": len(reg.METRICS),
        },
    }
    model["quotable"] = quotable_facts(model)
    return model


_HISTORICAL_HINT = "eval/SCORECARD.md"

#: The ONLY artifact locations where a backslash may appear. Empty: ``report.py``
#: once wrote the Layer A path with NATIVE separators, so the set differed between
#: a Windows-generated artifact and a Linux CI run and the test could not pass on
#: both. It now writes POSIX paths. This set is asserted against a live scan of the
#: artifacts by ``tools/test_generate_scorecard.py``, so any backslash path -- a
#: Windows path leaking into an artifact -- fails the test instead of quietly
#: reaching the card.
BACKSLASH_ALLOWED_ARTIFACT_PATHS: frozenset[str] = frozenset()


def _walk_strings(obj, path=""):
    if isinstance(obj, dict):
        for k in obj:
            yield from _walk_strings(obj[k], f"{path}.{k}" if path else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk_strings(v, f"{path}[{i}]")
    elif isinstance(obj, str):
        yield path, obj


def scan_artifacts_for_paths(arts: dict) -> tuple[set[str], set[str]]:
    """Scan every artifact for backslash and Windows drive paths.

    Returns ``(backslash_paths, drive_paths)`` as ``'<artifact>:<json.path>'``.
    """
    backslashes: set[str] = set()
    drives: set[str] = set()
    for spec in reg.ARTIFACTS:
        data = arts.get(spec.key)
        if data is None:
            continue
        for jpath, s in _walk_strings(data):
            if "\\" in s:
                backslashes.add(f"{spec.key}:{jpath}")
            if re.search(r"(?<![A-Za-z])[A-Za-z]:[\\/]", s):
                drives.add(f"{spec.key}:{jpath}")
    return backslashes, drives


def quotable_facts(model: dict) -> dict[str, dict[str, float]]:
    """metric key -> {scope: value} for every NUMERIC metric cell the card
    renders. The doc lint accepts a doc line's metric/number pair only when the
    number is one of that metric's values HERE -- so a number that no artifact
    produced cannot be quoted as if it had been measured."""
    out: dict[str, dict[str, float]] = {}
    for m, val in model["twin_rows"]:
        _absorb(out, m, val, f"{reg.TWIN_STORYLINE} (twin)")
    for m, val in model["global_rows"]:
        _absorb(out, m, val, "global")
    for st in model["stories"]:
        for m, val in st["rows"]:
            _absorb(out, m, val, st["name"])
    return out


def _absorb(out, m: "reg.MetricSpec", val: str, scope: str) -> None:
    key = getattr(m, "alias_key", None) or m.key
    try:
        f = float(val.split()[0])
    except (ValueError, IndexError):
        return
    out.setdefault(key, {})[scope] = f


# --------------------------------------------------------------------------
def render(model: dict) -> str:
    L: list[str] = []
    a = L.append
    a("# FENGARDE evaluation scorecard")
    a("")
    a("Generated by `tools/generate_scorecard.py` from the gate's own JSON artifacts.")
    a("Do not edit this file by hand: the `run_all_tests.sh` scorecard stanza re-renders")
    a("it and fails on any difference.")
    a("")
    a(f"- basis: `{model['basis']}`  |  seed: `{model['seed']}`")
    a(f"- registry digest: `{model['digest']}` (`eval/scorecard_registry.py`)")
    a(f"- {model['counts']['tagged_rules']} tagged rules, "
      f"{model['counts']['techniques']} ATT&CK/ATT&CK-ICS/ATLAS techniques, "
      f"{model['counts']['storylines']} storylines, "
      f"{model['counts']['metrics']} registered metrics")
    p = model["pooled"]
    if p:
        a(f"- pooled across storylines: {p.get('passed')}/{p.get('applicable')} = "
          f"{reg._f(p.get('mutation_robustness'))} "
          f"(convenience only -- the per-storyline numbers are the result)")
    a("")
    a("## How to read this card")
    a("")
    a("- Every value is read from a JSON artifact the gate produced in the run that")
    a("  checked this card. Nothing here is hand-copied.")
    a("- **Control existence is static.** A control proves that a cited assertion")
    a("  EXISTS in a gate-wired test file and is CALLED from that module's `main()`;")
    a("  it does not prove the assertion passed. Pass status is the gate's exit code.")
    a("- **A bold `NONE` is not 'fine'.** It means no control in this repository")
    a("  can move that number today. The reasons are all listed in the register below.")
    a("- Companion rules (those carrying `siem.companion_of`, `score_weight: 0`) COUNT as")
    a("  separate rules: they have their own rule ids and fire on their own. They are")
    a("  marked `†` in the per-technique table so a reader can tell them from standalone")
    a("  rules. The owner decided this; the alternative (folding them into their")
    a("  sibling) would hide rules that really do fire.")
    a("- Timestamps, wall-clock values and Windows paths are deliberately absent: the")
    a("  renderer refuses to read the volatile keys `" +
      "`, `".join(reg.VOLATILE) + "`.")
    a("")

    a("## Per-storyline metrics")
    a("")
    for st in model["stories"]:
        a(f"### {st['name']}")
        a("")
        if st["summary"]:
            a(st["summary"])
            a("")
        a(f"Oracle: {st['n_steps']} step(s), {st['n_gaps']} declared gap(s), "
          f"{st['n_non_gap']} non-gap step(s).")
        a("")
        a("| metric | value | direction | blind spot | control |")
        a("|---|---|---|---|---|")
        for m, val in st["rows"]:
            a(f"| {m.label} | {val} | {_DASH[m.direction]} | {_clean(m.blind_spot)} | "
              f"{_control_cell(m)} |")
        a("")

    a("## Twin metrics (AI-to-OT only)")
    a("")
    a("`eval/twin/report.latest.json` and `eval/adversarial/out/matrix.latest.json`")
    a("cover AI-to-OT. The other storylines show `not measured` for these; generalising")
    a("`report.py` is a separate step.")
    a("")
    a("| metric | value | direction | blind spot | control |")
    a("|---|---|---|---|---|")
    for m, val in model["twin_rows"]:
        a(f"| {m.label} | {val} | {_DASH[m.direction]} | {_clean(m.blind_spot)} | "
          f"{_control_cell(m)} |")
    a("")

    a("## Cross-cutting metrics")
    a("")
    a("| metric | value | direction | blind spot | control |")
    a("|---|---|---|---|---|")
    for m, val in model["global_rows"]:
        a(f"| {m.label} | {val} | {_DASH[m.direction]} | {_clean(m.blind_spot)} | "
          f"{_control_cell(m)} |")
    a("")

    a(f"## Per-technique coverage ({model['counts']['techniques']} techniques, "
      f"{model['counts']['tagged_rules']} tagged rules)")
    a("")
    a("`rules` = tagged rules carrying the technique (`†` = companion rule).")
    a("`verified` = rules that fired on their own producer fixture AND whose boundary or")
    a("near-miss probe held. `lost` = applicable mutation variants in which a step carrying")
    a("this technique lost its expected rule, over ALL applicable variants, with the variant")
    a("names sorted. Coverage is credited from MEASURED firing, never from the oracle's")
    a("declared `expected_rules`: a rule listed at a step that did not fire is counted as a")
    a("decorative expectation (see the cross-cutting table), never as coverage.")
    a("")
    a("| technique | framework | tactic | rules | verified | lost | end-to-end | blind spot | control |")
    a("|---|---|---|---|---|---|---|---|---|")
    fc_ref = reg.CONTROLS["fire_check_boundary"]
    fc_cell = f"`{fc_ref.test_file}::{fc_ref.needle.replace('def ', '')}`"
    for t in model["techniques"]:
        rules_cell = str(t["n_rules"])
        if t["n_companion"]:
            rules_cell += f" ({t['n_companion']}† companion)"
        verif = f"{t['verified']}/{t['n_rules']}"
        lost = f"{len(t['lost'])}/{t['lost_denom']}"
        if t["lost"]:
            lost += " (" + ", ".join(t["lost"]) + ")"
        if t["end_to_end"]:
            e2e = "yes: " + ", ".join(t["steps"])
        else:
            e2e = "**NOT EXERCISED END-TO-END**"
        if t["unheld"]:
            blind = (f"a boundary/near-miss probe did NOT hold for "
                     f"{len(t['unheld'])} rule(s); fire_check proves declared-vs-fired "
                     f"on the rule's own producer fixture, not real-world detection")
        elif t["end_to_end"]:
            blind = ("declared at an oracle step AND measured on the rule's own fixture; "
                     "the two agree, which still says nothing about traffic the fixture "
                     "does not model")
        else:
            blind = ("declared at no oracle step: measured only on the rule's own "
                     "producer fixture, so no storyline exercises it end-to-end")
        a(f"| {t['technique']} | {t['framework']} | {t['tactic']} | {rules_cell} | "
          f"{verif} | {lost} | {e2e} | {blind} | {fc_cell} |")
    a("")

    a(f"## Oracle gaps ({len(model['gaps'])})")
    a("")
    a("Steps the oracle records with `no_rule_exists: true`. These are excluded from the")
    a("TPR denominator, so a declared gap can never lower TPR -- read them here, not there.")
    a("")
    a("| storyline | step | reason |")
    a("|---|---|---|")
    for s, step, reason in model["gaps"]:
        a(f"| {s} | {step} | {reason} |")
    a("")

    a("## Register: metric cells with NO control")
    a("")
    not_measured = len(model["none_register"]) - model["none_rendered"]
    a(f"{model['none_rendered']} of {_total_cells(model)} rendered metric cells have no "
      f"control that can move them today, and {not_measured} more cells are not measured "
      f"at all (twin-only metrics for the other storylines; listed below, not rendered "
      f"above). Each is a gap in the harness, not a clean bill of health.")
    a("")
    a("| cell | why there is no control |")
    a("|---|---|")
    for cell, why in model["none_register"]:
        a(f"| {cell} | {_clean(why)} |")
    a("")

    a("## What this harness cannot prove")
    a("")
    for i, (key, ok, evidence, static) in enumerate(model["limits"], start=1):
        ev = "static (unguarded)" if static else f"guard: {'OK' if ok else 'FAILED'} -- {_clean(evidence)}"
        a(f"{i}. {_clean(_limit_text(key))}")
        a(f"   - {ev}")
    a("")

    a("## Provenance")
    a("")
    a("| artifact | path | producer |")
    a("|---|---|---|")
    for spec in reg.ARTIFACTS:
        a(f"| {spec.key} | `{spec.path}` | `{spec.producer}` |")
    a("")
    a("<!-- QUOTABLE-FACTS (machine-read by `tools/generate_scorecard.py --lint-docs`)")
    a(json.dumps(model["quotable"], indent=1, sort_keys=True))
    a("-->")
    a("")
    return "\n".join(L) + "\n"


def _limit_text(key: str) -> str:
    for lim in reg.LIMITS:
        if lim.key == key:
            return lim.text
    return key


def _total_cells(model: dict) -> int:
    n = 0
    for st in model["stories"]:
        n += len(st["rows"])
    n += len(model["twin_rows"]) + len(model["global_rows"])
    n += len(model["techniques"])
    return n


# ==========================================================================
# Cell-level diff
# ==========================================================================
CELL_ROW = re.compile(r"^\|\s*([^|]+?)\s*\|\s*([^|]*?)\s*\|")


def extract_cells(text: str) -> dict[str, str]:
    """cell id -> value, where the id is ``###-scope|first-column``. Used to name
    a changed metric in the ``--check`` summary (the unified diff shows the line;
    this says WHICH CELL moved)."""
    cells: dict[str, str] = {}
    scope = ""
    for line in text.splitlines():
        if line.startswith("### "):
            scope = line[4:].strip()
            continue
        if line.startswith("## "):
            scope = line[3:].strip()
            continue
        m = CELL_ROW.match(line)
        if not m:
            continue
        col0 = m.group(1).strip()
        if col0 in ("metric", "technique", "---", "artifact", "cell") or set(col0) <= {"-"}:
            continue
        cells[f"{scope}|{col0}"] = m.group(2).strip()
    return cells


def cell_summary(committed: str, fresh: str) -> list[str]:
    old, new = extract_cells(committed), extract_cells(fresh)
    out = []
    for k in sorted(set(old) | set(new)):
        if old.get(k) != new.get(k):
            out.append(f"cell {k}: committed={old.get(k, '<absent>')!r} "
                       f"fresh={new.get(k, '<absent>')!r}")
    return out


# ==========================================================================
# Doc lint
# ==========================================================================
def _alias_regex() -> re.Pattern:
    toks = sorted(reg.ALIASES, key=len, reverse=True)
    alt = "|".join(re.escape(t) for t in toks)
    # The number may be followed by a sentence-ending "." -- the old lookahead
    # (?![\d.]) rejected "tpr 0.42." outright, so any quote at the end of a
    # sentence escaped the lint (external review 2026-10-14). Only a further
    # digit, or a "." that continues the number, disqualifies the match.
    return re.compile(rf"(?<![\w.])({alt})(?:\s*[:=]\s*|\s+)(-?\d+(?:\.\d+)?)(?!\d|\.\d)",
                      re.IGNORECASE)


def _ssot_scanned_lines(text: str) -> list[tuple[int, str]]:
    lines = text.splitlines()
    out = []
    section = None
    for i, line in enumerate(lines, start=1):
        m = re.match(r"^##\s+(\d+)\.", line)
        if m:
            section = m.group(1)
            continue
        if line.startswith("## "):
            section = None
            continue
        if section in reg.SSOT_SCANNED_SECTIONS:
            out.append((i, line))
    return out


def lint_docs(root: Path = ROOT, quotable: dict | None = None) -> list[str]:
    problems: list[str] = []
    if quotable is None:
        quotable = quotable_from_card(root)
    rx = _alias_regex()
    for rel in reg.DOC_LINT_FILES:
        p = root / rel
        if not p.exists():
            problems.append(f"[LINT] {rel} does not exist")
            continue
        text = p.read_text(encoding="utf-8")
        pairs = _ssot_scanned_lines(text) if rel == "SSOT.md" else \
            list(enumerate(text.splitlines(), start=1))
        for i, line in pairs:
            if reg.HISTORICAL_TAG in line:
                continue
            for m in rx.finditer(line):
                alias, num = m.group(1), m.group(2)
                key = reg.ALIASES.get(alias.lower())
                if key is None:
                    continue
                allowed = quotable.get(key, {})
                try:
                    fv = float(num)
                except ValueError:
                    continue
                if any(abs(fv - v) < 1e-9 for v in allowed.values()):
                    continue
                scopes = ", ".join(f"{s}={reg._f(v)}" for s, v in sorted(allowed.items()))
                problems.append(
                    f"[LINT] {rel}:{i}: {alias} {num} is not a card number for "
                    f"'{key}' (card holds: {scopes or 'nothing'}). Quote the card, or "
                    f"tag the line {reg.HISTORICAL_TAG} - current: {_HISTORICAL_HINT}].")
    return problems


def quotable_from_card(root: Path = ROOT) -> dict:
    """Read the machine block out of the committed card."""
    p = root / reg.CARD_PATH
    if not p.exists():
        return {}
    text = p.read_text(encoding="utf-8")
    m = re.search(r"<!-- QUOTABLE-FACTS.*?\n(.*?)\n-->", text, re.DOTALL)
    if not m:
        return {}
    try:
        return json.loads(m.group(1))
    except ValueError:
        return {}


# ==========================================================================
# REGRESSIONS
# ==========================================================================
def regressions(committed_cells: dict, fresh_cells: dict) -> list[str]:
    out = []
    by_label = {}
    for m in reg.METRICS:
        by_label[m.label] = m
    for k, newv in sorted(fresh_cells.items()):
        if k not in committed_cells:
            continue
        col0 = k.split("|", 1)[-1]
        m = by_label.get(col0)
        if m is None or m.direction not in ("higher_better", "lower_better"):
            continue
        try:
            newf = float(newv.split()[0])
            oldf = float(committed_cells[k].split()[0])
        except (ValueError, IndexError):
            continue
        if m.direction == "higher_better" and newf < oldf:
            out.append(f"REGRESSION: {k} fell {oldf} -> {newf}")
        elif m.direction == "lower_better" and newf > oldf:
            out.append(f"REGRESSION: {k} rose {oldf} -> {newf}")
    return out


# ==========================================================================
# --run
# ==========================================================================
def run_instruments(root: Path = ROOT) -> int:
    print("== --run: replaying every instrument in the gate's order ==")
    print("   NOTE: this writes the SHARED gitignored artifacts. Do NOT run it")
    print("   concurrently with run_all_tests.sh -- two writers would race on the")
    print("   same paths. report.py keeps --no-trend so eval/trend.jsonl stays clean.")
    rc = 0
    for key, cmd in reg.INSTRUMENTS_RUN_BEFORE_CHECK:
        print(f"-- {key}: {' '.join(cmd)}")
        proc = subprocess.run([sys.executable, *cmd], cwd=str(root))
        if proc.returncode != 0:
            print(f"   [FAIL] {key} exited {proc.returncode}")
            rc = 1
    return rc


# ==========================================================================
# CLI
# ==========================================================================
def _prepare(arts_override=None):
    arts, problems = load_artifacts()
    if problems:
        return arts, problems, None
    arts = decorate(arts)
    problems += validate_provenance(arts)
    problems += _check_pooled_sum(arts)
    problems += _check_storylines(arts)
    problems += verify_controls()
    problems += assert_gate_wiring((ROOT / reg.GATE_SH).read_text(encoding="utf-8"))
    return arts, problems, None


def _check_pooled_sum(arts: dict) -> list[str]:
    """The card's per-storyline applicable denominator must equal the
    instrument's own pooled denominator. This caught a real reading mistake while
    building the card (a per-row recompute counted 91 applicable variants where
    the instrument counts 81), which is exactly why it is an assertion and not a
    comment."""
    sm = arts.get("scenario_matrix") or {}
    pooled = sm.get("pooled") or {}
    if not pooled:
        return []
    story_sum = sum((sm.get("scenarios", {}).get(s, {}).get("overall", {}) or {}).get(
        "applicable", 0) for s in reg.STORYLINES)
    check_any = any((sm.get("scenarios", {}).get(s, {}).get("overall") or {}).get("applicable")
                    is not None for s in reg.STORYLINES)
    if check_any and story_sum != pooled.get("applicable"):
        return [f"[POOLED] per-storyline applicable denominators sum to {story_sum} but the "
                f"instrument's pooled denominator is {pooled.get('applicable')} -- the card "
                f"would report a different denominator than the lane did"]
    return []


def _oracle_rule_ids(expected_rules) -> list[str]:
    """Read a step's ``expected_rules`` defensively.

    The critic claimed the elements are bare rule-id STRINGS and that a literal
    ``.rule_id`` lookup raises. On THIS tree they are dicts carrying
    ``rule_id`` (plus title/level/role), so the claim is wrong -- and neither
    shape may be assumed. Accept a bare string OR a dict with ``rule_id``; skip
    anything unrecognised so a schema variant can never render a blank cell
    (which would read as "no rule expected here", i.e. as coverage).
    ``test_generate_scorecard.py`` asserts BOTH shapes.
    """
    ids: list[str] = []
    for er in expected_rules or []:
        rid = er if isinstance(er, str) else (er or {}).get("rule_id") \
            if isinstance(er, dict) else None
        if rid:
            ids.append(str(rid))
    return ids


def _check_storylines(arts: dict) -> list[str]:
    """The registry's STORYLINES must equal the artifact's own scenario_list.

    ``phishing_bec`` was added to ``scenario_registry.ALL`` AFTER the design spec
    was written (the spec assumes three storylines). This assertion is how the
    fourth is handled explicitly: a fifth storyline cannot appear in the
    artifacts without the registry being updated, and a registry entry cannot
    rot away unnoticed.
    """
    sm = arts.get("scenario_matrix") or {}
    got = set(sm.get("scenario_list") or [])
    want = set(reg.STORYLINES)
    if got != want:
        return [f"[STORYLINES] the artifacts register {sorted(got)} but the registry "
                f"lists {sorted(want)} -- {'/'.join(sorted(got - want))} would silently "
                f"vanish from the card (or {'/'.join(sorted(want - got))} is stale in the "
                f"registry)"]
    for s in sorted(want):
        if s not in (sm.get("scenarios") or {}):
            return [f"[STORYLINES] {s} is registered but has no scenario block"]
    # The evasion artifact feeds two per-storyline rows too. A storyline missing
    # there rendered "0 searched" -- which the blind spot explains as a scope
    # limit, not as "the lane never ran" (external review 2026-10-14).
    ev = set(((arts.get("evasion") or {}).get("scenarios") or {}))
    if ev and ev != want:
        return [f"[STORYLINES] evasion_search covers {sorted(ev)} but the registry lists "
                f"{sorted(want)}"]
    return []


def decorate(arts: dict) -> dict:
    """Attach derived indexes the registry (pure data) cannot compute."""
    import yaml
    storylines = list((arts.get("scenario_matrix") or {}).get("scenario_list") or [])
    # Oracle paths come from the REGISTRY, never from a hardcoded map: a map rots with
    # every storyline. It did, one storyline after this file was written -- a missing name
    # resolved to `ROOT / ''` == the repo directory and read_text() failed with Errno 13
    # (evidenced by the 5th storyline, ot_opcua_sabotage, 2026-10-14). A registered
    # storyline whose oracle file is missing must fail LOUDLY, not vanish from the card.
    # Lazy import, same convention as scenario_matrix.run_metric_controls: the harness
    # is kept off the module imports. eval/twin/ is not on tools/' sys.path by itself;
    # the twin modules set it up the same way when they import each other.
    import sys as _sys  # noqa: PLC0415
    _sys.path.insert(0, str(ROOT / "eval" / "twin"))
    import scenario_registry as sreg  # noqa: PLC0415, E402
    oracle_by_name = {s.name: s.oracle_path for s in sreg.ALL}
    denominator: dict[str, tuple[int, int, int]] = {}
    gap_steps: dict[str, list] = {}
    rule_index: dict[str, dict] = {}
    for s in storylines:
        p = oracle_by_name.get(s)
        if p is None or not Path(p).exists():
            raise FileNotFoundError(
                f"no oracle file for registered storyline {s!r} (registry path: {p!r}); "
                "the scorecard must not silently drop a storyline")
        oracle = yaml.safe_load(p.read_text(encoding="utf-8"))
        dp = oracle["detection_points"]
        n_steps = len(dp)
        gaps = 0
        glist = []
        for step, node in dp.items():
            if (node.get("gap") or {}).get("no_rule_exists"):
                gaps += 1
                glist.append((step, (node.get("gap") or {}).get("reason") or ""))
                continue
            ids = []
            for rid in _oracle_rule_ids(node.get("expected_rules")):
                ids.append(rid)
            rule_index[f"{s}/{step}"] = {"storyline": s, "rule_ids": ids}
        denominator[s] = (n_steps - gaps, n_steps, gaps)
        gap_steps[s] = glist
    companion_ids = set()
    for f in sorted((ROOT / "contracts" / "rules").glob("*.y*ml")):
        d = yaml.safe_load(f.read_text(encoding="utf-8"))
        if isinstance(d, dict) and (d.get("siem") or {}).get("companion_of"):
            if d.get("id"):
                companion_ids.add(d["id"])
    arts["__denominator__"] = denominator
    arts["__oracle_index__"] = denominator
    arts["__oracle_index_rules__"] = rule_index
    arts["__gap_steps__"] = gap_steps
    arts["__companions__"] = companion_ids
    arts["__seed__"] = 7
    return arts


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="generate_scorecard")
    ap.add_argument("--write", action="store_true", help="render and write eval/SCORECARD.md")
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if the committed card differs from a fresh render")
    ap.add_argument("--lint-docs", action="store_true",
                    help="README/SSOT may quote only numbers the card holds")
    ap.add_argument("--run", action="store_true",
                    help="re-run every instrument first (shared artifacts; NEVER "
                         "concurrent with run_all_tests.sh)")
    ap.add_argument("--print", dest="do_print", action="store_true",
                    help="render to stdout")
    args = ap.parse_args(argv)

    rc = 0
    if args.run and run_instruments():
        # its own message, not the "limit EXPIRED" one below (they used to share rc)
        print("[FAIL] an instrument failed during --run; refusing to render from its "
              "artifacts.")
        return 1

    arts, problems, _ = _prepare()
    if problems:
        for p in problems:
            print(p)
        print(f"[FAIL] scorecard: {len(problems)} problem(s); refusing to render.")
        return 1

    model = build_model(arts)
    if model["extract_errors"]:
        for e in model["extract_errors"]:
            print(e)
        print(f"[FAIL] scorecard: {len(model['extract_errors'])} cell(s) could not be read "
              f"from the artifacts; refusing to render them as null.")
        return 1
    for key, ok, evidence, static in model["limits"]:
        flag = "static" if static else ("OK" if ok else "FAILED")
        print(f"[limit] {key}: {flag} -- {evidence}")
        if not ok:
            rc = 1
    if rc:
        print("[FAIL] a limit EXPIRED (its guard no longer holds) -- rewrite the "
              "sentence before rendering; the card would otherwise claim something "
              "no longer true.")
        return 1

    text = render(model)

    if args.do_print:
        sys.stdout.write(text)

    if args.write:
        old = CARD.read_text(encoding="utf-8") if CARD.exists() else ""
        CARD.write_text(text, encoding="utf-8", newline="\n")
        print(f"[write] {reg.CARD_PATH} written ({len(text.splitlines())} lines)")
        for r in regressions(extract_cells(_norm(old)), extract_cells(text)):
            print(r)

    if args.lint_docs:
        lint_problems = lint_docs(quotable=quotable_facts(model))
        for p in lint_problems:
            print(p)
        if lint_problems:
            print(f"[FAIL] doc lint: {len(lint_problems)} quoted number(s) the card "
                  f"does not hold.")
            rc = 1
        else:
            print("[OK] doc lint: README and SSOT sections 2-3 quote only card numbers.")

    if args.check:
        if not CARD.exists():
            print(f"[FAIL] {reg.CARD_PATH} does not exist -- run --write")
            return 1
        # Read WITHOUT universal-newline translation (newline="") so the
        # CRLF normalisation in _norm is genuinely load-bearing: with a default
        # read, Python silently converts CRLF and a neutered _norm would still
        # compare equal (found by neutering _norm -- the control went green).
        committed = _norm(CARD.open(encoding="utf-8", newline="").read())
        fresh = _norm(text)
        if committed == fresh:
            print(f"[OK] {reg.CARD_PATH} matches a fresh render of the artifacts.")
        else:
            rc = 1
            print(f"[FAIL] {reg.CARD_PATH} is STALE (differs from a fresh render):")
            for line in difflib.unified_diff(
                    committed.splitlines(), fresh.splitlines(),
                    fromfile="committed eval/SCORECARD.md",
                    tofile="fresh render", lineterm="", n=1):
                print(line)
            print("-- cell-level summary --")
            for c in cell_summary(committed, fresh):
                print(c)
            print("Regenerate with: python tools/generate_scorecard.py --write")
    if not (args.write or args.check or args.lint_docs or args.do_print):
        ap.print_help()
    return rc


def _norm(text: str) -> str:
    """Normalise line endings and trailing whitespace so a CRLF conversion cannot
    mask a real difference (and an equal CRLF copy still compares equal)."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(line.rstrip() for line in text.split("\n"))


if __name__ == "__main__":
    raise SystemExit(main())
