"""rule_cascade: generators run in order (floor only for a stateful rule, never --allow-lower), the cheap gates
map to TODO/DONE/CHECK items, and nothing is edited by the tool itself. Gate scripts are faked; the real ones
are covered by their own tests."""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rule_cascade as RC

STATEFUL = "title: t\nid: 11111111-2222-3333-4444-555555555555\nsiem:\n  window_seconds: 60\n  threshold: 5\n"
STATELESS = "title: t\nid: 66666666-2222-3333-4444-555555555555\nsiem:\n  score_weight: 50\n"
assert RC.is_stateful({"siem": {"window_seconds": 60, "threshold": 5}})
assert not RC.is_stateful({"siem": {"score_weight": 50}}) and not RC.is_stateful({})
assert RC.failing_lines("ok\n[FAIL] a rule_x is dormant\n[FAIL] other") == ["[FAIL] a rule_x is dormant", "[FAIL] other"]
assert RC.failing_lines("[FAIL] other\n[FAIL] rule_x dormant", "rule_x") == ["[FAIL] rule_x dormant"], "prefers its own rule"


def tree(root: Path, rule: str, text: str, coverage: str = "", extra: dict | None = None) -> None:
    (root / "contracts/rules").mkdir(parents=True)
    (root / f"contracts/rules/{rule}.yml").write_text(text)
    (root / "contracts/detection-coverage.md").write_text(coverage)
    adv = root / "eval/adversarial"
    adv.mkdir(parents=True)
    for name in ("technique_waivers.yaml", "evasion_findings.yaml", "rule_probes.py"):
        (adv / name).write_text("")
    for rel, body in (extra or {}).items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(body)


def run_cascade(rule: str, text: str, results: dict, **kw):
    calls: list[list[str]] = []
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        tree(root, rule, text, coverage=kw.pop("coverage", ""), extra=kw.pop("extra", None))
        before = {p: p.read_text() for p in root.rglob("*") if p.is_file()}
        old_root, old_run = RC.ROOT, RC.run
        RC.ROOT = root

        def fake(cmd, timeout=0):
            calls.append(cmd)
            key = next((k for k in results if k in " ".join(cmd)), None)
            return results.get(key, (0, "")) if key else (0, "")
        RC.run = fake
        try:
            reps = RC.cascade([f"contracts/rules/{rule}.yml"], "origin/main", kw.get("generate", True),
                              kw.get("floor", True), False)
        finally:
            RC.ROOT, RC.run = old_root, old_run
        assert before == {p: p.read_text() for p in root.rglob("*") if p.is_file()}, "the tool must not edit files itself"
    return reps, calls


def status(rep, needle):
    return next(i.status for i in rep.items if needle in i.what)


# stateful rule, producer gate red, no coverage row -> TODOs, floor generator runs without --allow-lower
reps, calls = run_cascade("win_new", STATEFUL, {"check_rule_producers": (1, "[FAIL] win_new is dormant\n")})
flat = [" ".join(c) for c in calls]
assert any("technique_matrix.py --write-doc" in c for c in flat), flat
assert any("evasion_cost.py --seed 7 --write-doc" in c for c in flat), flat
assert any("--update-floor" in c for c in flat) and not any("--allow-lower" in c for c in flat), flat
assert flat.index(next(c for c in flat if "--write-doc" in c)) < flat.index(next(c for c in flat if "validate_rules" in c)), \
    "generators run before the gates that read their output"
rep = reps[0]
assert rep.stateful
assert status(rep, "producer fixture") == "TODO" and "win_new is dormant" in next(
    i.how for i in rep.items if "producer fixture" in i.what)
assert status(rep, "detection-coverage row") == "TODO"
assert status(rep, "rule_probes") == "CHECK" and status(rep, "F4 listing") == "CHECK"
assert status(rep, "rule counts") == "CHECK" and status(rep, "oracle pins") == "CHECK"
assert RC.render(reps) == 1, "an open TODO is a non-zero exit"

# stateless rule: no floor generator; everything green + a coverage row present -> exit 0
reps, calls = run_cascade("win_ok", STATELESS, {}, coverage="| win_ok | row |\n")
assert not any("--update-floor" in " ".join(c) for c in calls), "floor only for stateful rules"
assert not any(i.what.startswith("rule_probes") for i in reps[0].items), "probe template is a stateful-rule item"
assert status(reps[0], "detection-coverage row") == "DONE" and status(reps[0], "producer fixture") == "DONE"
assert RC.render(reps) == 0

# --no-generate / --no-floor
_, calls = run_cascade("win_new", STATEFUL, {}, generate=False)
assert not any("--write-doc" in " ".join(c) or "--update-floor" in " ".join(c) for c in calls)
_, calls = run_cascade("win_new", STATEFUL, {}, floor=False)
assert any("--write-doc" in " ".join(c) for c in calls) and not any("--update-floor" in " ".join(c) for c in calls)

# technique-matrix gate red -> the waiver/storyline decision is surfaced as a TODO, never written
reps, _ = run_cascade("win_new", STATELESS, {"technique_matrix.py": (1, "[FAIL] G2 win_new not exercised\n")})
assert status(reps[0], "storyline or dated waiver") == "TODO"

# rule-count scan reports a differing number with file:line, and stays quiet on the true total
with tempfile.TemporaryDirectory() as d:
    root = Path(d)
    tree(root, "a", STATELESS,
         extra={"README.md": "x\n| **Detection rules (46)** | ok |\n", "docs/index.html": "<h2>47 rules, all listed.</h2>"})
    old = RC.ROOT
    RC.ROOT = root
    try:
        assert RC.count_mentions(1) == ["README.md:2: says 46", "docs/index.html:1: says 47"], RC.count_mentions(1)
        assert RC.count_mentions(46) == ["docs/index.html:1: says 47"]
    finally:
        RC.ROOT = old
print("[OK] rule_cascade: generators ordered, floor only for stateful (never --allow-lower), "
      "gates -> TODO/CHECK, no file edited by the tool")
