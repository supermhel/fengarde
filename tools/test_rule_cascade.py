"""rule_cascade: generators run in order (floor only for a stateful rule, never --allow-lower), the cheap gates
map to TODO/DONE/CHECK items, and nothing is edited by the tool itself. Gate scripts are faked; the real ones
are covered by their own tests."""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rule_cascade as RC

FLOOR0 = "rule_sets:\n  old_rule:\n    fingerprint: aaa\n    fields: {extra_seconds: {value: 70}}\n"
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
    (adv / "evasion_floor.yaml").write_text(FLOOR0)
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


def rr(reps):
    return next(r for r in reps if r.rule != "(generators)")


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
rep = rr(reps)
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
assert not any(i.what.startswith("rule_probes") for i in rr(reps).items), "probe template is a stateful-rule item"
assert status(rr(reps), "detection-coverage row") == "DONE" and status(rr(reps), "producer fixture") == "DONE"
assert RC.render(reps) == 0

# --no-generate / --no-floor
_, calls = run_cascade("win_new", STATEFUL, {}, generate=False)
assert not any("--write-doc" in " ".join(c) or "--update-floor" in " ".join(c) for c in calls)
_, calls = run_cascade("win_new", STATEFUL, {}, floor=False)
assert any("--write-doc" in " ".join(c) for c in calls) and not any("--update-floor" in " ".join(c) for c in calls)

# technique-matrix gate red -> the waiver/storyline decision is surfaced as a TODO, never written
reps, _ = run_cascade("win_new", STATELESS, {"technique_matrix.py": (1, "[FAIL] G2 win_new not exercised\n")})
assert status(rr(reps), "storyline or dated waiver") == "TODO"

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
# ---- hardening (post-merge review of PR #118) -------------------------------------------------------------
import subprocess  # noqa: E402

# floor guard: only ADDED keys may reach the real floor. The scratch copy is really written by the fake generator,
# exactly like evasion_cost --update-floor writes its --floor file, including the fingerprint re-baseline side effect.
def floor_run(mutate):
    def fake(cmd, timeout=0):
        if "--update-floor" in cmd:
            f = Path(cmd[cmd.index("--floor") + 1])
            f.write_text(mutate(f.read_text()))
        return 0, ""
    return fake


def guarded(mutate):
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        tree(root, "win_new", STATEFUL)
        old_root, old_run = RC.ROOT, RC.run
        RC.ROOT, RC.run = root, floor_run(mutate)
        try:
            rc, msg = RC.guarded_floor_update()
        finally:
            RC.ROOT, RC.run = old_root, old_run
        return rc, msg, (root / RC.FLOOR).read_text()


add_only = lambda s: s + "  win_new:\n    fingerprint: bbb\n    fields: {extra_seconds: {value: 5}}\n"   # noqa: E731
rc, msg, real = guarded(add_only)
assert rc == 0 and "win_new" in real and "old_rule" in real and "win_new" in msg, (rc, msg, real)
rebaseline = lambda s: add_only(s).replace("fingerprint: aaa", "fingerprint: CHANGED")                    # noqa: E731
rc, msg, real = guarded(rebaseline)
assert rc == 1 and "REFUSED" in msg and "old_rule" in msg, msg
assert real == FLOOR0, "a refused update must leave the real floor byte-identical (no fingerprint re-baseline of other rule-sets)"
rc, msg, real = guarded(lambda s: s.replace("value: 70", "value: 60"))
assert rc == 1 and real == FLOOR0, "a lowered existing value is refused too"
rc, msg, real = guarded(lambda s: s + "removed: [x]\n")
assert rc == 1 and real == FLOOR0, "a change outside rule_sets is refused"
assert RC.floor_change({"rule_sets": {"a": 1}}, {"rule_sets": {"a": 1, "b": 2}}) == (["b"], [])

# generator / floor-update failures are TODOs that make the tool exit non-zero
reps, _ = run_cascade("win_ok", STATELESS, {"--write-doc": (3, "boom\nlast line\n")}, coverage="| win_ok |\n")
gen = reps[0]
assert gen.rule == "(generators)" and any(i.status == "TODO" and "failed (rc 3)" in i.what and "last line" in i.how for i in gen.items)
assert RC.render(reps) == 1, "a failed generator must not exit 0"
reps, _ = run_cascade("win_new", STATEFUL, {"--update-floor": (1, "[REFUSED] x\n")}, coverage="| win_new |\n")
assert any("update-floor" in i.what and i.status == "TODO" for i in reps[0].items) and RC.render(reps) == 1

# stale scenario_matrix artifact: re-run with --recompute instead of blaming the owner
with tempfile.TemporaryDirectory() as d:
    root = Path(d)
    tree(root, "win_ok", STATELESS, coverage="| win_ok |\n")
    art = root / "eval/adversarial/out/scenario_matrix.latest.json"
    art.parent.mkdir(parents=True)
    art.write_text("{}")
    seen: list[list[str]] = []

    def fake_stale(cmd, timeout=0):
        seen.append(cmd)
        if "technique_matrix.py" in " ".join(cmd) and "--write-doc" not in cmd:
            return (0, "") if "--recompute" in cmd else (1, "[FAIL] G1 artefact inputs_fingerprint differs from the live tree")
        return 0, ""
    old_root, old_run = RC.ROOT, RC.run
    RC.ROOT, RC.run = root, fake_stale
    try:
        reps = RC.cascade(["contracts/rules/win_ok.yml"], "origin/main", False, False, False)
    finally:
        RC.ROOT, RC.run = old_root, old_run
    tm = [c for c in seen if "technique_matrix.py" in " ".join(c)]
    assert len(tm) == 2 and "--recompute" not in tm[0] and "--recompute" in tm[1], tm
    assert status(rr(reps), "storyline coverage") == "DONE"

# run(): a timeout or an unstartable interpreter is a failing (rc, message), never an exception
rc, out = RC.run(["-c", "import time; time.sleep(30)"], timeout=1)
assert rc == 124 and "timed out" in out
rc, out = RC.run(["-c", "raise SystemExit(5)"])
assert rc == 5
old_exe, sys.executable = sys.executable, str(Path(tempfile.gettempdir()) / "no-such-python.exe")
try:
    rc, out = RC.run(["-c", "pass"])
finally:
    sys.executable = old_exe
assert rc == 127 and "could not start" in out

# new_rule_files on a real git repo: added, renamed-in (names with spaces), uncommitted; an edit is not new
def g(root, *a):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *a], cwd=root, check=True, capture_output=True)


with tempfile.TemporaryDirectory() as d:
    root = Path(d)
    (root / "contracts/rules").mkdir(parents=True)
    for n in ("edited", "movedfrom"):
        (root / f"contracts/rules/{n}.yml").write_text(n + "\n" * 5)
    g(root, "init", "-b", "main"), g(root, "add", "-A"), g(root, "commit", "-m", "base")
    g(root, "checkout", "-b", "feature")
    (root / "contracts/rules/added.yml").write_text("a")
    (root / "contracts/rules/edited.yml").write_text("changed\n" * 5)
    g(root, "mv", "contracts/rules/movedfrom.yml", "contracts/rules/moved to.yml")
    g(root, "add", "-A"), g(root, "commit", "-m", "work")
    (root / "contracts/rules/uncommitted.yml").write_text("u")
    old = RC.ROOT
    RC.ROOT = root
    try:
        assert RC.new_rule_files("main") == ["contracts/rules/added.yml", "contracts/rules/moved to.yml",
                                             "contracts/rules/uncommitted.yml"], RC.new_rule_files("main")
    finally:
        RC.ROOT = old

print("[OK] rule_cascade: generators ordered, floor only for stateful (never --allow-lower), "
      "gates -> TODO/CHECK, no file edited by the tool")
