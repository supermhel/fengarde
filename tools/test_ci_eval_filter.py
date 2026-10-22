import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "eval"))
sys.path.insert(0, str(ROOT / "eval" / "twin"))
import ci_eval_filter as F  # noqa: E402
import fingerprint as FP  # noqa: E402
import scorecard_registry as SR  # noqa: E402

# 1. Single source of truth: EVERY file the eval fingerprint hashes today must trigger the eval jobs, so a
#    new fingerprint glob cannot silently diverge from the filter.
hashed = [p.relative_to(ROOT).as_posix() for p in FP.fingerprint_files(ROOT)]
assert hashed, "fingerprint hashes nothing?"
missed = [p for p in hashed if not F.needs_eval([p])]
assert not missed, f"fingerprinted files that do NOT trigger eval: {missed[:5]}"
# ... and the filter's mirror of fingerprint_files() agrees with the real thing on the real tree.
tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout.split()
assert sorted(p for p in tracked if F.fingerprinted(p) and (ROOT / p).is_file()) == sorted(hashed), \
    "fingerprinted() disagrees with eval/twin/fingerprint.fingerprint_files()"

# 2. Files the gate reads beyond the fingerprint.
for doc in SR.DOC_LINT_FILES:
    assert F.needs_eval([doc]), f"{doc} is linted by generate_scorecard --lint-docs: a docs-only PR must run eval-gates"
for p in ("eval/twin/baseline_scenarios.json", "eval/adversarial/technique_waivers.yaml", "tools/generate_scorecard.py",
          "run_all_tests.sh", ".github/workflows/ci.yml", ".github/ci-requirements/yaml.txt",
          "tools/ci_eval_filter.py", "tools/test_ci_eval_filter.py", "contracts/detection-coverage.md",
          "tools/validate_contract.py", "tools/validate_rules.py", "tools/check_rule_producers.py"):
    assert F.needs_eval([p]), f"{p} must run the eval jobs"
# 3. Services: the fingerprint hashes services/**/*.py, and report.py loads ws3's evidence_package.
for p in ("services/ws3-indexer/evidence_package.py", "services/ws3-indexer/triage_api.py", "services/ws8-correlation/correlator.py",
          "services/shared/ocsf.py", "services/ws2-normalization/parsers/sysmon.py", "services/ws5-ai/llm_adapter.py"):
    assert F.needs_eval([p]), f"{p} is hashed by the eval fingerprint and must run the eval jobs"
# 4. What cannot move an eval result skips them (tests, docs, console sources, the cascade helper).
for p in ("CHANGELOG.md", "CONTRIBUTING.md", "docs/adding-a-parser.md", "services/ws7-dashboard/app/src/App.tsx",
          "services/ws3-indexer/test_triage_api.py", "tools/rule_cascade.py", ".github/workflows/dco.yml"):
    assert not F.needs_eval([p]), f"{p} must not run the eval jobs"
assert F.needs_eval(["CHANGELOG.md", "eval/twin/report.py"]) and not F.needs_eval([]) and not F.needs_eval(["", " "])
assert F.needs_eval(["eval" + chr(92) + "twin" + chr(92) + "report.py"]), "windows separators"


# 5. CLI: NUL-separated input (git diff -z), both sides of a rename, paths with spaces/unicode.
def cli(data: str, *args: str) -> str:
    r = subprocess.run([sys.executable, str(ROOT / "tools" / "ci_eval_filter.py"), *args], input=data, capture_output=True,
                       text=True, cwd=ROOT)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


assert cli("docs/a.md\0contracts/rules/x.yml\0", "-z") == "true"          # a rename OUT of contracts/rules lists the old path
assert cli("docs/a b.md\0docs/ü.md\0", "-z") == "false"
assert cli("CHANGELOG.md\nREADME.md\n") == "true" and cli("CHANGELOG.md\n") == "false" and cli("") == "false"
print("[OK] ci_eval_filter: derived from eval/twin/fingerprint.py (every hashed file triggers), docs the scorecard lints trigger, "
      "tests/docs/console do not, -z + rename both sides handled")
