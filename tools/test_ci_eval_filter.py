import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ci_eval_filter import needs_eval

# Every path class the task names must trigger the eval jobs.
for p in ("contracts/rules/new_rule.yml", "services/ws2-normalization/parsers/sysmon.py",
          "services/ws4-detection/engine.py", "eval/twin/baseline_scenarios.json",
          "eval/adversarial/technique_waivers.yaml", "tools/generate_scorecard.py", "run_all_tests.sh",
          # consumers of the same artifacts / fingerprint
          "services/ws8-correlation/correlator.py", "services/shared/ocsf.py", "contracts/bus-topics.md",
          ".github/workflows/ci.yml"):
    assert needs_eval([p]), f"{p} must run the eval jobs"
# Paths that cannot move an eval result skip them.
for p in ("README.md", "CHANGELOG.md", "docs/adding-a-parser.md", "services/ws3-indexer/triage_api.py",
          "services/ws7-dashboard/app/src/App.tsx", "tools/rule_cascade.py", ".github/workflows/dco.yml"):
    assert not needs_eval([p]), f"{p} must not run the eval jobs"
assert needs_eval(["README.md", "eval/twin/report.py"]), "one eval path in a mixed diff is enough"
assert needs_eval(["eval" + chr(92) + "twin" + chr(92) + "report.py"]), "windows separators"
assert not needs_eval([]) and not needs_eval(["", "  "]), "empty diff"
print("[OK] ci_eval_filter: eval-affecting paths trigger the eval jobs, docs-only changes do not")
