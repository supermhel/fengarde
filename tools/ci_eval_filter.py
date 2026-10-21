#!/usr/bin/env python3
"""Decide whether a change must run the eval harness jobs in .github/workflows/ci.yml.

Reads changed file paths on stdin (newline-separated, or NUL-separated with ``-z``) and prints
``true`` when any of them can move an eval result, ``false`` otherwise. ci.yml's ``changes`` job
feeds it ``git diff --name-only --no-renames -z <base>...HEAD`` (both sides of a rename are listed,
paths are not quoted); main pushes and manual runs skip the filter and run the full gate.

SINGLE SOURCE OF TRUTH. The eval artifacts are stamped by eval/twin/fingerprint.py, so the paths that
can move a measured atom are exactly the files that fingerprint hashes. This module imports its glob
list and exclusions and only ADDS what the fingerprint deliberately does not hash but the gate still
reads: the whole eval/ tree (tests, oracles, baselines), the docs the scorecard lints
(eval/scorecard_registry.DOC_LINT_FILES), the gate script, the scorecard generator, the workflow and
its pinned requirements, and this filter with its test (a filter edit must be judged by the eval jobs).
tools/test_ci_eval_filter.py fails if the two diverge. Services are covered by the fingerprint's own
``services/**/*.py``: eval/twin/report.py loads services/ws3-indexer/evidence_package.py, so ws3 is
in; ws1/ws5/ws6/ws7/ws9 are covered conservatively because the fingerprint hashes them.

    git diff --name-only --no-renames -z origin/main...HEAD | python tools/ci_eval_filter.py -z
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "eval" / "twin"))
import fingerprint as _fp  # noqa: E402  (stdlib-only module: runs in the bare-python `changes` job)

#: Read by the gate but not hashed by the fingerprint. Prefix entries end with "/".
EXTRA_PATHS = (
    "eval/",
    "README.md", "SSOT.md",                       # eval/scorecard_registry.DOC_LINT_FILES (--lint-docs)
    "run_all_tests.sh", "tools/generate_scorecard.py",
    "contracts/detection-coverage.md",            # generated blocks read by technique_matrix G6 / evasion_cost check_doc
    ".github/workflows/ci.yml", ".github/ci-requirements/",
    "tools/ci_eval_filter.py", "tools/test_ci_eval_filter.py",
)


def _glob_regex(glob: str) -> "re.Pattern[str]":
    out, i = "", 0
    while i < len(glob):
        if glob.startswith("**/", i):
            out, i = out + "(?:.*/)?", i + 3
        elif glob[i] == "*":
            out, i = out + "[^/]*", i + 1
        else:
            out, i = out + re.escape(glob[i]), i + 1
    return re.compile(out + r"\Z")


_FINGERPRINT = [_glob_regex(g) for g in _fp._FINGERPRINT_GLOBS]


def fingerprinted(path: str) -> bool:
    """Would eval/twin/fingerprint.py hash this path? (Mirrors fingerprint_files() on a path string, so a
    deleted or renamed-away file still counts.)"""
    if not any(r.match(path) for r in _FINGERPRINT):
        return False
    name = path.rsplit("/", 1)[-1]
    if "__pycache__" in path.split("/") or name.startswith("test_") or path in _fp._EXCLUDED:
        return False
    return not (path.endswith((".pyc", ".json")) and not path.startswith("contracts/"))


def needs_eval(paths: "list[str]") -> bool:
    for raw in paths:
        p = raw.strip().replace("\\", "/")
        if not p:
            continue
        if any(p.startswith(e) if e.endswith("/") else p == e for e in EXTRA_PATHS) or fingerprinted(p):
            return True
    return False


def main(argv: "list[str]") -> int:
    data = sys.stdin.read()
    paths = data.split("\0") if "-z" in argv else data.splitlines()
    print("true" if needs_eval(paths) else "false")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
