#!/usr/bin/env python3
"""Decide whether a change must run the eval harness jobs in .github/workflows/ci.yml.

Reads changed file paths (one per line, repo-relative) on stdin and prints ``true`` when any of
them can move an eval result, ``false`` otherwise. ci.yml's ``changes`` job calls this on
``git diff --name-only <base>...HEAD``; main pushes, manual runs and any diff failure skip the
filter and run everything.

The list is wider than rules + parsers + detection on purpose: the eval harness replays the REAL
WS-2 -> WS-4 -> WS-8 path, and eval/twin/fingerprint.py hashes contracts/ and services/ into every
artifact, so the WS-8 correlator, services/shared and the contracts move eval numbers too. A
narrower filter would let such a PR merge with a red eval that only the post-merge full gate sees.

    git diff --name-only origin/main...HEAD | python tools/ci_eval_filter.py
"""
import re
import sys

EVAL_PATHS = re.compile(
    r"^(?:"
    r"contracts/|"
    r"services/ws2-normalization/|"
    r"services/ws4-detection/|"
    r"services/ws8-correlation/|"
    r"services/shared/|"
    r"eval/|"
    r"tools/generate_scorecard\.py$|"
    r"tools/check_rule_producers\.py$|"
    r"tools/detection_quality_eval\.py$|"
    r"run_all_tests\.sh$|"
    r"\.github/workflows/ci\.yml$|"
    r"\.github/ci-requirements/"
    r")"
)


def needs_eval(paths: list[str]) -> bool:
    return any(EVAL_PATHS.match(p.strip().replace("\\", "/")) for p in paths if p.strip())


if __name__ == "__main__":
    print("true" if needs_eval(sys.stdin.read().splitlines()) else "false")
