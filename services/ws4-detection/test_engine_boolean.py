"""Unit tests for the T4 boolean evaluator and T7 deterministic alert id.

Zero infra. Run: C:/Python313/python.exe services/ws4-detection/test_engine_boolean.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from engine import Rule, _parse_or  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def ev(values):
    """Evaluate a condition string against a dict of selection-name -> bool."""
    import re
    toks = re.findall(r"\(|\)|\band\b|\bor\b|\bnot\b|[\w.]+", values["__expr__"])
    val, end = _parse_or(toks, 0, values)
    return bool(val) and end == len(toks)


def truth(expr, **vals):
    vals = dict(vals)
    vals["__expr__"] = expr
    return ev(vals)


def run():
    # --- truth table: and / or / not / parens ---
    check(truth("a and b", a=True, b=True) is True, "a and b (TT)")
    check(truth("a and b", a=True, b=False) is False, "a and b (TF)")
    check(truth("a or b", a=False, b=True) is True, "a or b (FT)")
    check(truth("a or b", a=False, b=False) is False, "a or b (FF)")
    check(truth("not a", a=False) is True, "not a (F)")
    check(truth("not a", a=True) is False, "not a (T)")
    check(truth("a and not b", a=True, b=False) is True, "a and not b")
    check(truth("(a or b) and c", a=False, b=True, c=True) is True, "(a or b) and c")
    check(truth("(a or b) and c", a=False, b=True, c=False) is False, "(a or b) and c F")
    check(truth("a or b and c", a=False, b=True, c=False) is False, "and binds tighter than or")
    # unknown selection name -> False, never an error
    check(truth("a and missing", a=True) is False, "unknown name is False")

    # --- no-RCE: a malicious condition cannot execute code ---
    # Through the real Rule path. A condition referencing builtins must NOT run them;
    # the tokens are just unknown selection names -> False, no exception, no execution.
    sentinel = {"hit": False}
    import builtins
    _orig_import = builtins.__import__

    def _tripwire(name, *a, **k):
        if name == "os":
            sentinel["hit"] = True
        return _orig_import(name, *a, **k)

    builtins.__import__ = _tripwire
    try:
        malicious = Rule({
            "id": "m", "title": "malicious", "level": "high",
            "detection": {
                "sel": {"class_uid": 3002},
                # an old eval() would have tried to run this
                "condition": "__import__('os').system('echo pwned') or sel",
            },
            "siem": {"score_weight": 10},
        })
        result = malicious._eval_condition({"class_uid": 3002})
    finally:
        builtins.__import__ = _orig_import
    # The two properties that matter: (1) NO code executed (the import tripwire never
    # fired), and (2) the garbage condition FAILS CLOSED to False rather than raising
    # or running. An old eval() would have executed os.system; the evaluator just sees
    # unparseable tokens and returns False.
    check(sentinel["hit"] is False, "T4 RCE: malicious condition must NOT import os")
    check(result is False, "T4: malicious/unparseable condition fails closed to False")

    # --- no crash: deeply nested parens must not blow the stack ---
    # A contributor-supplied rule with thousands of nested parens would recurse deep
    # enough to raise RecursionError. That must be caught and fail closed to False,
    # not escape and poison-pill the consumer (message redelivered forever).
    deep = Rule({
        "id": "d", "title": "deep", "level": "high",
        "detection": {"sel": {"class_uid": 3002},
                      "condition": "(" * 20000 + "sel" + ")" * 20000},
        "siem": {"score_weight": 10},
    })
    try:
        deep_result = deep.evaluate({"class_uid": 3002})
    except RecursionError:
        deep_result = "RAISED"
    check(deep_result is False,
          "T4: deeply nested parens must fail closed to False, not raise RecursionError")

    # --- T7: deterministic alert id ---
    bf = Rule({
        "id": "bf", "title": "brute-force", "level": "high",
        "detection": {"failed": {"class_uid": 3002, "activity_id": 4}, "condition": "failed"},
        "siem": {"score_weight": 70, "window_seconds": 60, "threshold": 10,
                 "group_by": "src_endpoint.ip"},
    })
    e1 = {"time": 1750000009000, "src_endpoint": {"ip": "203.0.113.5"}}
    e2 = {"time": 1750000010000, "src_endpoint": {"ip": "203.0.113.5"}}  # same 60s bucket
    e3 = {"time": 1750000900000, "src_endpoint": {"ip": "203.0.113.5"}}  # later bucket
    e4 = {"time": 1750000009000, "src_endpoint": {"ip": "10.0.0.9"}}     # other IP

    check(bf.alert_key(e1) == bf.alert_key(e2), "T7: same group+window -> same id (idempotent)")
    check(bf.alert_key(e1) != bf.alert_key(e3), "T7: different window -> different id")
    check(bf.alert_key(e1) != bf.alert_key(e4), "T7: different group -> different id")

    # non-stateful rule keys on ingest_id
    one = Rule({"id": "x", "title": "t", "level": "high",
                "detection": {"s": {"class_uid": 1}, "condition": "s"},
                "siem": {"score_weight": 80}})
    check(one.alert_key({"siem": {"ingest_id": "abc"}}) == "x:default:abc",
          "T7: non-stateful keys on ingest_id (P1-1: tenant-namespaced, default tenant here)")


def main():
    run()
    if FAILS:
        print(f"[FAIL] engine boolean/id: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] engine boolean evaluator + deterministic alert id PASS")


if __name__ == "__main__":
    main()
