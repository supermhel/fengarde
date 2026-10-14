"""F2 (owner decision 2026-10-14): account group keys are the ADR-009 canonical actor.

A Windows account is case-insensitive at the source, so "Admin", "admin" and
"admin " are ONE principal. WS-4 used to key its windows on the raw string:
a burst split across two spellings put half the events in each window and
neither reached the threshold. Account group keys are now ``strip().casefold()``
(the canonical actor WS-8 already uses). Non-account group keys (addresses,
sessions, object names) are untouched, and DOMAIN\\ / UPN forms are NOT folded
(that would amend ADR-009 -- a registered residual in evasion_findings.yaml).

Run: python services/ws4-detection/test_group_canonical.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from engine import Rule  # noqa: E402

FAILS: list[str] = []
BASE = 1_751_500_000_000


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _rule(group_by: str, threshold: int = 10) -> Rule:
    return Rule({"id": "f2", "title": "t", "level": "high",
                 "detection": {"s": {"class_uid": 3002, "activity_id": 4}, "condition": "s"},
                 "siem": {"score_weight": 0, "window_seconds": 60, "threshold": threshold,
                          "group_by": group_by}})


def _fail(i: int, name: str, ip: str = "192.0.2.10") -> dict:
    return {"class_uid": 3002, "activity_id": 4, "time": BASE + i * 1_000,
            "actor": {"user": {"name": name}}, "src_endpoint": {"ip": ip},
            "siem": {"ingest_id": f"f2-{i}", "tenant": "acme"}}


def _burst(rule: Rule, names: list[str]) -> bool:
    fired = False
    for i, name in enumerate(names):
        fired = rule.evaluate(_fail(i, name))
    return fired


def run():
    # (1) one burst of 10 split over three spellings of ONE account fires
    spellings = ["Admin", "admin", "ADMIN ", " admin"] * 2 + ["Admin", "admin"]
    check(_burst(_rule("actor.user.name"), spellings),
          "10 failures for one account in 4 spellings must reach the 10-event threshold")
    # (2) control: 10 failures over two DIFFERENT accounts stays per account
    check(not _burst(_rule("actor.user.name"), ["admin", "admin2"] * 5),
          "control: two different accounts must not pool into one window")
    # (3) control: the residual is not folded -- DOMAIN\\name is another key
    check(not _burst(_rule("actor.user.name"), ["admin", "CORP\\admin"] * 5),
          "DOMAIN\\ prefix is NOT stripped (ADR-009 unchanged; registered residual)")
    # (4) the other account field folds too
    target = _rule("unmapped.target_user.name", threshold=2)
    ev1, ev2 = _fail(0, "x"), _fail(1, "x")
    ev1["unmapped"] = {"target_user": {"name": "SvcBackup"}}
    ev2["unmapped"] = {"target_user": {"name": "svcbackup "}}
    target.evaluate(ev1)
    check(target.evaluate(ev2), "unmapped.target_user.name keys are canonical as well")
    # (5) one alert id for one principal (alert_key uses the same canonical key)
    r = _rule("actor.user.name")
    check(r.alert_key(_fail(0, "Admin")) == r.alert_key(_fail(0, "admin ")),
          "alert_key must not split one principal into two alert ids")
    # (6) a NON-account group key is still the raw string
    ip_rule = _rule("src_endpoint.hostname", threshold=2)
    a, b = _fail(0, "u"), _fail(1, "u")
    a["src_endpoint"]["hostname"] = "WKS-01"
    b["src_endpoint"]["hostname"] = "wks-01"
    ip_rule.evaluate(a)
    check(not ip_rule.evaluate(b), "non-account group keys are not case-folded")


def main():
    run()
    if FAILS:
        print(f"[FAIL] group canonicalisation: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] F2: account group keys are strip+casefold (ADR-009), other keys raw, DOMAIN\\ not folded")


if __name__ == "__main__":
    main()
