"""Design-A (2026-07-29 audit): make_alert() must record MULTIPLE contributing
event ids for a stateful rule, not just the one event that crossed the
threshold.

Before this fix, `make_alert()` always set `event_ids` to a single-element
list (the triggering event's own ingest_id) even for a stateful rule whose
`rule_title` claims N events occurred (a `common_bruteforce` alert cites "10
failed logins" but referenced only 1 of the 10). Combined with alerts (365d)
outliving common-sector events (30d), that meant an alert older than 30 days
could never be substantiated even for the single id it did keep.

`Rule.contributing_event_ids()` and `window.py`'s `members()`/
`distinct_members()` already existed; this test proves the missing last step
-- `make_alert()` actually calling it -- is wired up and behaves correctly
for both stateful shapes (plain-count and distinct-count) and for
non-stateful rules (single id, unchanged).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
ROOT = SERVICES.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))
os.environ["BUS_BACKEND"] = "memory"

import main as ws4  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def failed_auth(ip, t, i):
    return {
        "class_uid": 3002, "category_uid": 3, "activity_id": 4, "type_uid": 300204,
        "severity_id": 4, "time": t, "status": "Failure",
        "src_endpoint": {"ip": ip}, "actor": {"user": {"name": "jdoe"}},
        "siem": {"sector": "common", "source_type": "active_directory", "ingest_id": f"auth-{i}"},
    }


def denied_conn(ip, port, t, i):
    return {
        "class_uid": 4001, "category_uid": 4, "activity_id": 6, "type_uid": 400106,
        "severity_id": 3, "time": t,
        "src_endpoint": {"ip": ip}, "dst_endpoint": {"port": port},
        "siem": {"sector": "common", "source_type": "cisco_asa", "ingest_id": f"scan-{i}"},
    }


def bank_priv_op(t=1750000000000):
    return {
        "class_uid": 6005, "category_uid": 6, "activity_id": 5, "type_uid": 600505,
        "severity_id": 4, "time": t, "status": "Success",
        "actor": {"user": {"name": "dba1"}},
        "dst_endpoint": {"hostname": "ora-core-01"},
        "siem": {"sector": "bank", "source_type": "oracle_db", "ingest_id": "bank-1"},
    }


def run():
    # --- plain-count stateful rule (common_bruteforce): 10 DISTINCT ingest_ids ---
    det = ws4.Detector()
    fired_event = None
    fired_rule = None
    for i in range(10):
        ev, matched, _ = det.process(failed_auth("203.0.113.5", 1750000000000 + i * 1000, i))
        for r in matched:
            if "brute-force" in r.title:
                fired_event, fired_rule = ev, r
    check(fired_rule is not None, "brute-force rule never fired -- can't test its event_ids")
    if fired_rule is not None:
        alert = ws4.make_alert(fired_event, fired_rule, fired_event["siem"]["score"])
        check(len(alert["event_ids"]) == 10,
              f"plain-count stateful alert should reference all 10 contributing "
              f"events, got {len(alert['event_ids'])}: {alert['event_ids']}")
        check(len(set(alert["event_ids"])) == 10,
              f"contributing ids must be distinct, got {alert['event_ids']}")
        check(all(i.startswith("auth-") for i in alert["event_ids"]),
              f"contributing ids must be the real ingest_ids, got {alert['event_ids']}")

    # --- distinct-count stateful rule (common_port_scan): 15 DISTINCT dst ports ---
    det2 = ws4.Detector()
    fired_event2 = None
    fired_rule2 = None
    for i in range(15):
        ev, matched, _ = det2.process(denied_conn("198.51.100.9", 10000 + i, 1750000000000 + i * 1000, i))
        for r in matched:
            if "Port scan" in r.title:
                fired_event2, fired_rule2 = ev, r
    check(fired_rule2 is not None, "port-scan rule never fired -- can't test its event_ids")
    if fired_rule2 is not None:
        alert2 = ws4.make_alert(fired_event2, fired_rule2, fired_event2["siem"]["score"])
        check(len(alert2["event_ids"]) == 15,
              f"distinct-count stateful alert should reference all 15 distinct "
              f"port values, got {len(alert2['event_ids'])}: {alert2['event_ids']}")
        check(set(alert2["event_ids"]) == {str(10000 + i) for i in range(15)},
              f"distinct-count contributing values must be the real dst ports, "
              f"got {alert2['event_ids']}")

    # --- non-stateful rule: single id, unchanged behavior ---
    det3 = ws4.Detector()
    ev3, matched3, _ = det3.process(bank_priv_op())
    bank_rule = next((r for r in matched3 if "Privileged database" in r.title), None)
    check(bank_rule is not None, "bank priv-esc rule never fired")
    if bank_rule is not None:
        alert3 = ws4.make_alert(ev3, bank_rule, ev3["siem"]["score"])
        check(alert3["event_ids"] == ["bank-1"],
              f"non-stateful alert must keep the single triggering id, got {alert3['event_ids']}")


def _run_truncation_cap():
    """Review finding (2026-08-27): _MAX_CONTRIBUTING_IDS capping used to
    embed a `"<truncated: N omitted>"` string INSIDE the `event_ids` list
    itself -- any consumer treating that field as "a list of ids" (a wire
    consumer, a join against raw events) would treat the sentinel as a real
    id. Fixed to report the omitted count as a separate `event_ids_omitted`
    field, `event_ids` staying a clean list of real ids only, capped at
    Rule._MAX_CONTRIBUTING_IDS. This proves both halves: the cap still
    binds, and the count is reported OUT of band, not embedded in-band.
    """
    from engine import Rule as _Rule  # noqa: E402 - local import, matches module layout

    det = ws4.Detector()
    fired_event, fired_rule = None, None
    n = _Rule._MAX_CONTRIBUTING_IDS + 7  # a few more than the cap so it actually bites
    for i in range(n):
        ev, matched, _ = det.process(failed_auth("203.0.113.99", 1750000000000 + i * 1000, i))
        for r in matched:
            if "brute-force" in r.title:
                fired_event, fired_rule = ev, r
    check(fired_rule is not None, "brute-force rule never fired -- can't test truncation")
    if fired_rule is None:
        return
    alert = ws4.make_alert(fired_event, fired_rule, fired_event["siem"]["score"])
    cap = _Rule._MAX_CONTRIBUTING_IDS
    check(len(alert["event_ids"]) == cap,
          f"event_ids must be capped at {cap}, got {len(alert['event_ids'])}")
    check(all(i.startswith("auth-") for i in alert["event_ids"]),
          f"every entry in event_ids must be a real ingest_id, never a "
          f"truncation-marker string, got {alert['event_ids']}")
    check(alert.get("event_ids_omitted") == n - cap,
          f"event_ids_omitted must report the real omitted count "
          f"({n - cap}), got {alert.get('event_ids_omitted')!r}")

    # And the un-truncated case must NOT carry the field at all (omitted when
    # absent, same convention as `mitre`).
    det2 = ws4.Detector()
    fired_event2, fired_rule2 = None, None
    for i in range(3):
        ev, matched, _ = det2.process(failed_auth("203.0.113.100", 1750000000000 + i * 1000, i))
        for r in matched:
            if "brute-force" in r.title:
                fired_event2, fired_rule2 = ev, r
    if fired_rule2 is not None:
        alert2 = ws4.make_alert(fired_event2, fired_rule2, fired_event2["siem"]["score"])
        check("event_ids_omitted" not in alert2,
              "an un-truncated alert must not carry event_ids_omitted at all")


def main():
    run()
    _run_truncation_cap()
    if FAILS:
        print(f"[FAIL] Design-A event_ids wiring: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] Design-A: make_alert() records all contributing event ids for "
          "stateful rules (plain-count and distinct-count), single id for "
          "non-stateful rules")


if __name__ == "__main__":
    main()
