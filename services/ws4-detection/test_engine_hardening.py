"""P0 detection-engine hardening regression tests.

Covers the bugs found in the v0.4 deep audit:
  P0.1 - stateful rules must fail closed on non-numeric / NaN / far-future event
         time (poison-pill + window-poisoning), never raise, never fire.
  P0.8 - non-stateful alerts without an ingest_id must not all collapse onto one
         shared alert id; distinct events get distinct ids, and the id is stable
         across calls (deterministic under redelivery).

Zero infra. Run: C:/Python313/python.exe services/ws4-detection/test_engine_hardening.py
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from engine import Rule  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _bruteforce_rule() -> Rule:
    return Rule({
        "id": "bf", "title": "brute-force", "level": "high",
        "detection": {"failed": {"class_uid": 3002, "activity_id": 4},
                      "condition": "failed"},
        "siem": {"score_weight": 70, "window_seconds": 60, "threshold": 2,
                 "group_by": "src_endpoint.ip"},
    })


def _match(t):
    return {"time": t, "class_uid": 3002, "activity_id": 4,
            "src_endpoint": {"ip": "203.0.113.5"},
            "siem": {"ingest_id": f"i-{t}"}}


def run():
    now_ms = int(time.time() * 1000)

    # --- P0.1: non-numeric / NaN / inf time -> fail closed, never raise ---
    for bad in ("abc", None, float("nan"), float("inf"), [], {}, True):
        r = _bruteforce_rule()
        ev = {"time": bad, "class_uid": 3002, "activity_id": 4,
              "src_endpoint": {"ip": "1.2.3.4"}, "siem": {"ingest_id": "x"}}
        try:
            fired = r.evaluate(ev)
        except Exception as exc:  # noqa: BLE001
            FAILS.append(f"P0.1: time={bad!r} raised {type(exc).__name__} (must fail closed)")
            continue
        check(fired is False, f"P0.1: time={bad!r} must not fire (got {fired})")

    # --- P0.1: a far-future event must not count toward / poison the window ---
    r = _bruteforce_rule()
    future = now_ms + 10 * 365 * 24 * 3600 * 1000  # ~10 years ahead
    check(r.evaluate(_match(future)) is False,
          "P0.1: far-future event must not drive the window (fail closed)")
    # ...and it must not have polluted the counter: two real events still fire.
    check(r.evaluate(_match(now_ms - 2000)) is False, "P0.1: 1st real event below threshold")
    check(r.evaluate(_match(now_ms - 1000)) is True,
          "P0.1: 2nd real event fires (future event did not poison the window)")

    # --- P0.1: time=0 is numeric, must not crash (may or may not fire) ---
    r0 = _bruteforce_rule()
    try:
        r0.evaluate({"time": 0, "class_uid": 3002, "activity_id": 4,
                     "src_endpoint": {"ip": "9.9.9.9"}, "siem": {"ingest_id": "z"}})
    except Exception as exc:  # noqa: BLE001
        FAILS.append(f"P0.1: time=0 raised {type(exc).__name__} (must not crash)")

    # --- P0.8: non-stateful alerts without ingest_id get distinct, stable ids ---
    one = Rule({"id": "x", "title": "t", "level": "high",
                "detection": {"s": {"class_uid": 1}, "condition": "s"},
                "siem": {"score_weight": 80}})
    a = {"class_uid": 1, "src_endpoint": {"ip": "10.0.0.1"}}
    b = {"class_uid": 1, "src_endpoint": {"ip": "10.0.0.2"}}
    check(one.alert_key(a) == one.alert_key(a),
          "P0.8: same no-ingest event -> same id (deterministic)")
    check(one.alert_key(a) != one.alert_key(b),
          "P0.8: different no-ingest events -> different ids (no shared-bucket collapse)")
    check(one.alert_key(a).startswith("x:default:sha:"),
          "P0.8: no-ingest fallback uses a content hash, not a shared constant "
          "(P1-1: and is tenant-namespaced, default tenant here)")
    # ingest_id still preferred when present
    check(one.alert_key({"siem": {"ingest_id": "abc"}}) == "x:default:abc",
          "P0.8: ingest_id still preferred over the hash fallback "
          "(P1-1: tenant-namespaced, default tenant here)")


def main():
    run()
    if FAILS:
        print(f"[FAIL] engine hardening: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] engine hardening (P0.1 time guard, P0.8 alert-id) PASS")


if __name__ == "__main__":
    main()
