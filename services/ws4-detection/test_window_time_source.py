"""Q12 (2026-10-20) + F4 clamp (2026-10-21): FENGARDE_WINDOW_TIME_SOURCE selects the clock that
drives stateful windows. DEFAULT ``clamp``: the record time, unless it is more than
min(FENGARDE_WINDOW_MAX_SKEW_SECONDS (600), window/2) away from the WS-1 receipt time (siem.received_ms), in which
case the receipt time is used and siem.time_clamped is set. ``event`` = the old behaviour (the
explicit replay/backfill opt-out); ``ingest`` = always receipt time.

Attack: 12 failed SSH logins in ~1.2 s of real time, each record stamped 10 s apart
(record time spans 120 s > the 60 s window of the 10-failure brute-force rule).

Run: python services/ws4-detection/test_window_time_source.py
"""
from __future__ import annotations

import copy
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "services"))
sys.path.insert(0, str(ROOT / "services" / "ws2-normalization"))

import engine  # noqa: E402
from engine import load_rules  # noqa: E402
from parsers import _REGISTRY  # noqa: E402
from enrichment import enrich  # noqa: E402

BRUTE = "6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c01"  # 10 failures / 60 s, by source
FAILS: list = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _event(i: int, record_ms: int, received_ms: int, tag: str) -> dict:
    line = f"Jun 10 13:55:00 db01 sshd[{3000 + i}]: Failed password for deploy from 203.0.113.77 port {52000 + i} ssh2"
    meta = {"received_at": received_ms, "ingest_id": f"{tag}-{i}", "tenant_id": "acme"}
    ev = enrich(_REGISTRY["linux_ssh"].parse({"source_type": "linux_ssh", "raw": line, "meta": meta}))
    ev = copy.deepcopy(ev)
    ev["time"] = record_ms
    ev.setdefault("siem", {})["received_ms"] = received_ms
    return ev


def _fires(source: str, tag: str, spacing_ms: int = 10_000) -> bool:
    os.environ["FENGARDE_WINDOW_TIME_SOURCE"] = source
    rule = next(r for r in load_rules(ROOT / "contracts" / "rules") if r.id == BRUTE)
    wall = int(time.time() * 1000) - 5_000
    fired = False
    for i in range(12):
        fired |= bool(rule.evaluate(_event(i, wall - 11 * spacing_ms + i * spacing_ms, wall + i * 100,
                                           f"{tag}-{source}")))
    return fired


def _drive(record_ms: int, received_ms, periodicity: bool = False, window_ms=None):
    ev = {"time": record_ms, "siem": {} if received_ms is None else {"received_ms": received_ms}}
    return ev, engine._window_time_of(ev, periodicity, window_ms)


def run():
    for k in ("FENGARDE_WINDOW_TIME_SOURCE", "FENGARDE_WINDOW_MAX_SKEW_SECONDS"):
        os.environ.pop(k, None)
    # --- end to end on the 60 s / 10-failure brute-force rule (effective skew = 30 s) ---
    # the author stretches the burst over 110 s of RECORD time, receipt time stays true
    check(not _fires("event", "t1"), "opt-out event: the spread-out burst evades (F4 control)")
    check(_fires("clamp", "t2"), "default clamp: the forged spread is clamped, the burst is counted in one window")
    check(_fires("ingest", "t3"), "ingest: receipt time drives the window -> fires")
    os.environ.pop("FENGARDE_WINDOW_TIME_SOURCE", None)
    check(_fires("bogus", "t4"), "unknown mode falls back to the safe default (clamp), not to event")
    check(_fires("clamp", "t5", 600_000), "far-forged (10 min apart) is clamped too")
    # forgery INSIDE the old 600 s global skew but beyond window/2 (the case the plain 600 s clamp missed)
    check(_fires("clamp", "t6", 20_000), "forgery that fits the old global skew but not window/2 is still caught")

    R = 2_000_000_000_000
    # --- boundaries per window size: effective skew = min(600 s, window/2) ---
    os.environ.pop("FENGARDE_WINDOW_TIME_SOURCE", None)
    for window_s, eff_s in ((60, 30), (300, 150), (3600, 600)):
        w, eff = window_s * 1000, eff_s * 1000
        check(engine.effective_skew_ms(w) == eff, f"window {window_s}s: effective skew is {eff_s}s")
        for sign, side in ((-1, "record behind receipt"), (1, "record ahead of receipt")):
            ev, t = _drive(R + sign * eff, R, window_ms=w)
            check(t == R + sign * eff and "time_clamped" not in ev["siem"],
                  f"window {window_s}s, exactly at the skew, {side}: trusted, no flag")
            ev, t = _drive(R + sign * (eff + 1), R, window_ms=w)
            check(t == R and ev["siem"].get("time_clamped") is True,
                  f"window {window_s}s, 1 ms over, {side}: receipt time + flag")
        # honest shipper delay well inside the limit is counted on its record time
        lag = eff // 2
        ev, t = _drive(R - lag, R, window_ms=w)
        check(t == R - lag and "time_clamped" not in ev["siem"], f"window {window_s}s: legit {lag // 1000}s shipper lag unchanged")
        # a burst forged anywhere inside the allowed band spans at most one window
        lo, hi = R - eff, R + eff
        check(hi - lo <= w, f"window {window_s}s: the trusted band ({hi - lo} ms) fits in one window ({w} ms)")
    # replay opt-out and periodicity are never clamped
    ev, t = _drive(R - 3_600_000, R, window_ms=60_000, periodicity=True)
    check(t == R - 3_600_000 and "time_clamped" not in ev["siem"], "periodicity rules always use record time")
    os.environ["FENGARDE_WINDOW_TIME_SOURCE"] = "event"
    ev, t = _drive(R - 3_600_000, R, window_ms=60_000)
    check(t == R - 3_600_000 and "time_clamped" not in ev["siem"], "opt-out event: historical replay untouched at any window")
    os.environ.pop("FENGARDE_WINDOW_TIME_SOURCE", None)

    # --- no window given (direct helper use): global skew only ---
    ev, t = _drive(R - 600_000, R)
    check(t == R - 600_000 and "time_clamped" not in ev["siem"], "no window: exactly at the global skew: trusted")
    ev, t = _drive(R - 600_001, R)
    check(t == R and ev["siem"].get("time_clamped") is True, "no window: 1 ms over the global skew: clamped")
    ev, t = _drive(R - 3_600_000, None)
    check(t == R - 3_600_000 and "time_clamped" not in ev["siem"], "missing received_ms: record time, no flag, no raise")
    ev = {"time": R - 3_600_000, "siem": {"received_ms": True}}
    check(engine._window_time_of(ev, False) == R - 3_600_000, "bool received_ms is not a clock")
    ev = {"time": R - 3_600_000}
    check(engine._window_time_of(ev, False) == R - 3_600_000, "no siem block at all: record time")
    before = engine.CLAMP_STATS["time_clamped"]
    ev = {"time": R - 3_600_000, "siem": {"received_ms": R}}
    engine._window_time_of(ev, False)
    engine._window_time_of(ev, False)
    check(engine.CLAMP_STATS["time_clamped"] == before + 1, "clamp metric counts an event once")

    # --- alert id follows the effective window clock (live-proof finding 2026-10-22) ---
    # A forged burst spread over more than one 300 s alert bucket, redelivered byte-identically, used to fire on an
    # EARLIER event the second time (the window already held the hosts) and mint a second alert id from that event's
    # forged record time. The bucket now follows the clamped clock, so every firing lands on one id.
    lat = next(r for r in load_rules(ROOT / "contracts" / "rules") if r.id == "2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061")
    wall = int(time.time() * 1000) - 5_000
    wall -= wall % 300_000                       # start of an alert bucket, so honest times sit inside ONE bucket

    def _logon(i, rnd):
        return {"class_uid": 3002, "activity_id": 1, "status": "Success", "time": wall + 150_000 - (4 - i) * 100_000,
                "actor": {"user": {"name": "mallory"}}, "dst_endpoint": {"hostname": f"fs0{i}"},
                "siem": {"ingest_id": f"idem-{i}", "tenant": "acme", "received_ms": wall + 150_000 + i * 100}}
    keys = set()
    for rnd in (1, 2):                           # round 2 = byte-identical redelivery into the SAME window state
        for i in range(5):
            ev = _logon(i, rnd)
            if lat.evaluate(ev):
                keys.add(lat.alert_key(ev))
    check(len(keys) == 1, f"redelivered forged burst must keep ONE alert id under the default clamp, got {sorted(keys)}")
    os.environ["FENGARDE_WINDOW_TIME_SOURCE"] = "event"
    try:
        k2 = {lat.alert_key(_logon(i, 1)) for i in range(5)}
    finally:
        os.environ.pop("FENGARDE_WINDOW_TIME_SOURCE", None)
    check(len(k2) == 2, f"event mode keeps the record-time bucket: 400 s spread = two 300 s buckets, got {len(k2)}")

    # --- configuration ---
    os.environ["FENGARDE_WINDOW_MAX_SKEW_SECONDS"] = "10"
    check(engine.effective_skew_ms(3_600_000) == 10_000, "env skew caps a long window")
    check(engine.effective_skew_ms(8_000) == 4_000, "a short window caps the env skew (window/2)")
    for bad in ("abc", "-5", "nan", "inf"):
        os.environ["FENGARDE_WINDOW_MAX_SKEW_SECONDS"] = bad
        check(engine.window_skew_ms() == 600_000, f"invalid skew {bad!r} falls back to 600 s")
    os.environ.pop("FENGARDE_WINDOW_MAX_SKEW_SECONDS", None)

    # no received_ms -> falls back to record time, never crashes
    os.environ["FENGARDE_WINDOW_TIME_SOURCE"] = "ingest"
    rule = next(r for r in load_rules(ROOT / "contracts" / "rules") if r.id == BRUTE)
    ev = _event(99, int(time.time() * 1000) - 10_000, int(time.time() * 1000), "t7")
    ev["siem"].pop("received_ms", None)
    try:
        rule.evaluate(ev)
    except Exception as exc:  # pragma: no cover
        check(False, f"missing received_ms must fall back, not raise: {exc!r}")
    os.environ.pop("FENGARDE_WINDOW_TIME_SOURCE", None)


if __name__ == "__main__":
    run()
    if FAILS:
        for f in FAILS:
            print("[FAIL]", f)
        sys.exit(1)
    print("[OK] WS-4 window time source: default clamp defeats a far-forged record clock "
          "(per-window boundaries tested); event opt-out unchanged; ingest; missing receipt time falls back")
