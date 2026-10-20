"""Q12 (owner decision 2026-10-20): FENGARDE_WINDOW_TIME_SOURCE=ingest drives stateful windows
from the WS-1 receipt time (siem.received_ms), so an attacker who controls the RECORD clock cannot
spread a burst out of its window. Default (event) keeps the old behaviour byte-for-byte.

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


def _fires(source: str, tag: str) -> bool:
    os.environ["FENGARDE_WINDOW_TIME_SOURCE"] = source
    rule = next(r for r in load_rules(ROOT / "contracts" / "rules") if r.id == BRUTE)
    wall = int(time.time() * 1000) - 5_000
    fired = False
    for i in range(12):
        fired |= bool(rule.evaluate(_event(i, wall - 120_000 + i * 10_000, wall + i * 100, f"{tag}-{source}")))
    return fired


def run():
    check(not _fires("event", "t1"),
          "control: with the default event time source the spread-out burst evades (that is finding F4)")
    check(_fires("ingest", "t2"),
          "ingest time source: the same burst must fire, driven by receipt time")
    # no received_ms -> falls back to record time, never crashes
    os.environ["FENGARDE_WINDOW_TIME_SOURCE"] = "ingest"
    rule = next(r for r in load_rules(ROOT / "contracts" / "rules") if r.id == BRUTE)
    ev = _event(99, int(time.time() * 1000) - 10_000, int(time.time() * 1000), "t3")
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
    print("[OK] WS-4 window time source: default unchanged; ingest time defeats a "
          "forged-clock burst; missing receipt time falls back")
