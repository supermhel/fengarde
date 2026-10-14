"""timeline_order_ok: does the WS-8 read-side timeline present each storyline's
attack in oracle order? (owner decision WS-8 option B, 2026-10-14)

For every registered storyline (seed 7) the chain's REAL alerts go through the
REAL Correlator; every promoted incident is laid out by
``services/ws8-correlation/timeline.build_timeline`` and the oracle step of each
of its alerts must appear in non-decreasing ``expected_sequence`` rank (alerts at
one instant are one timeline step and are never read as out of order).

This is an analyst-facing PRODUCT output graded for order -- unlike
``order_concordance``, which is a timestamp invariant of the harness's own chain.
It still cannot move ``directional_discrimination`` (graph edges are unchanged).

NEGATIVE CONTROL: the same alerts with their times mirrored (``lo + hi - t``)
must make the check say no on at least one storyline whose incident spans two
or more steps -- otherwise the check cannot fail and proves nothing.

Run: python eval/twin/test_timeline_order.py
"""
from __future__ import annotations

import copy
import importlib.util
import sys
from pathlib import Path

TWIN = Path(__file__).resolve().parent
ROOT = TWIN.parents[1]
for _p in (str(TWIN), str(ROOT / "services")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import report  # noqa: E402  (pins ws4's `main` before anything else imports one)
import scenario_registry as reg  # noqa: E402

# by file, NOT via sys.path: ws8-correlation/ on the path would shadow ws2's `main` the
# chain imports by bare name (the module-name collision report.py documents)
_spec = importlib.util.spec_from_file_location(
    "ws8_timeline", ROOT / "services" / "ws8-correlation" / "timeline.py")
assert _spec is not None and _spec.loader is not None
_timeline = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_timeline)
build_timeline = _timeline.build_timeline

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _incidents_and_items(sdef, seed: int = 7):
    result = reg.run(sdef, seed)
    items = report._build_chain_alerts([e for e in result.events if e.parsed])
    return items


def _correlate(items):
    ws8 = report._ensure_ws8()
    last = max((i["alert"].get("time") or 0) for i in items) if items else 0
    corr = ws8.Correlator(now_fn=lambda: (last + 3_600_000) / 1000.0)
    incidents: dict = {}
    for item in items:
        for inc in corr.ingest_alert(item["alert"]):
            incidents[inc["incident_id"]] = inc
    return incidents


def timeline_order_ok(items, expected_seq) -> tuple:
    """(ok, n_graded_incidents): ok is None when no incident spans two attack steps."""
    rank = {s: i for i, s in enumerate(expected_seq)}
    step_of = {i["alert"]["alert_id"]: i["step"] for i in items if i["step"] in rank}
    alerts = [i["alert"] for i in items]
    graded, ok = 0, True
    for inc in _correlate(items).values():
        tl = build_timeline(inc, alerts)
        seq = [sorted(rank[step_of[a]] for a in st["alert_ids"] if a in step_of) for st in tl["steps"]]
        seq = [r for r in seq if r]
        if len({x for r in seq for x in r}) < 2:
            continue
        graded += 1
        flat = [x for r in seq for x in r]
        # a later step's first alert must never come before an earlier step's
        if any(flat[k] > flat[k + 1] for k in range(len(flat) - 1)):
            ok = False
    return (ok if graded else None), graded


def _mirrored(items):
    out = copy.deepcopy(items)
    ts = [i["alert"].get("time") for i in out if isinstance(i["alert"].get("time"), int)]
    lo, hi = min(ts), max(ts)
    for i in out:
        if isinstance(i["alert"].get("time"), int):
            i["alert"]["time"] = lo + hi - i["alert"]["time"]
    return out


def run():
    said_no = []
    for sdef in reg.ALL:
        oracle = reg.load_oracle(sdef)
        items = _incidents_and_items(sdef)
        ok, graded = timeline_order_ok(items, oracle["expected_sequence"])
        check(ok is not False, f"{sdef.name}: the timeline puts the attack out of oracle order")
        print(f"   {sdef.name}: timeline_order_ok={ok} over {graded} multi-step incident(s)")
        if graded:
            m_ok, _ = timeline_order_ok(_mirrored(items), oracle["expected_sequence"])
            if m_ok is False:
                said_no.append(sdef.name)
    check(bool(said_no), "NEGATIVE CONTROL: a mirrored clock never made the timeline check say no")
    print(f"   negative control (mirrored clock) said no on: {said_no}")


def main():
    run()
    if FAILS:
        print(f"[FAIL] timeline order: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WS-8 timeline presents every storyline's multi-step incidents in oracle order; "
          "a mirrored clock makes it say no")


if __name__ == "__main__":
    main()
