"""Zero-infra: Detector batches all of an event's window ops into ONE counter call
(``hit_many``) and reaches the same verdicts as the sequential loop.

A recording counter wraps DequeWindowCounter (real window semantics) and adds
``hit_many`` implemented as the plain sequence of single calls, so any
difference between pipelined and sequential evaluation can only come from the
Detector's batching logic. The Redis side (EVALSHA pipeline == single EVALSHA
calls, real zsets/TTLs) is proven in test_window_lua_live.py.

Run: python services/ws4-detection/test_window_pipeline.py
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parents[1] / "tools"))
os.environ.setdefault("FENGARDE_LOG_LEVEL", "error")

from shared.window import DequeWindowCounter  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


class RecordingCounter(DequeWindowCounter):
    def __init__(self):
        super().__init__()
        self.single_calls = 0
        self.batches: list[int] = []

    def hit(self, *a, **k):
        self.single_calls += 1
        return super().hit(*a, **k)

    def hit_distinct(self, *a, **k):
        self.single_calls += 1
        return super().hit_distinct(*a, **k)

    def hit_many(self, ops):
        self.batches.append(len(ops))
        out = []
        for kind, key, now, win, arg in ops:
            out.append(super().hit(key, now, win, arg) if kind == "hit"
                       else super().hit_distinct(key, now, win, arg))
        return out


def build(pipeline: bool):
    import fengarde_loadtest as L
    _fb, ws2, _ws3, ws4 = L._load_stages()
    det = ws4.Detector(pipeline_window_ops=pipeline)
    counter = RecordingCounter()
    det._window_counter = counter
    for r in det.rules:
        if r.stateful:
            r.set_counter(counter)
    return L, ws2, ws4, det, counter


def events(L, ws2, n=500):
    fb = L._load_stages()[0]
    base = int(time.time()) - 900
    raw = []
    for i in range(n):
        ip = f"203.0.113.{i % 7 + 1}" if i % 3 == 0 else f"198.51.100.{i % 120 + 1}"
        user = "admin" if i % 2 == 0 else f"u{i % 9}"
        e = fb._ssh_fail(ip, i, base)
        e["raw"] = e["raw"].replace("invalid user admin", f"invalid user {user}")
        raw.append(e)
    out = []
    for r in raw:
        ev, errs = ws2.normalize_one(r)
        if ev is not None and not errs:
            out.append(ev)
    return out


def verdicts(det, evs):
    seq = []
    for ev in evs:
        _e, matched, _a = det.process(dict(ev))
        seq.append(tuple(r.id for r in matched))
    return seq


def test_batched_equals_sequential_and_uses_one_call_per_event():
    L, ws2, ws4, det_seq, c_seq = build(False)
    _, _, _, det_pipe, c_pipe = build(True)
    evs = events(L, ws2)
    a, b = verdicts(det_seq, evs), verdicts(det_pipe, evs)
    check(a == b, "per-event matched rule ids differ between sequential and batched evaluation")
    check(any(a), "stream must trip rules, else the comparison proves nothing")
    check(c_seq.batches == [], "sequential path must not use hit_many")
    check(c_pipe.batches and max(c_pipe.batches) > 1, f"batched path groups ops: {sorted(set(c_pipe.batches))}")
    # every event contributes at most ONE batched call, and the total number of
    # window ops is identical either way
    check(len(c_pipe.batches) <= len(evs), "at most one hit_many per event")
    total_pipe = sum(c_pipe.batches) + c_pipe.single_calls
    check(total_pipe == c_seq.single_calls, f"same number of window ops: {total_pipe} vs {c_seq.single_calls}")
    # and the window state ends up identical
    check(c_seq._w == c_pipe._w and c_seq._dw == c_pipe._dw, "window state differs after the stream")


def test_env_switch_and_fallbacks():
    L, ws2, ws4, det, c = build(True)
    check(det._pipeline_window_ops is True, "pipeline_window_ops=True honoured")
    os.environ["FENGARDE_WINDOW_PIPELINE"] = "0"
    try:
        d2 = ws4.Detector()
        check(d2._pipeline_window_ops is False, "FENGARDE_WINDOW_PIPELINE=0 switches it off")
    finally:
        del os.environ["FENGARDE_WINDOW_PIPELINE"]
    # plain deque counter (no hit_many): batching silently falls back, verdicts unchanged
    _, _, _, d3, _ = build(True)
    plain = DequeWindowCounter()
    d3._window_counter = plain
    for r in d3.rules:
        if r.stateful:
            r.set_counter(plain)
    _, _, _, d4, _ = build(False)
    plain2 = DequeWindowCounter()
    for r in d4.rules:
        if r.stateful:
            r.set_counter(plain2)
    evs = events(L, ws2, 200)
    check(verdicts(d3, evs) == verdicts(d4, evs), "no-hit_many counter falls back to identical verdicts")


def main() -> int:
    for fn in (test_batched_equals_sequential_and_uses_one_call_per_event, test_env_switch_and_fallbacks):
        n = len(FAILS)
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            FAILS.append(f"{fn.__name__} raised {type(exc).__name__}: {exc}")
        print(f"{'FAIL' if len(FAILS) > n else 'PASS'}: {fn.__name__}")
    if FAILS:
        print("FAILURES:\n - " + "\n - ".join(FAILS))
        return 1
    print("window pipeline test OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
