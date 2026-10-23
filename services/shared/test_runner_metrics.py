"""Gap-hunt #3 (2026-08-27): runner's combined /metrics provider must not
swallow provider errors with a bare `pass` -- a broken bus factory or metrics
provider used to render /metrics as a silent {} with zero signal. Each
failure is now logged once per (component, error type) via runner._warn_once,
so /metrics degrades to a partial dict with visible logs instead of silence.

Run: python services/shared/test_runner_metrics.py
"""
from __future__ import annotations

import io
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import runner  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _capture_stdout(fn):
    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        fn()
    finally:
        sys.stdout = old
    return buf.getvalue()


def test_broken_bus_factory_warns_once_and_degrades_to_empty():
    runner._metric_warned.clear()

    def bad_factory():
        raise RuntimeError("bus down")

    def call():
        return runner._serialize_metrics(bad_factory, {"t": ("g", None)}, None)

    out = _capture_stdout(lambda: (call(), call()))  # two calls -> warn once
    check("bus down" in out,
          f"a broken bus factory must be visible in the logs, got: {out!r}")
    check(out.count("bus down") == 1,
          f"the warning must be emitted once per error type, got {out.count('bus down')}")
    result = call()
    check(result == {},
          f"a broken bus factory must degrade to {{}} (never raise), got {result!r}")


def test_broken_metrics_provider_warns_and_merges_rest():
    runner._metric_warned.clear()

    class _FakeBus:
        def depth(self, topic):
            return 3

        def pel_evicted(self, topic):
            return 1

    def broken_provider():
        raise ValueError("provider broken")

    out = _capture_stdout(lambda: runner._serialize_metrics(
        lambda: _FakeBus(), {"t": ("g", None)}, broken_provider))
    check("provider broken" in out,
          f"a broken metrics provider must be visible, got: {out!r}")
    res = runner._serialize_metrics(lambda: _FakeBus(), {"t": ("g", None)}, broken_provider)
    check(res.get("t.deadletter_depth") == 3 and res.get("t.pel_evicted") == 1,
          f"bus-derived metrics must survive a broken provider, got {res!r}")


def test_broken_depth_method_warns_once_across_topics():
    runner._metric_warned.clear()

    class _BrokenDepthBus:
        def depth(self, topic):
            raise ConnectionError("redis gone")

        def pel_evicted(self, topic):
            return 0

    out = _capture_stdout(lambda: runner._serialize_metrics(
        lambda: _BrokenDepthBus(), {"a": ("g", None), "b": ("g", None)}, None))
    check("redis gone" in out,
          f"a broken depth() must be visible, got: {out!r}")
    check(out.count("redis gone") == 1,
          "the same (component, error type) must warn only once across topics")


def test_bus_without_pel_cap_is_skipped_silently():
    """The Redis buses have no pel_evicted(); that must not log a warning on every service."""
    runner._metric_warned.clear()

    class _RedisLikeBus:
        def depth(self, topic):
            return 2

    holder = {}
    out = _capture_stdout(lambda: holder.update(runner._serialize_metrics(
        lambda: _RedisLikeBus(), {"t": ("g", None)}, None)))
    check("pel_evicted" not in out, f"a bus without pel_evicted must not warn, got: {out!r}")
    check(holder.get("t.deadletter_depth") == 2 and "t.pel_evicted" not in holder,
          f"depth must still be reported and pel_evicted omitted, got {holder!r}")


def main():
    test_bus_without_pel_cap_is_skipped_silently()
    test_broken_bus_factory_warns_once_and_degrades_to_empty()
    test_broken_metrics_provider_warns_and_merges_rest()
    test_broken_depth_method_warns_once_across_topics()

    if FAILS:
        print(f"[FAIL] runner metrics provider: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] gap-hunt #3: runner /metrics provider errors are logged (warn once "
          "per error type), never a silent {}")


if __name__ == "__main__":
    main()
