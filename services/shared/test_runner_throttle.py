"""P2-4 (2026-07-21 audit) -- traceback throttling in shared/runner.py.

Before this fix, a poison message stuck in the redelivery loop called
traceback.print_exc() on every single delivery attempt -- unbounded stderr
flood. This proves _throttled_print_exc emits at most once per throttle
window per (topic, exception type), and reports a suppressed count on the
next emission.

Run: python services/shared/test_runner_throttle.py
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


def _capture_stderr(fn):
    buf = io.StringIO()
    old = sys.stderr
    sys.stderr = buf
    try:
        fn()
    finally:
        sys.stderr = old
    return buf.getvalue()


def test_burst_of_same_exception_emits_once_within_window():
    runner._throttle_state.clear()
    topic = "test.throttle.topic1"

    def burst():
        for _ in range(50):
            try:
                raise ValueError("boom")
            except ValueError as exc:
                runner._throttled_print_exc(topic, exc)

    out = _capture_stderr(burst)
    check(out.count("Traceback (most recent call last)") == 1,
          f"expected exactly 1 traceback printed for a burst within the window, got "
          f"{out.count('Traceback (most recent call last)')}")


def test_next_emission_after_window_reports_suppressed_count():
    runner._throttle_state.clear()
    topic = "test.throttle.topic2"
    key = (topic, "ValueError")

    try:
        raise ValueError("boom")
    except ValueError as exc:
        runner._throttled_print_exc(topic, exc)  # first emission

    # Simulate 49 suppressed occurrences, then force the window to have elapsed.
    with runner._throttle_lock:
        runner._throttle_state[key]["suppressed"] = 49
        runner._throttle_state[key]["last"] -= runner._THROTTLE_WINDOW_S + 1

    def second():
        try:
            raise ValueError("boom")
        except ValueError as exc:
            runner._throttled_print_exc(topic, exc)

    out = _capture_stderr(second)
    check("49 more ValueError" in out, f"expected suppressed-count line, got: {out!r}")
    check(out.count("Traceback (most recent call last)") == 1,
          "the post-window emission must still print the traceback once")


def test_different_topics_throttle_independently():
    runner._throttle_state.clear()

    def raise_in(topic):
        try:
            raise ValueError("boom")
        except ValueError as exc:
            runner._throttled_print_exc(topic, exc)

    out_a = _capture_stderr(lambda: raise_in("topic-a"))
    out_b = _capture_stderr(lambda: raise_in("topic-b"))
    check("Traceback" in out_a and "Traceback" in out_b,
          "distinct topics must each get their own independent throttle bucket")


def run():
    test_burst_of_same_exception_emits_once_within_window()
    test_next_emission_after_window_reports_suppressed_count()
    test_different_topics_throttle_independently()


def main():
    run()
    if FAILS:
        print(f"[FAIL] runner traceback throttle: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] P2-4: shared/runner.py throttles traceback.print_exc to at most once per "
          "throttle window per (topic, exception type), reporting the suppressed count on "
          "the next emission; distinct topics throttle independently")


if __name__ == "__main__":
    main()
