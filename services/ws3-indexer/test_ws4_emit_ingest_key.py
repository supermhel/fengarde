"""Gap-hunt finding R4-27: ws4-detection's `_emit` must not collapse every
event whose `siem.ingest_id` is PRESENT-but-None onto one shared ai.requests
bus key.

The pre-fix form was `siem.get("ingest_id", key)` -- the default only fired
when the KEY was absent, so a null-valued ingest_id produced a None funnel
key for every such event. The funnel key must fall back to the (src-ip)
default whenever the VALUE is None too, not just when the key is missing.

This test lives under ws3-indexer (the owning workstream for this pass) but
exercises ws4-detection/main.py's `_emit` directly -- the R4-27 fix touches
only ws4's main.py, which is why it is verified here rather than under a
ws4 test dir.

Run: python services/ws3-indexer/test_ws4_emit_ingest_key.py
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))

from shared.bus import Bus  # noqa: E402  (used for the _emit assertions)

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


_WS4_MAIN = SERVICES / "ws4-detection" / "main.py"
_spec = importlib.util.spec_from_file_location("ws4_main_under_test", _WS4_MAIN)
w4main = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(w4main)  # noqa: E402


class _FakeScorer:
    def is_llm_funnel_fresh(self, k):
        return True


class _FakeDetector:
    """Minimal stand-in for ws4 Detector with only the members _emit reads
    (no rule loading, no window counters). matched=[] means no make_alert
    calls and no record_fire."""

    def __init__(self):
        self.scorer = _FakeScorer()
        self.stats = {"scored": 0, "alerts": 0, "ai_enqueued": 0,
                      "classifier_enqueued": 0}

    def _funnel_fresh(self, event, matched):
        return True

    def _record_funnel(self, event, matched):
        pass

    def record_fire(self, rule_id, ts=None):
        pass


def _emit_keys(event, action="llm"):
    bus = Bus()
    # `_emit` is a method on Detector; call it unbound against our minimal
    # fake so we exercise the real production code path.
    w4main.Detector._emit(_FakeDetector(), bus, event, [], action)  # noqa: E501
    return [m.key for m in bus.drain("ai.requests")]


def test_present_none_ingest_id_falls_back_to_src_ip_key():
    """ingest_id present in the envelope with a null value: the funnel key
    must NOT be None (which collapses every such event onto one key)."""
    event = {"src_endpoint": {"ip": "203.0.113.9"},
             "siem": {"ingest_id": None, "score": 70}}
    keys = _emit_keys(event)
    check(len(keys) == 1, f"expected exactly one ai.requests emit, got {keys}")
    check(keys == ["203.0.113.9"],
          f"a present-but-None ingest_id must fall back to the src-ip key, got {keys}")


def test_absent_ingest_id_still_falls_back_to_src_ip_key():
    """Regression: a genuinely-missing ingest_id keeps the pre-fix fallback."""
    event = {"src_endpoint": {"ip": "198.51.100.7"}, "siem": {"score": 60}}
    check(_emit_keys(event) == ["198.51.100.7"],
          "an absent ingest_id must fall back to the src-ip key")


def test_present_non_none_ingest_id_is_used_as_key():
    """A real ingest_id is still used as the funnel key (no behavioral change
    for the well-formed case)."""
    event = {"src_endpoint": {"ip": "203.0.113.9"},
             "siem": {"ingest_id": "e-42", "score": 80}}
    check(_emit_keys(event) == ["e-42"],
          "a real ingest_id must be used as the funnel key")


def test_missing_src_endpoint_uses_zero_ip_fallback():
    event = {"siem": {"ingest_id": None, "score": 70}}
    check(_emit_keys(event) == ["0.0.0.0"],
          "no src_endpoint -> the module-level 0.0.0.0 default key")


def main():
    test_present_none_ingest_id_falls_back_to_src_ip_key()
    test_absent_ingest_id_still_falls_back_to_src_ip_key()
    test_present_non_none_ingest_id_is_used_as_key()
    test_missing_src_endpoint_uses_zero_ip_fallback()

    if FAILS:
        print(f"[FAIL] ws4 _emit funnel key: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] R4-27 ws4 _emit: present-but-None siem.ingest_id falls back to the "
          "src-ip funnel key (real and absent ingest_id unchanged)")


if __name__ == "__main__":
    main()