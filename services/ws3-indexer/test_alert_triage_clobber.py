"""Gap-hunt finding (2026-08-23): a redelivered `alerts` message must never
silently erase a `triage` field the triage API has since set on the same
alert_id -- same failure SHAPE as the P1-4 normalized/scored siem.score
clobber (test_double_index_order.py), a different pair of writers/field.

Bus delivery is at-least-once: a stale WS-4 alert payload (never carrying
`triage`) can be redelivered after this worker is killed mid-batch and
restarted, landing AFTER an analyst has already set `triage` via
triage_api.py's index_cas read-modify-write. Fix under test: `index_doc`
routes alert docs through `_index_alert_preserving_triage`, which carries
the existing `triage` field into the incoming payload under CAS.

These assertions go RED if the alerts-topic write reverts to a plain
`store.index()`.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from main import build_handlers, index_doc  # noqa: E402
from storage.memory import MemoryStore  # noqa: E402


def _alert(alert_id: str = "alert-clobber-1", score: int = 70) -> dict:
    return {
        "alert_id": alert_id,
        "time": 1_700_000_000_000,
        "src_endpoint": {"ip": "203.0.113.9"},
        "tenant_id": "default",
        "siem": {"score": score},
    }


def check(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def test_first_write_creates_and_reports_created():
    store = MemoryStore()
    check(index_doc(store, _alert()) is True,
          "first write of a brand-new alert_id should report True (it created)")


def test_redelivered_alert_after_triage_keeps_triage():
    """The race this whole module exists to close."""
    store = MemoryStore()
    index_doc(store, _alert())  # WS-4's original alert lands

    # Analyst triages it via the same path triage_api.py uses.
    index, doc, version = store.find_alert_versioned("alert-clobber-1")
    doc = dict(doc)
    doc["triage"] = {"status": "true_positive", "note": "confirmed", "updated_at": 123}
    check(store.index_cas(index, "alert-clobber-1", doc, version),
          "setup: triage CAS write should succeed")

    # Stale redelivery of the ORIGINAL WS-4 payload (no triage field at all).
    index_doc(store, _alert())

    _, stored, _ = store.find_alert_versioned("alert-clobber-1")
    check(stored.get("triage", {}).get("status") == "true_positive",
          "redelivered alert clobbered an already-set triage field")


def test_redelivered_alert_before_any_triage_is_a_harmless_noop():
    """No triage set yet -- redelivery must still behave like a normal
    idempotent duplicate (reports False, content unchanged)."""
    store = MemoryStore()
    index_doc(store, _alert())
    reported_created = index_doc(store, _alert())
    check(reported_created is False,
          "redelivery of an alert with no triage set should report as a duplicate")
    _, stored, _ = store.find_alert_versioned("alert-clobber-1")
    check(stored.get("siem", {}).get("score") == 70, "content should be unchanged")


def test_two_different_alerts_are_independent():
    store = MemoryStore()
    index_doc(store, _alert("alert-a"))
    index_doc(store, _alert("alert-b"))
    _, doc_a, ver_a = store.find_alert_versioned("alert-a")
    doc_a = dict(doc_a)
    doc_a["triage"] = {"status": "closed"}
    store.index_cas("alerts-2023.11.14", "alert-a", doc_a, ver_a)

    index_doc(store, _alert("alert-b"))  # redeliver b, must not touch a
    _, stored_a, _ = store.find_alert_versioned("alert-a")
    check(stored_a["triage"]["status"] == "closed",
          "an unrelated alert_id's redelivery must not affect this one's triage")


def test_alerts_topic_is_wired_through_the_preserving_path():
    """The daemon must actually route the `alerts` topic through
    `index_doc` (not some bypassed plain store.index call) -- drives the
    real `build_handlers()` map, same discipline as
    test_double_index_order.py::test_normalized_topic_is_wired_create_only.
    """
    store = MemoryStore()
    handlers = build_handlers(store)
    check("alerts" in handlers, f"expected 'alerts' in handler map, got {sorted(handlers)}")
    _, alerts_h = handlers["alerts"]

    alerts_h(_alert())
    index, doc, version = store.find_alert_versioned("alert-clobber-1")
    doc = dict(doc)
    doc["triage"] = {"status": "triaged", "note": "", "updated_at": 1}
    store.index_cas(index, "alert-clobber-1", doc, version)

    alerts_h(_alert())  # stale redelivery through the REAL wired handler
    _, stored, _ = store.find_alert_versioned("alert-clobber-1")
    check(stored.get("triage", {}).get("status") == "triaged",
          "the daemon's alerts handler clobbered triage -- build_handlers regression")


def test_triage_update_still_reaches_the_document():
    """The fix must not accidentally freeze `triage` forever -- a genuine
    triage CAS update (the normal path) must still land."""
    store = MemoryStore()
    index_doc(store, _alert())
    index, doc, version = store.find_alert_versioned("alert-clobber-1")
    doc = dict(doc)
    doc["triage"] = {"status": "new", "note": "", "updated_at": 1}
    store.index_cas(index, "alert-clobber-1", doc, version)

    index, doc, version = store.find_alert_versioned("alert-clobber-1")
    doc = dict(doc)
    doc["triage"] = {"status": "closed", "note": "resolved", "updated_at": 2}
    check(store.index_cas(index, "alert-clobber-1", doc, version),
          "a genuine triage CAS update must still succeed")
    _, stored, _ = store.find_alert_versioned("alert-clobber-1")
    check(stored["triage"]["status"] == "closed", "the real triage update must land")


def run_all() -> None:
    tests = [
        test_first_write_creates_and_reports_created,
        test_redelivered_alert_after_triage_keeps_triage,
        test_redelivered_alert_before_any_triage_is_a_harmless_noop,
        test_two_different_alerts_are_independent,
        test_alerts_topic_is_wired_through_the_preserving_path,
        test_triage_update_still_reaches_the_document,
    ]
    for t in tests:
        t()
    print(f"[OK] WS-3 alert/triage redelivery clobber PASS ({len(tests)} scenarios)")


if __name__ == "__main__":
    run_all()
