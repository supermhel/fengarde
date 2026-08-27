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

from main import build_handlers, index_doc, _index_alert_preserving_triage  # noqa: E402
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
    store.index_cas(index, "alert-clobber-1", doc, version)
    version_after_triage = store.find_alert_versioned("alert-clobber-1")[2]

    # Stale redelivery of the ORIGINAL WS-4 payload (no triage field at all).
    index_doc(store, _alert())

    _, stored, version_after_redelivery = store.find_alert_versioned("alert-clobber-1")
    check(stored.get("triage", {}).get("status") == "true_positive",
          "redelivered alert clobbered an already-set triage field")
    # Mutation-sound: a plain store.index() also leaves triage=true_positive,
    # but it does NOT bump the version counter (index_cas does). Asserting
    # the version advanced proves the preserving write actually happened,
    # not a silent no-op.
    check(version_after_redelivery == version_after_triage + 1,
          "redelivery should have advanced the version (CAS write), not been a no-op")


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


def test_retry_exhaustion_under_sustained_contention_preserves_triage():
    """Finding 21: a plain overwrite after retry exhaustion is the exact clobber
    this function exists to prevent. After 5 version conflicts the function
    must bail out cleanly (return False = "treated as duplicate") rather than
    destroy the analyst's triage.
    """
    store = MemoryStore()
    index_doc(store, _alert())  # original alert lands

    index, doc, version = store.find_alert_versioned("alert-clobber-1")
    doc = dict(doc)
    doc["triage"] = {"status": "true_positive", "note": "confirmed", "updated_at": 123}
    store.index_cas(index, "alert-clobber-1", doc, version)
    version_after_triage = store.find_alert_versioned("alert-clobber-1")[2]

    # Monkey-patch index_cas to fail 5 times in a row (simulates sustained
    # concurrent triage writes from multiple analyst sessions).
    original_cas = store.index_cas
    cas_failures = [True] * 5  # each call returns False (version conflict)
    def always_conflict(index, doc_id, document, ver):
        if cas_failures:
            cas_failures.pop(0)
            return False  # simulate CAS conflict
        return original_cas(index, doc_id, document, ver)

    store.index_cas = always_conflict  # type: ignore[method-assign]
    try:
        result = _index_alert_preserving_triage(
            store, "alerts-2023.11.14", "alert-clobber-1", _alert())
    finally:
        store.index_cas = original_cas  # type: ignore[method-assign]

    # Must return False (duplicate / no-write) rather than True (new write).
    check(result is False,
          "retry exhaustion must not produce a new write (got %r)" % (result,))
    _, stored, version_after = store.find_alert_versioned("alert-clobber-1")
    check(stored.get("triage", {}).get("status") == "true_positive",
          "retry exhaustion must not clobber analyst triage")
    check(version_after == version_after_triage,
          "retry exhaustion must not advance the version (no write should have happened)")


def test_backoff_between_cas_retries():
    """Finding 21 backoff: two concurrent CAS writes on the same alert must
    not burn through all 5 retries in microseconds (which makes the stale-read
    problem on real OpenSearch ~100% likely). A sleep between retries means
    the second writer has time to complete before the first retries.
    """
    import time as time_mod
    store = MemoryStore()
    index_doc(store, _alert())

    # Set up triage FIRST so the function reaches the CAS path (it short-circuits
    # on `triage is None` without ever calling index_cas).
    index, doc, version = store.find_alert_versioned("alert-clobber-1")
    doc = dict(doc)
    doc["triage"] = {"status": "triaged", "note": "", "updated_at": 1}
    store.index_cas(index, "alert-clobber-1", doc, version)
    version_after_triage = store.find_alert_versioned("alert-clobber-1")[2]

    # Patch time.sleep to record calls and make the test fast.
    sleep_calls = []
    orig_sleep = time_mod.sleep
    def fake_sleep(s):
        sleep_calls.append(s)
    time_mod.sleep = fake_sleep  # type: ignore[assignment]

    try:
        # Force index_cas to fail once, then succeed on retry.
        calls = [False, True]
        orig_cas = store.index_cas
        def fail_once(*a, **kw):
            result = calls.pop(0)
            if result:
                return orig_cas(*a, **kw)  # actually perform the write on retry
            return False
        store.index_cas = fail_once  # type: ignore[method-assign]
        result = _index_alert_preserving_triage(
            store, "alerts-2023.11.14", "alert-clobber-1", _alert())
    finally:
        time_mod.sleep = orig_sleep  # type: ignore[assignment]
        store.index_cas = store.index_cas  # restore (already patched back)

    check(result is False, "CAS write after one conflict should succeed")
    check(len(sleep_calls) == 1, "one CAS conflict should trigger exactly one backoff sleep")
    # Mutation-sound: version must have advanced (CAS write happened), not stayed
    # the same (which would mean the function silently no-op'd).
    _, stored, version_after = store.find_alert_versioned("alert-clobber-1")
    check(version_after == version_after_triage + 1,
          "a successful CAS write after retry must bump the version")


def test_no_plain_non_cas_index_call_for_alert_writes():
    """R2-#19/#23: BOTH branches that used to bail out to a plain
    store.index() -- the create branch (existing is None) and the
    existing-doc-with-no-triage branch -- must now route through
    index_cas. A plain index() there silently destroys any concurrent
    triage write that lands between the read and the write."""
    store = MemoryStore()
    plain_calls = []
    orig_index = store.index

    def recording_index(index, doc_id, document):
        plain_calls.append((index, doc_id))
        return orig_index(index, doc_id, document)

    store.index = recording_index  # type: ignore[method-assign]
    try:
        check(index_doc(store, _alert("no-cas-1")) is True,
              "first create of a brand-new alert_id must succeed")
        check(index_doc(store, _alert("no-cas-1")) is False,
              "redelivery with no triage set yet must report as a duplicate")
        index, doc, version = store.find_alert_versioned("no-cas-1")
        doc = dict(doc)
        doc["triage"] = {"status": "triaged", "note": "", "updated_at": 1}
        store.index_cas(index, "no-cas-1", doc, version)
        index_doc(store, _alert("no-cas-1"))  # redelivery while triage IS set
    finally:
        store.index = orig_index  # type: ignore[method-assign]

    check(len(plain_calls) == 0,
          f"no alerts-topic write may fall back to a plain non-CAS store.index(); got {plain_calls}")


def test_create_path_uses_index_cas_with_version_none():
    """R2-#23: the very first write of an alert_id (existing is None) must
    call index_cas(..., version=None) -- not store.index -- so a create
    racing a concurrent write resolves through the same CAS path as every
    other alert write."""
    store = MemoryStore()
    cas_calls = []
    orig_cas = store.index_cas

    def recording_cas(index, doc_id, document, version):
        cas_calls.append((doc_id, version))
        return orig_cas(index, doc_id, document, version)

    store.index_cas = recording_cas  # type: ignore[method-assign]
    try:
        index_doc(store, _alert("create-cas-1"))
    finally:
        store.index_cas = orig_cas  # type: ignore[method-assign]

    check(len(cas_calls) == 1
          and cas_calls[0] == ("create-cas-1", None),
          f"a brand-new alert's create must call index_cas with version=None, got {cas_calls}")


def test_concurrent_triage_on_triage_none_path_is_preserved():
    """R2-#19: the doc exists but has NO triage yet; an analyst triage write
    lands between this redelivery's find_alert and its write. Because the
    branch writes through index_cas (not a plain index()), the version
    conflict is detected, the loop re-reads the fresher doc and carries the
    triage, and the concurrent analyst write survives."""
    store = MemoryStore()
    index_doc(store, _alert("concurrent-1"))  # no triage yet

    orig_cas = store.index_cas
    first = [True]

    def conflict_once(index, doc_id, document, ver):
        if first[0]:
            first[0] = False
            # simulate the peer analyst write landing between our read+write
            i2, d2, v2 = store.find_alert_versioned(doc_id)
            d2 = dict(d2)
            d2["triage"] = {"status": "true_positive", "note": "confirmed", "updated_at": 9}
            orig_cas(i2, doc_id, d2, v2)
            return False  # our (stale) write loses the version race
        return orig_cas(index, doc_id, document, ver)

    store.index_cas = conflict_once  # type: ignore[method-assign]
    try:
        index_doc(store, _alert("concurrent-1"))
    finally:
        store.index_cas = orig_cas  # type: ignore[method-assign]

    _, stored, _ = store.find_alert_versioned("concurrent-1")
    check(stored.get("triage", {}).get("status") == "true_positive",
          "a concurrent triage write racing the no-triage CAS path must survive the redelivery")


def test_two_different_alerts_are_independent():
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
        test_retry_exhaustion_under_sustained_contention_preserves_triage,
        test_backoff_between_cas_retries,
        test_no_plain_non_cas_index_call_for_alert_writes,
        test_create_path_uses_index_cas_with_version_none,
        test_concurrent_triage_on_triage_none_path_is_preserved,
        test_two_different_alerts_are_independent,
        test_alerts_topic_is_wired_through_the_preserving_path,
        test_triage_update_still_reaches_the_document,
    ]
    for t in tests:
        t()
    print(f"[OK] WS-3 alert/triage redelivery clobber PASS ({len(tests)} scenarios)")


if __name__ == "__main__":
    run_all()
