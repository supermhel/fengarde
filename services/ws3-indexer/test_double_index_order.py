"""P1-4 remainder: normalized/scored double-index must be order-independent.

WS-3 consumes BOTH `normalized.events` and `scored.events`, and the runner
gives each topic its OWN worker thread -- so for one logical event the two
writes race with no ordering guarantee between them. Both route to the SAME
(index, doc_id) (router.py derives the id from `siem.ingest_id`, which WS-4
passes through unchanged) and the plain `index()` is a full-document
replace, so a normalized write landing LAST used to overwrite the scored
copy and silently strip `siem.score` off an already-scored document.

The event stayed indexed, so nothing looked broken -- it just lost its
detection score, which is exactly the kind of silent-wrong-answer this
project's fail-closed discipline exists to catch.

Fix under test: the normalized-events path writes create-only
(`index_if_absent`), so whichever order the two threads run in, the result
converges to the scored document.

These assertions go RED if `normalized_handler`/`create_only` is reverted to
a plain `index()`.
"""
from __future__ import annotations

import copy
import os
import sys
import threading
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from main import build_handlers, index_doc  # noqa: E402
from router import route  # noqa: E402
from storage.memory import MemoryStore  # noqa: E402

_BASE: dict[str, Any] = {
    "time": 1_700_000_000_000,
    "class_uid": 3002,
    "activity_id": 4,
    "src_endpoint": {"ip": "203.0.113.5"},
    "siem": {"sector": "common", "ingest_id": "evt-order-1", "tenant": "default"},
}


def _normalized() -> dict:
    """WS-2 output: no siem.score (only WS-4 sets it, main.py's Detector)."""
    return copy.deepcopy(_BASE)


def _scored(score: int = 70) -> dict:
    """WS-4 output: same event, same ingest_id, plus siem.score."""
    doc = copy.deepcopy(_BASE)
    doc["siem"]["score"] = score
    return doc


def _score_of(store: MemoryStore, doc: dict):
    index, doc_id = route(doc)
    stored = store.get(index, doc_id)
    assert stored is not None, "expected a stored document"
    return (stored.get("siem") or {}).get("score")


def check(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def test_both_topics_route_to_the_same_document():
    """The premise of the whole bug: same event -> same (index, doc_id)."""
    check(route(_normalized()) == route(_scored()),
          "normalized and scored must route to the same index+doc_id "
          "(if this fails the double-index bug's premise changed)")


def test_scored_then_normalized_keeps_the_score():
    """The race-losing order: scored lands first, normalized arrives late.

    This is the assertion that goes red without the fix -- a plain index()
    here overwrites the scored doc with the score-less normalized one.
    """
    store = MemoryStore()
    index_doc(store, _scored())                        # scored.events worker
    index_doc(store, _normalized(), create_only=True)  # normalized worker, late
    check(_score_of(store, _scored()) == 70,
          "late normalized write clobbered siem.score off the scored document")


def test_normalized_then_scored_keeps_the_score():
    """The lucky order still has to work -- the fix must not break it."""
    store = MemoryStore()
    index_doc(store, _normalized(), create_only=True)
    index_doc(store, _scored())
    check(_score_of(store, _scored()) == 70,
          "scored write failed to upgrade the earlier normalized document")


def test_redelivered_normalized_never_downgrades():
    """At-least-once delivery: a redelivered normalized event must stay inert."""
    store = MemoryStore()
    index_doc(store, _normalized(), create_only=True)
    index_doc(store, _scored())
    for _ in range(3):  # same normalized message redelivered repeatedly
        index_doc(store, _normalized(), create_only=True)
    check(_score_of(store, _scored()) == 70,
          "a redelivered normalized event downgraded an already-scored document")


def test_create_only_reports_suppression():
    """index_if_absent's return value distinguishes wrote-it from already-there."""
    store = MemoryStore()
    check(index_doc(store, _normalized(), create_only=True) is True,
          "first create-only write should report True (it wrote)")
    check(index_doc(store, _normalized(), create_only=True) is False,
          "second create-only write should report False (suppressed)")


def test_concurrent_writers_converge_on_the_scored_doc():
    """Both workers firing at once must still converge -- no lock-free window.

    MemoryStore.index_if_absent does its existence check and its write under
    ONE lock hold; a check-then-act split would reopen the race this whole
    module exists to close.
    """
    for attempt in range(50):
        store = MemoryStore()
        barrier = threading.Barrier(2)
        errors: list[BaseException] = []

        def write_scored():
            try:
                barrier.wait()
                index_doc(store, _scored())
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        def write_normalized():
            try:
                barrier.wait()
                index_doc(store, _normalized(), create_only=True)
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=write_scored),
                   threading.Thread(target=write_normalized)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        check(not errors, f"concurrent writers raised: {errors!r}")
        check(_score_of(store, _scored()) == 70,
              f"attempt {attempt}: concurrent writers lost siem.score")


def test_normalized_topic_is_wired_create_only():
    """The daemon must actually POINT `normalized.events` at the create-only
    handler -- the fix is worthless if the wiring regresses.

    Everything else in this file proves `index_doc(create_only=True)` behaves
    correctly; this proves the live daemon actually calls it that way. Drives
    the real `build_handlers()` map and checks behavior through the handler
    it returns, rather than asserting on a function name (which would pass
    just as happily if the body were changed to a plain index()).
    """
    store = MemoryStore()
    handlers = build_handlers(store)

    check("normalized.events" in handlers and "scored.events" in handlers,
          f"expected both event topics in the handler map, got {sorted(handlers)}")

    _, normalized_h = handlers["normalized.events"]
    _, scored_h = handlers["scored.events"]

    # Scored lands first; the late normalized delivery must not strip its score.
    scored_h(_scored())
    normalized_h(_normalized())
    check(_score_of(store, _scored()) == 70,
          "the daemon's normalized.events handler clobbered siem.score -- it is "
          "not wired create-only (build_handlers regression)")

    # And the scored handler must still be a plain overwrite, or a genuinely
    # updated score could never land on a doc the normalized path created.
    store2 = MemoryStore()
    n2 = build_handlers(store2)["normalized.events"][1]
    s2 = build_handlers(store2)["scored.events"][1]
    n2(_normalized())          # normalized arrives first this time
    s2(_scored(score=90))      # scored must still be able to upgrade it
    check(_score_of(store2, _scored()) == 90,
          "the daemon's scored.events handler must overwrite in place -- a real "
          "score can never reach a doc the normalized path created otherwise")


def run_all() -> None:
    tests = [
        test_both_topics_route_to_the_same_document,
        test_scored_then_normalized_keeps_the_score,
        test_normalized_then_scored_keeps_the_score,
        test_redelivered_normalized_never_downgrades,
        test_create_only_reports_suppression,
        test_concurrent_writers_converge_on_the_scored_doc,
        test_normalized_topic_is_wired_create_only,
    ]
    for t in tests:
        t()
    print(f"[OK] WS-3 double-index order-independence PASS ({len(tests)} scenarios)")


if __name__ == "__main__":
    run_all()
