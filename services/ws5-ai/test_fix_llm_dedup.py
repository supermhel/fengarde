"""WS-5 Task F: LLM dedup on redelivery -- standalone test.

Under at-least-once delivery the same event (same ``siem.ingest_id`` /
``event_id``) can be re-delivered, and AiWorker.handle() used to call
``self.llm.analyze()`` once per delivery. This test proves a redelivered event
is NOT re-sent to the LLM: the LLM adapter is swapped for a counting stub and
the same event_id is delivered twice -- analyze() must be called exactly once,
and the second delivery must return the identical (cached) result.

Also verifies:
  * the bounded cache evicts the OLDEST id when full, so an aged-out id is
    genuinely triaged again (LLM called) rather than falsely suppressed;
  * events with NO ingest_id/event_id are still processed on every delivery
    (back-compat, nothing stable to dedup on);
  * the two-level fallback (R4-39): siem.ingest_id ABSENT but the request-level
    event_id PRESENT still dedups against that event_id;
  * the classifier tier never touches the LLM (dedup is LLM-path only).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))
os.environ["BUS_BACKEND"] = "memory"
os.environ.pop("OLLAMA_URL", None)  # force StubLLM

import main as ws5  # noqa: E402

FAILS: list[str] = []


def check(c, m):
    if not c:
        FAILS.append(m)


class CountingLLM:
    """Deterministic LLM stub that counts analyze() calls."""

    def __init__(self):
        self.calls = 0

    def analyze(self, event, reasons):
        self.calls += 1
        return {"verdict": "malicious", "summary": "s", "level": "critical"}


def ai_request(ingest_id):
    return {
        "event_id": ingest_id,
        "reason": ["Privileged database operation on a banking DB"],
        "event": {
            "class_uid": 6005, "activity_id": 5, "severity_id": 4,
            "time": 1750000000000,
            "siem": {"sector": "bank", "ingest_id": ingest_id, "score": 85},
        },
    }


def run():
    # (4) core call-count assertion: same event_id twice -> analyze ONCE.
    worker = ws5.AiWorker()
    llm = CountingLLM()
    worker.llm = llm
    req = ai_request("evt-1")
    r1 = worker.handle(req)
    check(llm.calls == 1, f"first delivery: analyze called {llm.calls}x, want 1")
    r2 = worker.handle(req)  # redelivered -> cached, no new LLM call
    check(llm.calls == 1, f"redelivery: analyze called {llm.calls}x, want 1 (dedup failed)")
    check(r1 == r2, "redelivery must return the identical cached result")

    # distinct ids each call the LLM once.
    worker.handle(ai_request("evt-2"))
    worker.handle(ai_request("evt-3"))
    check(llm.calls == 3, f"3 distinct events: analyze called {llm.calls}x, want 3")

    # (1) bounded eviction: cap=2 -> feeding a,b,c evicts a; re-delivering a
    # must call the LLM again (it genuinely left the window), c stays cached.
    w2 = ws5.AiWorker(seen_cap=2)
    l2 = CountingLLM()
    w2.llm = l2
    w2.handle(ai_request("a"))
    w2.handle(ai_request("b"))
    w2.handle(ai_request("c"))  # evicts "a"
    check(l2.calls == 3, f"eviction fill: analyze called {l2.calls}x, want 3")
    calls_before = l2.calls
    w2.handle(ai_request("c"))  # still cached -> no call
    check(l2.calls == calls_before, "in-window id re-delivered but LLM re-called")
    w2.handle(ai_request("a"))  # evicted earlier -> triaged fresh
    check(l2.calls == calls_before + 1,
          f"evicted id must be re-triaged (analyze {l2.calls}x, want {calls_before + 1})")

    # (back-compat) no ingest_id / event_id -> always processed, no dedup.
    w3 = ws5.AiWorker()
    l3 = CountingLLM()
    w3.llm = l3
    noid = {"reason": [], "event": {"class_uid": 6005, "time": 1750000000000}}
    w3.handle(noid)
    w3.handle(noid)
    check(l3.calls == 2, f"no-id events must each be processed: analyze {l3.calls}x, want 2")

    # R4-39 (2026-08-27): the two-level dedup fallback -- siem.ingest_id ABSENT
    # on a request that DOES carry a request-level event_id must still dedup on
    # the event_id (ai_request() stamps ingest_id, so pop it to leave siem but
    # with no ingest_id). The fallback is what makes redelivery of events that
    # lack an OCSF siem.ingest_id idempotent against the request path.
    w5 = ws5.AiWorker()
    l5 = CountingLLM()
    w5.llm = l5
    fallback = ai_request("fb-evt")
    fallback["event"]["siem"].pop("ingest_id")  # siem present, ingest_id gone
    check(w5._dedup_key(fallback) == "fb-evt",
          "R4-39: _dedup_key must fall back to the request-level event_id when "
          "siem.ingest_id is absent")
    w5.handle(fallback)
    w5.handle(fallback)
    check(l5.calls == 1, "R4-39: dedup via event_id fallback failed -- a request "
          "with siem.ingest_id absent but event_id present must analyze ONLY once "
          f"(analyze {l5.calls}x, want 1)")
    check(w5.handle(fallback) == w5.handle(fallback),
          "R4-39: fallback-deduped redelivery must return the identical cached "
          "result (event_id fallback key)")
    # Belt-and-suspenders: siem entirely ABSENT (not just missing ingest_id) must
    # also dedup on the request-level event_id.
    w6 = ws5.AiWorker()
    l6 = CountingLLM()
    w6.llm = l6
    no_siem = {"reason": [], "event_id": "no-siem-evt",
               "event": {"class_uid": 6005, "time": 1750000000000}}
    w6.handle(no_siem)
    w6.handle(no_siem)
    check(l6.calls == 1, "R4-39: siem entirely absent must still dedup on the "
          f"request-level event_id (analyze {l6.calls}x, want 1)")

    # classifier tier never touches the LLM regardless of ids.
    w4 = ws5.AiWorker()
    l4 = CountingLLM()
    w4.llm = l4
    clf_req = dict(ai_request("dup-clf"))
    clf_req["tier"] = "classifier"
    w4.handle(clf_req)
    w4.handle(clf_req)
    check(l4.calls == 0, f"classifier tier must not call LLM: analyze {l4.calls}x, want 0")

    # R4-#36 (2026-08-27): main.py's handle() returns defensive COPIES
    # (`dict(cached)` on a cache hit, `dict(result)` at put()) so a caller that
    # mutates the returned result -- which the daemon handler hands straight to
    # bus.produce(), stored by reference on BUS_BACKEND=memory -- cannot corrupt
    # the cache entry for future redeliveries. `handle` asserting `==` only
    # never caught a shared reference; this alias test mutates BOTH returned
    # dicts and requires a third redelivery to still be pristine.
    w7 = ws5.AiWorker()
    l7 = CountingLLM()
    w7.llm = l7
    req7 = ai_request("alias-evt")
    r_a = w7.handle(req7)
    r_a["verdict"] = "MUTATED-1"    # must not touch the cache entry
    r_b = w7.handle(req7)           # cache hit -> must be a distinct copy
    check(r_b["verdict"] == "malicious",
          f"R4-#36: mutating the returned result corrupted the cached copy "
          f"(got {r_b['verdict']!r})")
    r_b["verdict"] = "MUTATED-2"    # must not touch the cache entry either
    r_c = w7.handle(req7)           # cache hit again
    check(r_c["verdict"] == "malicious",
          f"R4-#36: mutating a cache-hit result corrupted the cache "
          f"(got {r_c['verdict']!r})")


def main():
    run()
    if FAILS:
        print(f"[FAIL] WS-5 dedup: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WS-5 LLM dedup test PASS")


if __name__ == "__main__":
    main()
