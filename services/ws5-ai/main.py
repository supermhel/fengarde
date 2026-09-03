"""WS-5 AI worker entrypoint.

Decoupled funnel consumer (Contract B): reads the buffered `ai.requests` topic at
its own pace and runs one of two tiers per request's `tier` field (set by WS-4's
Scorer.route(), contracts/scoring.yaml):
  - "llm" (score >= llm_min): full LLM triage (local Ollama, StubLLM fallback) +
    the light classifier, same as before this fix.
  - "classifier" (classifier_min <= score < llm_min): ONLY the light classifier
    (classifier.py) runs -- no LLM call. This is the whole point of a cheap
    second tier (P1-2, 2026-07-21 audit): calling the LLM on every 20-59-score
    event would just reintroduce the cost the tier exists to avoid. A request
    with no `tier` field defaults to "llm" (back-compat with any producer that
    predates this).
Both tiers publish `ai.results` and an enriched `alerts` entry; the classifier
tier's alert carries no `ai` (LLM verdict) block, only `classification`, and its
`level` is the classifier's own priority (low/medium/high), not an LLM verdict.

Concurrency (WP-3-D): the LLM tier's ``analyze`` call is dispatched to a bounded
``ThreadPoolExecutor`` owned by ``AiWorker``. The light-classifier tier stays
inline (cheap and deterministic). Per-request results are independent and
deterministic (same input -> same verdict), but **ordering across requests is
not guaranteed under concurrency**: with a pool, two in-flight LLM calls may
complete in either order, and ``handle()`` returns each request's result as soon
as *that* request's LLM call finishes. The bus ``produce`` order in the handler
is whatever ``handle()`` returns per call. This matches the per-request
independence of the underlying triage and is safe because ``ai.results`` and
``alerts`` are keyed by a stable event id, not by sequence position.

The pool only does concurrent work if more than one request can be in
``handle()`` at once -- ``handle()`` itself blocks on ``future.result()``, so
that requires more than one caller thread. ``main()`` wires this via
``shared.runner.serve``'s ``topic_workers={"ai.requests": worker.max_workers}``:
that many consumer threads share the ``cg-ai`` group (Redis consumer groups
load-balance a group's deliveries across named consumers), so up to
``max_workers`` requests are genuinely in flight through the pool at once in
production, not just under this module's own multi-threaded tests.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import sys
import threading
from collections import deque
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))

from shared.bus import Bus  # noqa: E402
from classifier import LightClassifier  # noqa: E402
from llm_adapter import make_llm  # noqa: E402

# How many event-ids the in-process dedup cache retains. Bounded on purpose:
# under at-least-once redelivery we only need to catch a re-delivered event
# while it is still plausibly being replayed, so we keep the most recent ids
# and evict the OLDEST when full (mirrors ws4-detection/window.py's bounded
# member-eviction). A re-delivered event that aged out past the cap is simply
# triaged again -- harmless, and keeps memory flat on high-throughput bursts.
_SEEN_CAP = 10000

# WS-5 AI pool defaults. ``AI_MAX_WORKERS`` caps the number of concurrent LLM
# calls; ``AI_QUEUE_CAP`` caps the number of additional requests that can be
# admitted past ``max_workers`` (the executor's own queue is unbounded, so we
# layer a semaphore on top to give the caller backpressure instead of OOMing
# under a burst). Total hard bound = max_workers + queue_cap.
_AI_MAX_WORKERS_DEFAULT = 4
_AI_QUEUE_CAP_DEFAULT = 4


class _TriageCache:
    """Bounded in-process dedup for the LLM triage call.

    Under at-least-once delivery the same event (same ``siem.ingest_id`` /
    ``event_id``) can be re-delivered; without a guard we'd call
    ``self.llm.analyze()`` once per redelivery, doing paid/expensive triage on
    something already triaged on its first delivery. This keeps the event id in
    a bounded window and returns the previously-computed result on redelivery so
    the caller still gets a truthful, identical answer -- just without re-running
    the LLM.

    Eviction models ``DequeWindowCounter`` in ws4-detection/window.py: an
    insertion-order ``deque`` keeps recency, and when the cap is reached the
    OLDEST id is dropped. In-process-only, exactly like the deque window
    backend -- per-replica dedup, which is the right scope for a single funnel
    consumer.
    """

    def __init__(self, cap: int = _SEEN_CAP) -> None:
        self._cap = cap
        self._order: deque = deque()
        self._m: dict = {}  # event_id -> triage result
        self._lock = threading.Lock()

    def get(self, key: str):
        with self._lock:
            return self._m.get(key)

    def put(self, key: str, result) -> None:
        with self._lock:
            if key in self._m:
                return
            self._m[key] = result
            self._order.append(key)
            if len(self._order) > self._cap:
                oldest = self._order.popleft()
                self._m.pop(oldest, None)


class AiWorker:
    def __init__(self, seen_cap: int = _SEEN_CAP,
                 max_workers: int | None = None,
                 queue_cap: int | None = None):
        self.llm = make_llm()
        self.classifier = LightClassifier()
        self._triage = _TriageCache(cap=seen_cap)
        # llm_adapter.py tags every verdict with `engine`/`model` (stub vs
        # ollama vs the fallback-on-error path) and that tag is disclosed
        # end-to-end -- it reaches the stored alert doc and renders per-alert
        # in the dashboard -- but nothing aggregated it. This counter + the
        # module-level _metrics_provider() (wired into serve()) lets an operator
        # see "we've silently been running on the stub" at a glance.
        self._engine_lock = threading.Lock()
        self._engine_counts: dict[str, int] = {}
        self._in_flight = 0

        max_workers = max(1, int(os.getenv("AI_MAX_WORKERS", max_workers or _AI_MAX_WORKERS_DEFAULT)))
        if queue_cap is None:
            queue_cap = int(os.getenv("AI_QUEUE_CAP", _AI_QUEUE_CAP_DEFAULT))
        # Hard bound = workers that can run concurrently + extra queued admissions.
        # The executor's own queue is unbounded; this semaphore gives the caller
        # backpressure so memory cannot grow without limit under a burst.
        total_cap = max_workers + max(0, queue_cap)
        self.max_workers = max_workers
        self._admit = threading.Semaphore(total_cap)
        self._pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="ws5-ai-llm",
        )
        # Per-event-id lock map so two threads triaging the SAME event do not
        # trigger two LLM calls, while threads triaging DIFFERENT events can
        # run concurrently. Bounded the same way as _TriageCache (oldest
        # evicted past _SEEN_CAP) -- an unbounded map here would leak one
        # Lock per distinct event id for the life of the process.
        self._key_locks: dict[str, threading.Lock] = {}
        self._key_locks_order: deque = deque()
        self._key_locks_lock = threading.Lock()

    def _key_lock(self, eid: str) -> threading.Lock | None:
        with self._key_locks_lock:
            lock = self._key_locks.get(eid)
            if lock is None:
                lock = threading.Lock()
                self._key_locks[eid] = lock
                self._key_locks_order.append(eid)
                if len(self._key_locks_order) > _SEEN_CAP:
                    oldest = self._key_locks_order.popleft()
                    self._key_locks.pop(oldest, None)
            return lock

    def _llm_task(self, request: dict, event: dict, reasons: list, eid: str | None):
        """Run inside the pool worker. Releases the admission semaphore on
        completion (success or failure) so backpressure is maintained."""
        with self._engine_lock:
            self._in_flight += 1
        try:
            verdict = self.llm.analyze(event, reasons)
            engine = verdict.get("engine")
            if engine:  # a genuine LLM call, not a classifier-tier/cache-hit skip
                with self._engine_lock:
                    self._engine_counts[engine] = self._engine_counts.get(engine, 0) + 1
            result = {
                "event_id": request.get("event_id"),
                "tier": request.get("tier", "llm"),
                "verdict": verdict.get("verdict"),
                "summary": verdict.get("summary"),
                "level": verdict.get("level"),
                "classification": self.classifier.predict(event),
                "engine": verdict.get("engine"),
                "model": verdict.get("model"),
            }
            if eid is not None:
                # Cache a copy too, for the same reason -- the freshly-built
                # `result` is also handed to bus.produce() by the caller (R4-#36).
                self._triage.put(eid, dict(result))
            return result
        finally:
            self._admit.release()
            with self._engine_lock:
                self._in_flight -= 1

    @staticmethod
    def _dedup_key(request: dict):
        """The id used for dedup: the event's OCSF ``siem.ingest_id`` falling
        back to the request-level ``event_id``. Returns ``None`` when neither is
        present -- events with no id are still processed on every delivery
        (they carry no stable identity to dedup on). Gap-hunt (2026-08-27) #2:
        ``siem`` may be an explicit null in a hostile payload -- treat it as
        absent (``(x or {})``), never ``None.get``."""
        return ((request.get("event", {}) or {}).get("siem") or {}).get("ingest_id") \
            or request.get("event_id")

    def handle(self, request: dict) -> dict:
        event = request.get("event", {})
        tier = request.get("tier", "llm")
        if tier == "classifier":
            classification = self.classifier.predict(event)
            return {
                "event_id": request.get("event_id"),
                "tier": tier,
                "verdict": None,
                "summary": None,
                "level": classification["priority"],
                "classification": classification,
                "engine": None,
                "model": None,
            }
        reasons = request.get("reason", [])
        eid = self._dedup_key(request)
        key_lock = self._key_lock(eid) if eid is not None else None

        if key_lock is not None:
            key_lock.acquire()
        try:
            if eid is not None:
                cached = self._triage.get(eid)
                if cached is not None:
                    # Already triaged on a prior delivery -- do NOT pay for the LLM
                    # again; hand back the exact verdict we already computed. A
                    # COPY, not the cache's own dict: the caller (_make_handler)
                    # hands this straight to bus.produce(), and on
                    # BUS_BACKEND=memory a produced payload is stored by reference
                    # (no serialization) -- a later mutation of that message would
                    # otherwise corrupt this cache entry for every future
                    # redelivery of the same event (R4-#36).
                    return dict(cached)

            # Admission control: acquire before submit so the executor's
            # unbounded internal queue is bounded by backpressure instead of
            # growing without limit. Once submitted, `_llm_task` owns the
            # release (its own `finally`, on both success and failure) --
            # release here ONLY if submit() itself raises before the task
            # ever runs, or the semaphore would be released twice for one
            # acquire (its own analyze()/predict() exception already comes
            # back through future.result() after `_llm_task` released once).
            self._admit.acquire()
            try:
                future = self._pool.submit(self._llm_task, request, event, reasons, eid)
            except Exception:
                self._admit.release()
                raise
            return future.result()
        finally:
            if key_lock is not None:
                key_lock.release()

    def metrics(self) -> dict:
        """Aggregate LLM-engine mix for /metrics -- e.g. {"by_engine":
        {"stub": 12, "ollama": 3}, "total": 15}. Counts only genuine LLM
        invocations: classifier-tier requests never call the LLM at all, and a
        cache hit (redelivery of an already-triaged event) returns the prior
        verdict without a new call, so neither increments this.

        Includes ``in_flight`` (current concurrent LLM calls) as a gauge.
        """
        with self._engine_lock:
            by_engine = dict(self._engine_counts)
            in_flight = self._in_flight
        return {
            "by_engine": by_engine,
            "total": sum(by_engine.values()),
            "in_flight": in_flight,
        }

    def shutdown(self, wait: bool = True) -> None:
        """Shut down the worker's thread pool cleanly."""
        self._pool.shutdown(wait=wait)


def _metrics_provider(worker: "AiWorker") -> dict:
    """The flat #16 metrics shape main()'s serve() call exposes on /metrics:
    ``ai_llm_total`` plus one ``ai_llm_<engine>`` counter per engine seen.
    Module-level so a test can exercise main()'s ACTUAL provider wiring
    (import main, call this with a worker) rather than self-building an
    equivalent literal (R2-#18)."""
    m = worker.metrics()
    return {
        "ai_llm_total": m["total"],
        **{f"ai_llm_{k}": v for k, v in m["by_engine"].items()},
        "ai_llm_in_flight": m["in_flight"],
    }


def _stable_event_id(result: dict, event: dict) -> str:
    """Deterministic id for ai.results/alerts bus keys and the alert ``alert_id``.

    Events WITH an id keep it (string-normalized). Id-less events used to fall
    back to the literal 'unknown' -- every id-less alert collapsed onto the
    same doc (alert_id='ai-unknown') and bus key 'unknown'. Gap-hunt
    (2026-08-27) #8: derive a stable per-event id from a hash of the event
    payload instead, so distinct id-less events no longer collide while an
    identical redelivery of the SAME id-less event still maps to the SAME id
    (alert indexing stays idempotent under at-least-once delivery)."""
    eid = result.get("event_id")
    if eid:
        return str(eid)
    digest = hashlib.sha256(
        json.dumps(event, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()[:16]
    return f"hash-{digest}"


def _alert_payload(result: dict, event: dict) -> dict:
    """Build the enriched-alert doc for one ai.results record. The
    classifier tier never called an LLM, so its alert carries no `ai`
    (verdict/summary) block -- only `classification` -- rather than
    fabricating a verdict that was never actually computed."""
    stable_id = _stable_event_id(result, event)
    alert = {
        "alert_id": f"ai-{stable_id}",
        "time": event.get("time"),
        "level": result["level"],
        "classification": result["classification"],
        # Gap-hunt (2026-08-27) #2: `siem` may be an explicit null -- coerce to
        # {} so .get("sector") never raises AttributeError.
        "sector": (event.get("siem") or {}).get("sector"),
        "event_ids": [stable_id],
    }
    if result["tier"] != "classifier":
        alert["ai"] = {"verdict": result["verdict"], "summary": result["summary"],
                       "level": result["level"], "engine": result.get("engine"),
                       "model": result.get("model")}
    return alert


def run(bus, worker: "AiWorker") -> dict:
    stats = {"analyzed": 0}
    for msg in bus.consume("ai.requests", group="cg-ai"):
        event = msg.payload.get("event", {}) or {}
        result = worker.handle(msg.payload)
        bus.produce("ai.results", key=_stable_event_id(result, event), payload=result)
        bus.produce("alerts", key=_stable_event_id(result, event),
                    payload=_alert_payload(result, event))
        stats["analyzed"] += 1
    return stats


def _make_handler(bus, worker: "AiWorker"):
    """Build the per-message daemon handler bound to ONE shared `bus`.

    H1 (2026-07-29 audit): ONE Bus() per worker, not one per message. On
    BUS_BACKEND=memory a fresh Bus() per call returns a brand new, isolated
    in-memory bus nothing else ever reads -- ai.results/alerts would silently
    stay empty forever. `bus` is passed in so this closure is unit-testable
    without a live daemon loop.
    """
    def handler(payload: dict) -> None:
        event = payload.get("event", {}) or {}
        result = worker.handle(payload)
        bus.produce("ai.results", key=_stable_event_id(result, event), payload=result)
        bus.produce("alerts", key=_stable_event_id(result, event),
                    payload=_alert_payload(result, event))
    return handler


def main(worker: "AiWorker | None" = None):
    # Daemon (T0): consume ai.requests via the shared runner. run() above stays
    # the batch path used by tests / the e2e harness. Real local-Ollama triage
    # runs when OLLAMA_URL is set and reachable; otherwise the deterministic
    # StubLLM is used. `worker` is injectable so a test can drive main()'s real
    # serve() wiring against a worker it controls.
    from shared.runner import serve  # noqa: E402
    from shared.log import get_logger  # noqa: E402

    worker = worker or AiWorker()
    mode = type(worker.llm).__name__
    get_logger("ws5-ai").info("ai triage mode", mode=mode)

    handler_bus = Bus()
    handler = _make_handler(handler_bus, worker)

    bus_factory = Bus
    if os.getenv("FENGARDE_TENANT_FAIR_CONSUME", "1").strip().lower() not in ("0", "false", "no"):
        from shared.fairness import FairConsumeBus, event_tenant_key

        def bus_factory():
            return FairConsumeBus(Bus(), tenant_key_fn=event_tenant_key)

    # The pool inside `worker` only has real concurrent work to do if more
    # than one consumer thread can hand it requests at once -- with a single
    # runner thread per topic, handle() blocking on future.result() means the
    # ThreadPoolExecutor/semaphore/in_flight gauge above are never actually
    # exercised concurrently in production. `topic_workers` gives ai.requests
    # as many consumer threads as the pool has workers, so up to
    # AI_MAX_WORKERS requests really are in flight at once (each still
    # admission-controlled by `worker._admit`); Redis consumer groups are
    # built for exactly this (multiple named consumers load-balancing one
    # group's deliveries).
    serve({"ai.requests": ("cg-ai", handler)},
          health_port=int(os.getenv("PORT", "8005")), service_name="ws5-ai",
          bus_factory=bus_factory,
          metrics_provider=lambda: _metrics_provider(worker),
          topic_workers={"ai.requests": worker.max_workers})


if __name__ == "__main__":
    main()
