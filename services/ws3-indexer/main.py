"""WS-3 Indexer entrypoint.

Consume normalized.events / scored.events / alerts / ai.results, route each
document to the right index (Contract E), and store it idempotently. Storage
backend is swappable: MemoryStore (default) or OpenSearchStore (BUS-prod).
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))

from router import route  # noqa: E402
from storage.memory import MemoryStore  # noqa: E402
from shared.authz import require_auth_or_die  # noqa: E402

# ORDER IS LOAD-BEARING for the batch run() path below: `normalized.events`
# MUST stay ahead of `scored.events`. Both carry the same logical event and
# route to the same (index, doc_id), and run() drains them sequentially in
# this order -- so the scored copy (the one carrying `siem.score`) lands
# last and wins. Reordering these two silently strips the score off every
# event the batch path indexes. The live daemon does NOT rely on this: its
# per-topic threads have no ordering guarantee, which is why the
# normalized-events worker writes create-only instead (normalized_handler).
TOPICS = ["normalized.events", "scored.events", "alerts", "ai.results", "incidents",
          # Phase 5 (2026-09-04): the analyst read path. Both topics existed
          # on the bus since Phase 2/3 (WS-9, WS-8) with WS-3 only reaper-
          # trimming them (see _ALL_BUS_TOPICS below) -- no consumer, no
          # storage, no read route. entity.updates/incident.graph are
          # "current state" documents (each republish carries the full
          # latest snapshot, not a delta), so route() indexes them under a
          # flat, non-date-suffixed index keyed by entity_id/incident_id --
          # a plain last-write-wins overwrite is correct, same as `incidents`
          # itself already re-emitting in place as it grows.
          "entity.updates", "incident.graph"]


def make_store():
    if os.getenv("STORAGE_BACKEND", "memory").lower() == "opensearch":
        from storage.opensearch import OpenSearchStore
        return OpenSearchStore()
    return MemoryStore()


class BatchIndexHandler:
    """Daemon handler for ONE topic. Callable per payload (``handler(payload)``,
    the original one-write-per-message path, kept for MemoryStore and as the
    kill switch) and, when the store supports ``bulk_write``, batch-capable via
    :meth:`handle_batch` so ``shared.runner`` hands it a whole read pass and
    the batch goes out as ONE ``/_bulk`` request.

    Semantics are the per-document ones, item by item:

    * ``create_only`` (``normalized.events``): bulk ``create``; a per-item 409
      means "already stored" and is a SUCCESS (never clobbers the scored copy).
    * everything else: bulk ``index`` (idempotent upsert on the deterministic id).
    * alerts (``alert_id``, not create-only) must read-modify-write to preserve
      analyst ``triage``, which a blind bulk upsert would clobber. With a store
      that has ``mget_versioned`` the batch does that in bulk (see
      :meth:`_plan_alerts`: one ``_mget``, one conditional bulk write, per-item
      409 -> the per-document CAS path); otherwise every alert takes
      :func:`_index_alert_preserving_triage`.
    * unroutable docs are dropped (success), as in the single path.

    Result contract for the runner: a list parallel to the input, ``None`` =
    written/suppressed (ack), an Exception = leave unacked (redelivery). Items
    that fail with 429/5xx are retried in-process a bounded number of times
    (``WS3_BULK_RETRIES``) before being reported failed, so a transient
    OpenSearch back-pressure blip does not wait out the 60 s claim window. A
    whole-request failure fails every item that was in that request. Ordering:
    bulk applies items in order, so two writes to one id inside a batch land
    in message order, same as sequential PUTs.
    """

    _RETRYABLE = frozenset({429, 500, 502, 503, 504})

    def __init__(self, store, *, create_only: bool = False,
                 batch_max: int | None = None, retries: int | None = None,
                 backoff_s: float = 0.2):
        self.store = store
        self.create_only = create_only
        self.batch_max = batch_max if batch_max is not None else int(
            os.getenv("WS3_BULK_MAX", "500"))
        self.retries = retries if retries is not None else int(
            os.getenv("WS3_BULK_RETRIES", "3"))
        self.backoff_s = backoff_s
        self.stats = {"bulk_requests": 0, "bulk_docs": 0, "conflicts_409": 0,
                      "retried_items": 0, "failed_items": 0,
                      "cas_conflicts": 0}

    def __call__(self, payload: dict) -> None:
        try:
            index_doc(self.store, payload, create_only=self.create_only, strict=True)
        except ValueError:
            pass  # unroutable doc -> drop, matches run()

    def handle_batch(self, payloads: list) -> list:
        results: list = [None] * len(payloads)
        # pending item: [positions, op, index, doc_id, doc, version, original payload]
        pending: list = []
        alerts: dict = {}     # (index, doc_id) -> [positions, last payload]
        fallback: list = []   # (positions, index, doc_id, payload) -> per-doc CAS path
        alerts_bulk = callable(getattr(self.store, "mget_versioned", None))
        for i, payload in enumerate(payloads):
            try:
                index, doc_id = route(payload)
            except ValueError:
                continue  # unroutable -> drop (success)
            if not self.create_only and "alert_id" in payload:
                if alerts_bulk:
                    g = alerts.setdefault((index, doc_id), [[], None])
                    g[0].append(i)
                    g[1] = payload
                else:
                    fallback.append(([i], index, doc_id, payload))
                continue
            pending.append([[i], "create" if self.create_only else "index",
                            index, doc_id, payload, None, payload])
        pending = self._coalesce(pending)
        if alerts:
            self._plan_alerts(alerts, pending, fallback, results)
        self._flush(pending, results, fallback)
        for positions, index, doc_id, payload in fallback:
            try:
                _index_alert_preserving_triage(self.store, index, doc_id, payload, strict=True)
            except Exception as exc:  # noqa: BLE001 - per-item failure -> unacked
                for pos in positions:
                    results[pos] = exc
        return results

    @staticmethod
    def _coalesce(pending: list) -> list:
        """One item per (index, doc_id) per batch. "Current state" topics
        (incidents, entity.updates, incident.graph) can carry several versions of
        one id in a read pass; sending them separately lets an in-process retry of
        an EARLIER version land after a later one succeeded and overwrite it. The
        last payload wins for an upsert (the end state sequential writes reach);
        create-only keeps the first (later creates would only 409). All their
        messages share the one outcome."""
        merged: dict = {}
        for item in pending:
            key = (item[2], item[3])
            prev = merged.get(key)
            if prev is None:
                merged[key] = item
                continue
            prev[0].extend(item[0])
            if item[1] == "index":
                prev[4], prev[6] = item[4], item[6]
        return list(merged.values())

    def _plan_alerts(self, alerts: dict, pending: list, fallback: list, results: list) -> None:
        """Alerts need read-modify-write (keep the analyst's ``triage``), but one
        burst re-emits the SAME alert_id for every event past a threshold. So:
        collapse repeats inside the batch to the last payload (the end state a
        sequential pass would reach), read all current versions with ONE
        ``_mget``, and write the known ones as ONE conditional bulk (``if_seq_no``
        / ``if_primary_term``; a stale version = per-item 409 -> per-document CAS
        retry). Alert ids never seen before take the per-document path, which
        also runs the cross-index routing-drift check."""
        try:
            existing = self.store.mget_versioned(list(alerts))
        except Exception as exc:  # noqa: BLE001 - whole read failed -> unacked
            for positions, _payload in alerts.values():
                for pos in positions:
                    results[pos] = exc
            return
        for key, (positions, payload) in alerts.items():
            found = existing.get(key)
            if found is None or found[1] is None:
                fallback.append((positions, key[0], key[1], payload))
                continue
            current, version = found
            merged = dict(payload)
            if current.get("triage") is not None:
                merged["triage"] = current["triage"]
            pending.append([positions, "index", key[0], key[1], merged, version, payload])

    def _flush(self, pending: list, results: list, fallback: list) -> None:
        attempt = 0
        while pending:
            try:
                outcomes = self.store.bulk_write(
                    [(op, index, doc_id, doc, version)
                     for _p, op, index, doc_id, doc, version, _orig in pending])
                self.stats["bulk_requests"] += 1
                self.stats["bulk_docs"] += len(pending)
            except Exception as exc:  # noqa: BLE001 - whole request failed
                outcomes = [{"status": 503, "error_type": f"request_failed:{type(exc).__name__}",
                             "exc": exc}] * len(pending)
            retry: list = []
            for item, out in zip(pending, outcomes):
                positions, op, index, doc_id, doc, version, orig = item
                status = out["status"]
                if status < 300 or (status == 409 and op == "create"):
                    if status == 409:
                        self.stats["conflicts_409"] += 1
                    continue
                if status == 409 and version is not None:
                    # stale CAS version: someone (analyst triage / another
                    # writer) got in between -> per-document read-merge-retry.
                    # Hand over the ORIGINAL payload: `doc` carries the triage we
                    # read earlier, which would resurrect a triage the analyst
                    # has since cleared.
                    self.stats["cas_conflicts"] += 1
                    fallback.append((positions, index, doc_id, orig))
                    continue
                if status in self._RETRYABLE and attempt < self.retries:
                    retry.append(item)
                    continue
                self.stats["failed_items"] += 1
                err = out.get("exc") or RuntimeError(
                    f"bulk item rejected: HTTP {status} {out.get('error_type')}")
                for pos in positions:
                    results[pos] = err
            pending = retry
            if pending:
                self.stats["retried_items"] += len(pending)
                time.sleep(self.backoff_s * (2 ** attempt))
                attempt += 1


def build_handlers(store, group: str = "cg-index") -> dict:
    """Per-topic ``{topic: (group, handler)}`` map for the live daemon.

    Extracted from ``main()`` so the topic->handler wiring is testable on its
    own: which topics get the create-only handler is a correctness property
    (see :func:`index_doc`), not an implementation detail, and before this was
    a dict comprehension buried inside ``main()`` no test could reach. A
    regression here -- pointing `normalized.events` at the plain handler --
    silently reintroduces the score-stripping double-index race, so it gets a
    test (`test_double_index_order.py::test_normalized_topic_is_wired_create_only`).

    Every handler is a :class:`BatchIndexHandler`; ``shared.runner`` uses its
    ``handle_batch`` (one ``/_bulk`` per read pass) only when the store has
    ``bulk_write``. ``WS3_BULK=0`` is the kill switch: it wraps each handler
    in a plain per-document callable, which has no ``handle_batch`` and so
    keeps the pre-bulk behavior. ``WS3_BULK_MAX`` (default 500) bounds a batch.
    """
    bulk = os.getenv("WS3_BULK", "1").lower() not in ("0", "false", "no") \
        and callable(getattr(store, "bulk_write", None))
    out = {}
    for t in TOPICS:
        h = BatchIndexHandler(store, create_only=(t == "normalized.events"))
        if not bulk:
            h = _single_only(h)
        out[t] = (group, h)
    return out


def _single_only(h: "BatchIndexHandler"):
    """Per-document-only view of ``h`` (no ``handle_batch``), for the
    ``WS3_BULK=0`` kill switch and stores without ``bulk_write``."""
    def handler(payload: dict) -> None:
        h(payload)
    return handler


_ALERT_CAS_MAX_RETRIES = 5


class AlertCasExhausted(RuntimeError):
    """The alert's compare-and-swap lost every retry: the write did NOT land.
    Raised only in ``strict`` mode (the daemon), so the message stays unacked and
    is redelivered, then dead-lettered at the redelivery cap, instead of being
    acked as if written."""


def _index_alert_preserving_triage(store, index: str, doc_id: str, doc: dict,
                                   strict: bool = False) -> bool:
    """`alerts`-topic write for an alert_id that may already be indexed.

    Same failure SHAPE as the normalized/scored siem.score clobber (P1-4),
    a different pair of writers/field: bus delivery is at-least-once, so a
    stale `alerts` message (WS-4's original payload, never carrying `triage`)
    can be redelivered -- e.g. after this worker is killed mid-batch and
    restarted -- and land AFTER an analyst has since set `triage` via
    triage_api.py's independent index_cas-based read-modify-write. A plain
    index() there is a full-document replace and silently erases it; the
    alert stays indexed so nothing looks broken.

    CAS retry loop (mirrors triage_api.py's own _route_triage): read the
    current doc's `triage`, carry it into the incoming payload, write with
    index_cas so a concurrent triage update racing this same write loses
    cleanly (retry) rather than silently.

    Live-stack race fix (2026-08-28): reads by exact `(index, doc_id)` via
    `get_versioned()`, not the cross-index `find_alert_versioned()` this
    used to call. `find_alert_versioned`'s search is bounded by OpenSearch's
    refresh_interval (default 1s); a stateful rule fires on every event once
    past its threshold (`count >= threshold`, not `==`), so one burst can
    emit several `alerts` messages sharing ONE deterministic alert_id
    within milliseconds -- each one's search-based read saw stale (already-
    superseded) state and lost every CAS retry to the write THIS SAME
    process had just made. Live-caught via `fengarde_bench_live.py`: 4/10
    latency bursts never produced a visible alert within 120s, 586
    "exhausted 5 CAS retries" errors in one run. `get_versioned` is a direct
    GET on OpenSearch (immediately consistent, no refresh lag) -- this
    process's own prior write in this same loop is visible to the very next
    iteration.
    """
    for attempt in range(_ALERT_CAS_MAX_RETRIES):
        existing = store.get_versioned(index, doc_id)
        if existing is None:
            # Not found at the KNOWN expected index -- but that alone doesn't
            # rule out routing drift (the same alert_id landing under a
            # DIFFERENT index on an earlier delivery, e.g. a day-boundary
            # rollover). Only pay for the slower cross-index search on this
            # (rare) miss path, never on the hot repeat-write path above,
            # which get_versioned already resolves immediately-consistently.
            drift = store.find_alert_versioned(doc_id)
            if drift is not None and drift[0] != index:
                from shared.log import get_logger  # noqa: E402
                get_logger("ws3-indexer").warn(
                    f"alert {doc_id} already indexed under {drift[0]}, not "
                    f"{index} -- skipping write (routing drift, not a "
                    f"transient conflict)"
                )
                return False
            # Brand-new alert_id: a CREATE. Route it through index_cas with
            # version=None -- BOTH backends treat that as an unconditional
            # write (byte-identical to the plain store.index() this used to
            # call), but every alerts write now goes through the CAS path, so
            # a concurrent writer landing between this read and the write is
            # resolved deterministically instead of only the update path
            # being guarded. (Gap-hunt finding R2-#23.)
            return store.index_cas(index, doc_id, doc, None)
        existing_doc, version = existing
        # Carry any existing `triage` into the incoming payload. When the
        # stored doc has no triage yet there is nothing to preserve -- but we
        # STILL write conditionally on `version`: an analyst triage write that
        # lands between our read and this write bumps the version, our
        # index_cas returns False, and the retry loop re-reads the fresh doc
        # and carries that triage. The plain store.index() this branch used
        # to call would silently destroy it. (Gap-hunt finding R2-#19.)
        merged = dict(doc)
        existing_triage = existing_doc.get("triage")
        if existing_triage is not None:
            merged["triage"] = existing_triage
        if store.index_cas(index, doc_id, merged, version):
            return False
        if attempt < _ALERT_CAS_MAX_RETRIES - 1:
            time.sleep(0.05 * (2 ** attempt))
    # Retries exhausted under sustained CAS contention: no-write rather than a
    # destructive overwrite, but this is a DISTINCT failure from "an update
    # succeeded" -- both used to return False and land in run()'s same
    # `duplicates` bucket, making a genuinely lost write indistinguishable
    # from a benign redelivery (review finding, 2026-08-27). Log it loudly;
    # callers still get False (fail-safe: no-write, never a clobber).
    from shared.log import get_logger  # noqa: E402
    get_logger("ws3-indexer").error(
        f"alert {doc_id} in {index}: exhausted {_ALERT_CAS_MAX_RETRIES} CAS "
        f"retries under contention -- this write did NOT land (no-write, not "
        f"a clobber, but distinct from a benign duplicate)")
    if strict:
        raise AlertCasExhausted(f"alert {doc_id} in {index}: CAS retries exhausted")
    return False


def index_doc(store, doc: dict, *, create_only: bool = False, strict: bool = False) -> bool:
    """Route ``doc`` and write it.

    ``create_only=True`` writes only when nothing is stored under that id yet
    (see StorageAdapter.index_if_absent). Used for `normalized.events`, whose
    write must never overwrite the scored copy of the same event -- both
    topics route to the same (index, doc_id) and run on independent worker
    threads, so without this the later-arriving normalized write silently
    strips `siem.score` off an already-scored document.

    An alert doc (``alert_id`` present) never uses create_only -- a
    redelivered alert must still be able to create the doc on first arrival
    -- but does go through :func:`_index_alert_preserving_triage` so a stale
    redelivery can't clobber a `triage` field a completely different writer
    (the triage API) has since set.
    """
    index, doc_id = route(doc)
    if create_only:
        return store.index_if_absent(index, doc_id, doc)
    if "alert_id" in doc:
        return _index_alert_preserving_triage(store, index, doc_id, doc, strict=strict)
    return store.index(index, doc_id, doc)


def run(bus, store) -> dict:
    """Drain every topic and index every message.

    P1-4 (2026-07-21 audit): when the store supports batch indexing
    (OpenSearchStore.bulk_index -- MemoryStore does not), each topic's
    messages are routed then indexed in ONE /_bulk request instead of one
    HTTP PUT per doc. Safe here specifically because this is the batch/
    tooling path (tools/integration_e2e.py, demo_e2e.py, tests) -- it drains
    a topic fully before returning and has no per-message ack tied to a live
    Redis PEL to preserve (unlike the daemon's handler(), which still
    indexes one doc per call -- see storage/opensearch.py's module
    docstring for why that path is NOT batched this pass).
    """
    stats = {"indexed": 0, "duplicates": 0, "unroutable": 0}
    bulk_index = getattr(store, "bulk_index", None)
    for topic in TOPICS:
        msgs = list(bus.consume(topic, group="cg-index"))
        if not msgs:
            continue
        if bulk_index is None:
            for msg in msgs:
                try:
                    created = index_doc(store, msg.payload)
                except ValueError:
                    stats["unroutable"] += 1
                    continue
                stats["indexed" if created else "duplicates"] += 1
            continue

        items = []
        for msg in msgs:
            try:
                routed_index, doc_id = route(msg.payload)
            except ValueError:
                stats["unroutable"] += 1
                continue
            payload = msg.payload
            # Gap-hunt finding (2026-08-23): the batch bulk_index path used
            # to bypass _index_alert_preserving_triage entirely, sending
            # alert docs straight to _bulk where any stale redelivery would
            # clobber a triage field an analyst had just set (same race class
            # as the per-message handler above -- this is the batch/tooling
            # path this function's own docstring describes, not the daemon's
            # live handler() path; review finding, 2026-08-27, corrects the
            # prior wording here which mislabeled it "live-production").
            if "alert_id" in payload:
                created = _index_alert_preserving_triage(
                    store, routed_index, doc_id, payload)
                stats["indexed" if created else "duplicates"] += 1
            else:
                items.append((routed_index, doc_id, payload))
        if not items:
            continue
        result = bulk_index(items)
        for r in result["results"]:
            stats["indexed" if r["created"] else "duplicates"] += 1
        # A per-item /_bulk failure (e.g. a mapping conflict on one doc) is
        # NOT an "unroutable" document -- it routed fine, OpenSearch itself
        # rejected the write. Distinct failure class; not silently folded
        # into either existing counter.
        if result["errors"]:
            stats["bulk_errors"] = stats.get("bulk_errors", 0) + len(result["errors"])
    return stats


# P0-5 (2026-07-21 audit): the full bus-topics.md topic list, reaped from here
# regardless of which of these WS-3 itself consumes -- trim_acked() queries
# Redis's XINFO GROUPS/XPENDING directly (a global view of every consumer
# group on a stream, not just the caller's own), so correctness only needs
# ONE service to run the reaper, not one per producer/consumer. WS-3 is the
# most terminal/always-running service, so it owns this. `.deadletter`
# siblings are excluded by start_stream_reaper itself.
#
# entity.updates/incident.graph (2026-09-02 review): added after WP-2's
# entity-plane work (WS-8/WS-9) started producing onto these two topics
# without this list being updated -- the reaper never trimmed either stream,
# an unbounded-growth vector in the live Redis stack identical to the one
# this whole list exists to prevent. Phase 5 (2026-09-04): both are now ALSO
# real `TOPICS` entries above (indexed via GET /entities/{id} and
# GET /incidents/{id}/graph) -- this list stays because the reaper's job
# (bound the RAW STREAM length) is orthogonal to whether a queryable
# document exists; a consumer group ack doesn't trim the stream itself.
_ALL_BUS_TOPICS = ["raw.events", "normalized.events", "scored.events",
                   "ai.requests", "ai.results", "alerts", "assets.updates",
                   "incidents", "entity.updates", "incident.graph"]


def main():
    # FIX 6: refuse to boot default-open when FENGARDE_REQUIRE_AUTH=1 but the
    # configured auth surface is incomplete (see shared/authz.py). No-op
    # unless FENGARDE_REQUIRE_AUTH is set to 1/true/yes.
    require_auth_or_die("ws3-indexer")

    # Daemon (T0): one worker thread PER topic (the runner handles the 4-topic
    # fan-in that a single blocking loop would starve). run() above stays the batch
    # path used by tests / the e2e harness. The store is shared across the 4 topic
    # threads; MemoryStore is dict-based (fine for dev), OpenSearchStore is the real
    # backend in compose.
    import threading  # noqa: E402

    from shared.bus import Bus  # noqa: E402
    from shared.log import get_logger  # noqa: E402
    from shared.runner import serve, start_stream_reaper  # noqa: E402
    import triage_api  # noqa: E402
    import webhooks  # noqa: E402

    store = make_store()

    # C1 (v0.3): the triage API runs on its OWN port/thread, alongside the bus
    # consumer loop -- mirrors how WS-1 runs its UDP listener alongside the
    # runner's health thread (a second independent network listener, not
    # routed through the runner, which only owns bus consume loops + /health).
    triage_thread = threading.Thread(
        target=triage_api.serve,
        args=(store,),
        kwargs={"port": int(os.getenv("TRIAGE_PORT", "8013"))},
        daemon=True,
    )
    triage_thread.start()

    # M4.4: outbound webhooks are opt-in (contracts/webhooks/*.yml). No
    # configs -> no thread started at all, zero behavior change. When
    # present, dispatch runs under its OWN consumer group (cg-webhook) on
    # the SAME `alerts` topic WS-3 already indexes under cg-index -- two
    # independent Streams readers, so a slow/down webhook receiver can never
    # delay or duplicate indexing (webhooks.py's module docstring).
    webhook_configs = webhooks.load_webhook_configs()
    if webhook_configs:
        def webhook_handler(payload: dict) -> None:
            webhooks.dispatch_alert(webhook_configs, payload)

        webhook_thread = threading.Thread(
            target=serve,
            args=({"alerts": ("cg-webhook", webhook_handler)},),
            # install_signal_handlers=False: signal.signal() only works on
            # the main thread: the primary serve() call below (main thread)
            # already owns SIGTERM/SIGINT for the whole process.
            kwargs={"health_port": None, "service_name": "ws3-webhooks",
                    "install_signal_handlers": False},
            daemon=True,
        )
        webhook_thread.start()

    # P0-5: reap acked-by-every-group stream entries so Redis memory doesn't
    # grow unboundedly forever (live-proven: raw.events XLEN stayed frozen
    # after a full drain with nothing ever calling XTRIM). Interval is
    # deliberately coarser than the depth watchdog's -- trimming is cheap but
    # not free (XINFO GROUPS + XPENDING per group per topic).
    log = get_logger("ws3-indexer")
    shutdown = threading.Event()
    reap_interval = float(os.getenv("STREAM_REAP_INTERVAL_S", "300"))
    reaper = start_stream_reaper(Bus(), log, shutdown, _ALL_BUS_TOPICS,
                                 interval_s=reap_interval)

    handlers = build_handlers(store)
    try:
        def bulk_metrics() -> dict:
            return {"bulk": {t: dict(h.stats) for t, (_g, h) in handlers.items()
                             if isinstance(h, BatchIndexHandler)}}

        serve(handlers, health_port=int(os.getenv("PORT", "8003")),
              service_name="ws3-indexer", shutdown=shutdown,
              metrics_provider=bulk_metrics)
    finally:
        shutdown.set()
        if reaper is not None:
            reaper.join(timeout=5)


if __name__ == "__main__":
    main()
