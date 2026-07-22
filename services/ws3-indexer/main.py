"""WS-3 Indexer entrypoint.

Consume normalized.events / scored.events / alerts / ai.results, route each
document to the right index (Contract E), and store it idempotently. Storage
backend is swappable: MemoryStore (default) or OpenSearchStore (BUS-prod).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))

from router import route  # noqa: E402
from storage.memory import MemoryStore  # noqa: E402

TOPICS = ["normalized.events", "scored.events", "alerts", "ai.results"]


def make_store():
    if os.getenv("STORAGE_BACKEND", "memory").lower() == "opensearch":
        from storage.opensearch import OpenSearchStore
        return OpenSearchStore()
    return MemoryStore()


def index_doc(store, doc: dict) -> bool:
    index, doc_id = route(doc)
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
                index, doc_id = route(msg.payload)
            except ValueError:
                stats["unroutable"] += 1
                continue
            items.append((index, doc_id, msg.payload))
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
_ALL_BUS_TOPICS = ["raw.events", "normalized.events", "scored.events",
                   "ai.requests", "ai.results", "alerts", "assets.updates"]


def main():
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

    def handler(payload: dict) -> None:
        try:
            index_doc(store, payload)
        except ValueError:
            pass  # unroutable doc (e.g. ai.results) -> drop, matches run()

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

    handlers = {t: ("cg-index", handler) for t in TOPICS}
    try:
        serve(handlers, health_port=int(os.getenv("PORT", "8003")),
              service_name="ws3-indexer", shutdown=shutdown)
    finally:
        shutdown.set()
        if reaper is not None:
            reaper.join(timeout=5)


if __name__ == "__main__":
    main()
