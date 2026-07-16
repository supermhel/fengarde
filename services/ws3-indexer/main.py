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
    stats = {"indexed": 0, "duplicates": 0, "unroutable": 0}
    for topic in TOPICS:
        for msg in bus.consume(topic, group="cg-index"):
            try:
                created = index_doc(store, msg.payload)
            except ValueError:
                stats["unroutable"] += 1
                continue
            stats["indexed" if created else "duplicates"] += 1
    return stats


def main():
    # Daemon (T0): one worker thread PER topic (the runner handles the 4-topic
    # fan-in that a single blocking loop would starve). run() above stays the batch
    # path used by tests / the e2e harness. The store is shared across the 4 topic
    # threads; MemoryStore is dict-based (fine for dev), OpenSearchStore is the real
    # backend in compose.
    import threading  # noqa: E402

    from shared.runner import serve  # noqa: E402
    import triage_api  # noqa: E402

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

    handlers = {t: ("cg-index", handler) for t in TOPICS}
    serve(handlers, health_port=int(os.getenv("PORT", "8003")), service_name="ws3-indexer")


if __name__ == "__main__":
    main()
