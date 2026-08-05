"""M7 Track Y follow-up: WS-6's assets.updates bus consumer.

Closes a gap that predates this feature: contracts/bus-topics.md has named
WS-6 as assets.updates' consumer since Phase 0, and requirements.txt has
carried the dependency ("redis>=5.0  # to also consume assets.updates from
the bus") since F1 -- neither was ever implemented, so the topic has had zero
consumers and WS-6's inventory has had no data path other than direct HTTP
POSTs. This module is that consumer.

Every observation upserts into the same durable, per-tenant InventoryStore
the HTTP POST /assets/upsert path already writes to -- one store, two ways
in. A genuinely alertable first sighting (InventoryStore.upsert_with_diff's
baseline-gated new_device signal, see store.py) is republished onto
raw.events, in the shape services/ws2-normalization/parsers/inventory_diff.py
expects, so ws4-detection's ot_new_device_on_segment rule has a real producer
for the first time.

Only ever imported from ws6-inventory's own ``__main__`` block, and only when
BUS_BACKEND is set. app.py and store.py stay importable -- and testable
zero-infra -- with no dependency on `shared` at all, unchanged.
"""
from __future__ import annotations

from shared.bus import Bus
from shared.log import get_logger
from store import InventoryStore

log = get_logger("ws6-inventory-bus")


def build_notification(obs: dict) -> dict:
    """An assets.updates observation -> the raw shape inventory_diff's parser
    expects. ``sector``/``device_type`` are OT-only fields WS-1's collectors
    never populate on a plain network observation -- left as "" (never
    fabricated as "ot") since a guessed "ot" would wrongly escalate the
    parser's severity for a device that was never actually observed there.
    """
    return {
        "mac": obs.get("mac"),
        "ip": obs.get("ip"),
        "hostname": obs.get("hostname"),
        "device_type": obs.get("device_type", ""),
        "sector": obs.get("sector", ""),
        "seen_at": obs.get("seen_at"),
    }


def make_handler(store: InventoryStore, bus: Bus):
    """A shared.runner.serve()-compatible handler for the assets.updates topic."""

    def handler(payload: dict) -> None:
        asset, is_new_device = store.upsert_with_diff(payload)
        if asset is None:
            log.warn("assets.updates observation missing mac, dropped", payload=payload)
            return
        if not is_new_device:
            return
        notification = build_notification(payload)
        # InventoryStore resolves an absent tenant_id to the real "default"
        # tenant (store.py::_validated_tenant), never empty/None, so this is
        # always the tenant the observation was actually stored under -- not
        # a guess when the observation itself omitted one.
        tenant_id = asset.get("tenant_id")
        meta = {"tenant_id": tenant_id}
        bus.produce(
            "raw.events",
            key=asset["mac"],
            payload={"source_type": "inventory_diff", "raw": notification, "meta": meta},
        )
        log.info(
            "new device detected, published inventory-diff notification",
            mac=asset["mac"], tenant_id=tenant_id,
        )

    return handler


def run_forever(store: InventoryStore) -> None:
    """Entry point for the consumer thread started from app.py's __main__."""
    from shared.runner import serve

    bus = Bus()
    serve(
        {"assets.updates": ("cg-inventory", make_handler(store, bus))},
        health_port=None,
        service_name="ws6-inventory-bus-consumer",
        # This runs on a background thread inside app.py's process; the HTTP
        # server (app.py's serve(), main thread) already owns SIGTERM/SIGINT
        # for the whole process, same convention as ws3-indexer's webhook
        # thread (services/ws3-indexer/main.py).
        install_signal_handlers=False,
    )
