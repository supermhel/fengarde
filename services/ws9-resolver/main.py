"""WS-9 Entity Resolver entrypoint (WP-2-B, ADR-009).

**SAFETY (control-path statement): WS-9 is a resolver/analyzer -- an
information plane, NOT a control path.** It never decides or issues an
action. It cannot block, drop, suppress, quarantine, or modify any alert,
event, incident, or rule; it holds no authority over any other workstream.
Its only output is resolved ENTITY STATE on the `entity.updates` topic. Every
control decision (fire a rule, promote an incident, take an action) stays with
WS-4 / WS-8 / the analyst.

Bus contract (ADR-009 Topic A / contracts/bus-topics.md):
  consume  `alerts`          (group `cg-entity`)  -- WS-4/WS-5 enriched alerts
  produce  `entity.updates`  keyed by `entity_id` -- {entity_id, entity_type,
           tenant_id, entity_value, first_seen_ms, last_seen_ms, attributes}
  consume  `entity.updates`  (group `cg-entity-self`) -- WS-6 inventory asset
           sightings feed our own store; the apply is the ADR no-op upsert, so
           a redelivered/replayed entity.updates changes nothing (returns no-op).

Source-topic choice: `alerts`, not `normalized.events` or `incidents`.
  - `normalized.events` is every benign event -- the entity plane would resolve
    non-security noise at full pipeline volume for no analyst value.
  - `incidents` are already WS-8's aggregated, promoted view -- too late and
    collapsed (one incident per track, entities already joined).
  - `alerts` is the first bus message carrying exactly the enriched, correlated
    entity fields the plane needs (actor / src+dst / device), at the volume the
    "what else did this actor touch?" question actually targets. It also lets
    WS-9 sit alongside WS-8's `cg-correlate` as an independent consumer group
    on the SAME topic -- bus-only coupling, ADR 004, exactly as WS-8 did.

Zero-infra by default (BUS_BACKEND=memory); BUS_BACKEND=redis for the Docker
profile, same as every other service.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))

from shared.bus import Bus  # noqa: E402
from shared.runner import serve  # noqa: E402

from resolver import DEFAULT_MEMBER_CAP, EntityResolver  # noqa: E402


def make_resolver() -> EntityResolver:
    member_cap = int(os.getenv("ENTITY_MEMBER_CAP", str(DEFAULT_MEMBER_CAP)))
    return EntityResolver(member_cap=member_cap)


def make_handler(bus, resolver: EntityResolver):
    """The `alerts` handler: resolve -> emit one entity.updates per entity,
    keyed by the deterministic entity_id (the ADR partition key)."""
    def handle_alert(payload: dict) -> None:
        for update in resolver.resolve_alert(payload):
            bus.produce("entity.updates", key=update["entity_id"], payload=update)
    return handle_alert


def make_self_handler(resolver: EntityResolver):
    """The `entity.updates` self-consumer: merge WS-6's (or a replayed) update
    into our store under the ADR no-op rule -- a non-newer last_seen_ms is a
    no-op, so at-least-once redelivery of our own or WS-6's payload is safe."""
    def handle_update(payload: dict) -> None:
        resolver.apply_update(payload)
    return handle_update


if __name__ == "__main__":
    resolver = make_resolver()
    bus = Bus()
    handlers = {
        "alerts": ("cg-entity", make_handler(bus, resolver)),
        "entity.updates": ("cg-entity-self", make_self_handler(resolver)),
    }
    serve(handlers, health_port=int(os.getenv("PORT", "8009")),
          service_name="ws9-resolver", metrics_provider=resolver.metrics)
