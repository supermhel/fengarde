"""WS-8 Correlation entrypoint.

Consume `alerts` (as a SECOND, independent consumer group alongside WS-3's
`cg-index` -- see contracts/bus-topics.md), track per-entity activity over a
long horizon, and produce `incidents` when a track shows real multi-stage
(>=2 distinct MITRE tactic) evidence. Never imports WS-3 or WS-4 (bus-only
coupling, ADR 004/007) -- see correlator.py for the engine and INTERFACE.md
for the full contract.
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
from correlator import Correlator, DEFAULT_HORIZON_S, DEFAULT_MEMBER_CAP  # noqa: E402


def make_correlator() -> Correlator:
    horizon_s = int(os.getenv("CORRELATION_HORIZON_SECONDS", str(DEFAULT_HORIZON_S)))
    member_cap = int(os.getenv("CORRELATION_MEMBER_CAP", str(DEFAULT_MEMBER_CAP)))
    window_counter = None
    if os.getenv("BUS_BACKEND", "memory").lower() == "redis":
        import redis
        from shared.window import RedisWindowCounter
        # decode_responses=True is required, not cosmetic: found live
        # (2026-08-18) that without it, ZRANGE returns bytes from
        # RedisWindowCounter.members(), which then never string-equal the
        # plain-str alert_ids correlator.py's side table is keyed by --
        # every track silently lost all its members on the next hit,
        # so nothing ever promoted on real Redis (zero-infra tests never
        # caught this: DequeWindowCounter preserves whatever type is
        # given). Matches every other real-Redis client construction in
        # this repo (services/ws4-detection/main.py x3, shared/bus.py x2).
        client = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"),
                                 decode_responses=True)
        # ws8's OWN Redis zset namespace -- NOT the ws4:win default. The
        # reference review flagged the shared default as a latent collision
        # (a future WS-4 rule group or WS-8 entity type could collide in the
        # same zset); INTERFACE.md documents the key prefix as ws8:corr.
        window_counter = RedisWindowCounter(client, namespace="ws8:corr")
    return Correlator(window_counter, horizon_s=horizon_s, member_cap=member_cap)


def make_handler(bus, correlator: Correlator):
    def handle_alert(payload: dict) -> None:
        for incident in correlator.ingest_alert(payload):
            bus.produce("incidents", key=incident["incident_id"], payload=incident)
            # WP-2-C / ADR-009: emit the incident's relationship graph on its
            # own topic so consumers (WS-9, WS-3) can actually see it. The
            # graph is computed and cached inside the correlator; this is the
            # production wiring that makes it reachable (independent-review
            # finding: the feature existed but was never produced on the bus).
            graph = correlator.incident_graph(incident["incident_id"])
            if graph is not None:
                bus.produce("incident.graph",
                            key=incident["incident_id"], payload=graph)
    return handle_alert


if __name__ == "__main__":
    correlator = make_correlator()
    bus = Bus()
    handlers = {"alerts": ("cg-correlate", make_handler(bus, correlator))}
    serve(handlers, health_port=int(os.getenv("PORT", "8008")),
          service_name="ws8-correlation", metrics_provider=correlator.metrics)
