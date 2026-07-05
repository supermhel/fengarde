"""WS-2 Normalization entrypoint.

Consume ``raw.events`` -> parse via the per-source registry -> validate against
Contract A -> produce ``normalized.events`` (partition key = src_endpoint.ip).
Invalid events are dropped to a dead-letter topic instead of poisoning the stream.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))      # for `parsers`
sys.path.insert(0, str(SERVICES))  # for `shared`

from shared.bus import Bus  # noqa: E402
from shared.ocsf import validate  # noqa: E402
from parsers import resolve  # noqa: E402
from enrichment import enrich  # noqa: E402


def normalize_one(raw_payload: dict):
    """Return (event, errors). event is None if no parser / unparseable.

    Pipeline: parse -> A5 enrich (additive, offline, fail-open) -> validate.
    Enrichment runs before validate so the enriched event is what's checked
    against Contract A, but it only ADDS optional src_endpoint.reputation/
    location -- an event validates identically whether or not a data match adds
    a field.
    """
    parser = resolve(raw_payload)
    if parser is None:
        st = raw_payload.get("source_type", "")
        # Discoverability (DX): name the source and point at the v0.1 scope so an
        # unknown source reads as "deferred", not "broken". 5 parsers ship in v0.2.
        return None, [f"no parser for source_type={st!r} "
                      f"(v0.1 ships 4 parsers; see README 'What's real in v0.1')"]
    event = parser.parse(raw_payload)
    if event is None:
        return None, ["parser returned None"]
    event = enrich(event)
    return event, validate(event)


def run(bus) -> dict:
    stats = {"normalized": 0, "dropped": 0}
    for msg in bus.consume("raw.events", group="cg-normalize"):
        event, errors = normalize_one(msg.payload)
        if event is None or errors:
            bus.produce("raw.events.deadletter", key=msg.key,
                        payload={"raw": msg.payload, "errors": errors})
            stats["dropped"] += 1
            continue
        key = (event.get("src_endpoint") or {}).get("ip", "0.0.0.0")
        bus.produce("normalized.events", key=key, payload=event)
        stats["normalized"] += 1
    return stats


def main():
    # Daemon (T0): consume raw.events via the shared runner. run() above stays the
    # batch path used by tests / the e2e harness.
    from shared.runner import serve  # noqa: E402

    def handler(payload: dict) -> None:
        bus = Bus()
        event, errors = normalize_one(payload)
        if event is None or errors:
            bus.produce("raw.events.deadletter", key=None,
                        payload={"raw": payload, "errors": errors})
            return
        key = (event.get("src_endpoint") or {}).get("ip", "0.0.0.0")
        bus.produce("normalized.events", key=key, payload=event)

    serve({"raw.events": ("cg-normalize", handler)},
          health_port=int(os.getenv("PORT", "8002")), service_name="ws2-normalization")


if __name__ == "__main__":
    main()
