"""WS-2 Normalization entrypoint.

Consume ``raw.events`` -> parse via the per-source registry -> validate against
Contract A -> produce ``normalized.events`` (partition key = src_endpoint.ip).
Invalid events are dropped to a dead-letter topic instead of poisoning the stream.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))      # for `parsers`
sys.path.insert(0, str(SERVICES))  # for `shared`

from shared.bus import Bus  # noqa: E402
from shared.ocsf import validate  # noqa: E402
from shared.sanitize import strip_ansi_and_control  # noqa: E402
from parsers import resolve  # noqa: E402
from enrichment import enrich  # noqa: E402

# Free-text fields any parser may populate from raw, attacker-controlled log
# content -- sanitized uniformly here (one choke point for all 10 parsers)
# rather than in each parser individually. (path, is_list) where is_list means
# "a list of dicts with this key", used for actor.user/process which some
# parsers may extend; today none do, so this stays a flat dotted-path walk.
_FREE_TEXT_PATHS = (
    ("message",),
    ("actor", "user", "name"),
    ("actor", "process", "name"),
    ("src_endpoint", "hostname"),
    ("dst_endpoint", "hostname"),
)


def _sanitize_free_text(event: dict) -> dict:
    """M1 log-injection defense (PLAN_C Tier 1.2): strip ANSI escapes and C0
    control chars from every OCSF free-text field a parser may have populated
    from raw log content, so a hostile hostname/username/message can't forge
    terminal output (tools/dlq_peek.py, docker logs) or inject a fake extra
    log line downstream. Complements (does not replace) the dashboard's HTML
    escaping, which covers browser DOM XSS, not terminal/log-sink injection."""
    node = event
    for *path, leaf in (p for p in _FREE_TEXT_PATHS):
        cursor: Any = node
        for key in path:
            cursor = cursor.get(key) if isinstance(cursor, dict) else None
            if cursor is None:
                break
        if isinstance(cursor, dict) and leaf in cursor:
            cursor[leaf] = strip_ansi_and_control(cursor[leaf])
    return event


def normalize_one(raw_payload: dict):
    """Return (event, errors). event is None if no parser / unparseable.

    Pipeline: parse -> sanitize free text (M1) -> A5 enrich (additive, offline,
    fail-open) -> validate. Enrichment runs before validate so the enriched
    event is what's checked against Contract A, but it only ADDS optional
    src_endpoint.reputation/location -- an event validates identically whether
    or not a data match adds a field.
    """
    parser = resolve(raw_payload)
    if parser is None:
        st = raw_payload.get("source_type", "")
        # Discoverability (DX): name the source so an unknown/ambiguous payload
        # reads as "set source_type", not "broken". Content-sniff is best-effort;
        # source_type is authoritative (see parsers.resolve).
        return None, [f"no parser for source_type={st!r} "
                      f"(unknown source, or content-sniff was ambiguous -- set "
                      f"source_type explicitly; see known_sources())"]
    # Defense in depth: a parser bug on hostile input must dead-letter THIS one
    # record, never raise out of normalize_one and abort the whole batch (or
    # poison-pill the daemon into 5x redelivery). Parsers should return None on
    # bad input; this catches the ones that don't.
    try:
        event = parser.parse(raw_payload)
    except Exception as exc:  # noqa: BLE001
        return None, [f"parser {type(parser).__name__} raised: {type(exc).__name__}: {exc}"]
    if event is None:
        return None, ["parser returned None"]
    event = _sanitize_free_text(event)
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
    import threading  # noqa: E402
    from shared.runner import serve, start_depth_watchdog  # noqa: E402
    from shared.log import get_logger  # noqa: E402

    # P1-3 (2026-07-21 audit): ONE Bus() per worker, not one per event. Safe
    # because runner.py's _topic_worker owns exactly one topic per thread and
    # calls this handler serially in a loop on that single thread -- there is
    # no cross-thread sharing to guard against. Constructing Bus() per event
    # on the redis backend meant a fresh redis-py client (fresh TCP connect)
    # per event, the single biggest avoidable per-event cost in this stage.
    handler_bus = Bus()

    def handler(payload: dict) -> None:
        event, errors = normalize_one(payload)
        if event is None or errors:
            handler_bus.produce("raw.events.deadletter", key=None,
                                payload={"raw": payload, "errors": errors})
            return
        key = (event.get("src_endpoint") or {}).get("ip", "0.0.0.0")
        handler_bus.produce("normalized.events", key=key, payload=event)

    # P2.4: watch WS-2's own output topic for backpressure buildup (see
    # start_depth_watchdog's docstring for why this is signal-only, never a trim).
    log = get_logger("ws2-normalization")
    shutdown = threading.Event()
    warn_at = int(os.getenv("NORMALIZED_EVENTS_DEPTH_WARN", "100000"))
    watchdog = start_depth_watchdog(Bus(), log, shutdown, ["normalized.events"],
                                    warn_at=warn_at)
    try:
        serve({"raw.events": ("cg-normalize", handler)},
              health_port=int(os.getenv("PORT", "8002")),
              service_name="ws2-normalization", shutdown=shutdown)
    finally:
        if watchdog is not None:
            watchdog.join(timeout=5)


if __name__ == "__main__":
    main()
