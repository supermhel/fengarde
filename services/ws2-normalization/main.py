"""WS-2 Normalization entrypoint.

Consume ``raw.events`` -> parse via the per-source registry -> validate against
Contract A -> produce ``normalized.events`` (partition key = src_endpoint.ip).
Invalid events are dropped to a dead-letter topic instead of poisoning the stream.
"""
from __future__ import annotations

import os
import sys
import time as _time
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


def _int_env(name: str, default: int, log, *, crash_on_bad: bool = False) -> int:
    """Read an int env var, degrading to ``default`` on a malformed value.

    Mirrors ws1-collectors/main.py::_int_env (NEWS hunt #4): the previous
    bare ``int(os.getenv(...))`` raised ``ValueError`` on a typo'd tuning knob
    and killed the daemon at startup. Tuning values degrade-to-default-logged
    instead; ``crash_on_bad`` keeps the opt-in loud path for bind ports. ``log``
    may be None to skip the degradation warning (tests)."""
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        if crash_on_bad:
            raise
        if log is not None:
            log.warn("malformed env var, using default",
                     name=name, value=raw, default=default)
        return default

# Free-text fields any parser may populate from raw, attacker-controlled log
# content -- sanitized uniformly here (one choke point for all 17 parsers)
# rather than in each parser individually. (path, is_list) where is_list means
# "a list of dicts with this key", used for actor.user/process which some
# parsers may extend; today none do, so this stays a flat dotted-path walk.
_FREE_TEXT_PATHS = (
    ("message",),
    ("actor", "user", "name"),
    ("actor", "user", "domain"),
    ("actor", "user", "uid"),
    ("actor", "process", "name"),
    ("src_endpoint", "hostname"),
    ("dst_endpoint", "hostname"),
    # "*" is a wildcard leaf: every string anywhere under the `unmapped` dict
    # is sanitized (any prefix -- unmapped.mcp.*, unmapped.ot.*, unmapped.db.*),
    # no matter how deep, since parsers copy attacker-controlled raw payload
    # bytes into unmapped.* verbatim.
    ("unmapped", "*"),
    # api.request.data carries arbitrary request bodies parsers forward as
    # free text; sanitize it too (M1 gap fix).
    ("api", "request", "data"),
    # api.operation carries a raw tool-name / event-type string parsers copy
    # verbatim from attacker-controlled content (mcp_agent str(tool),
    # n8n_audit str(event_type), opcua_audit event_type) -- a mapped, non-
    # unmapped field it shares with api.request.data, so it needs an explicit
    # path of its own (WP-2-G: was reaching downstream unsanitized).
    ("api", "operation"),
)


def _sanitize_tree(value: Any) -> Any:
    """Recursively strip ANSI/control chars from every string leaf under a
    nested dict/list tree. Used for the ``("unmapped", "*")`` wildcard so ANY
    key under ``unmapped`` -- at arbitrary depth -- is covered, not just a
    fixed set of dotted paths. Non-string values pass through unchanged; the
    tree is mutated in place (mirrors the rest of the walker)."""
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(v, str):
                value[k] = strip_ansi_and_control(v)
            else:
                _sanitize_tree(v)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            if isinstance(v, str):
                value[i] = strip_ansi_and_control(v)
            else:
                _sanitize_tree(v)
    return value


def _sanitize_free_text(event: dict) -> dict:
    """M1 log-injection defense (PLAN_C Tier 1.2): strip ANSI escapes and C0
    control chars from every OCSF free-text field a parser may have populated
    from raw log content, so a hostile hostname/username/message can't forge
    terminal output (tools/dlq_peek.py, docker logs) or inject a fake extra
    log line downstream. Complements (does not replace) the dashboard's HTML
    escaping, which covers browser DOM XSS, not terminal/log-sink injection.
    A leaf of ``"*"`` triggers a full recursive strip of that subtree (the
    ``unmapped.*`` wildcard)."""
    node = event
    for *path, leaf in (p for p in _FREE_TEXT_PATHS):
        cursor: Any = node
        for key in path:
            cursor = cursor.get(key) if isinstance(cursor, dict) else None
            if cursor is None:
                break
        if cursor is None:
            continue
        if leaf == "*":
            if isinstance(cursor, (dict, list)):
                # The wildcard must recurse into a top-level unmapped LIST as
                # well as a dict (NEWS hunt #5): before this fix a producer
                # putting an array under `unmapped` skipped the whole subtree
                # and hostile control chars/ANSI survived into downstream
                # sinks. Mirror the explicit-path handling below, which
                # recurses on any dict/list value.
                _sanitize_tree(cursor)
            continue
        if isinstance(cursor, dict) and leaf in cursor:
            v = cursor[leaf]
            if isinstance(v, (dict, list)):
                # An explicit (non-wildcard) path whose value turned out to be
                # a nested structure rather than a plain string -- e.g. a
                # future/malformed producer putting a dict under
                # api.request.data instead of the documented string. Recurse
                # the same as the "*" wildcard rather than silently passing
                # it through: strip_ansi_and_control() only sanitizes str and
                # no-ops on dict/list, so without this a nested shape at an
                # explicit path would reach downstream sinks unsanitized.
                _sanitize_tree(v)
            else:
                cursor[leaf] = strip_ansi_and_control(v)
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


def _deadletter_key(payload: dict, msg_key: Any = None) -> Any:
    """Recover the original ``raw.events`` partition key from the payload
    alone, so the daemon's ``handler`` (which only receives the payload, not
    the bus Message) and the batch ``run()`` produce IDENTICAL dead-letter
    keys (gap-hunt finding: handler() set key=None while run() passed
    msg.key -- the two parallel implementations had already diverged).

    WS-1 partitions ``raw.events`` by ``meta.ip`` (ws1-collectors/main.py
    produces with ``key=payload[\"meta\"][\"ip\"]``), WS-6 by ``meta.mac``
    (contracts/bus-topics.md) -- both live in the payload itself, so this is
    the ORIGINAL message key, not a proxy. ``msg_key`` is only a fallback
    for callers that have the real key in hand and the payload doesn't carry
    it (a synthetic producer with a key that isn't in meta)."""
    if isinstance(payload, dict):
        meta = payload.get("meta")
        if isinstance(meta, dict):
            for k in ("ip", "mac"):
                v = meta.get(k)
                if isinstance(v, str) and v:
                    return v
    return msg_key


def _deadletter_payload(payload: dict, errors: list, key: Any) -> dict:
    """Build the requeueable WS-2 dead-letter payload (gap-hunt finding:
    the old shape ``{"raw": payload, "errors": errors}`` re-wrapped the
    original ``raw.events`` payload under ``raw``, so when
    ``tools/dlq_peek.py --requeue`` re-produced the entry verbatim back to
    ``raw.events``, the consumer saw a payload with no ``source_type`` and
    mis-dead-lettered it with \"no parser\" -- even after the root cause was
    fixed -- while dlq_peek happily reported success.

    New shape: the ORIGINAL raw.events payload carried verbatim (top-level
    ``source_type``/``raw``/``meta`` unchanged, so a requeued entry re-enters
    the exact same parser path) plus additive metadata:
      - ``errors`` -- kept TOP-LEVEL (eval/detection_accuracy/evtx_eval.py
        reads ``dead[0].get(\"errors\")``; breaking that is not allowed).
      - ``deadletter`` -- stage/key/timestamp for dlq_peek inspection.
    """
    base = dict(payload) if isinstance(payload, dict) else {"raw": payload}
    base["errors"] = list(errors) if errors else []
    base["deadletter"] = {
        "stage": "ws2-normalization",
        "key": key,
        "deadlettered_at": int(_time.time() * 1000),
    }
    return base


def _process(bus, msg_key: Any, payload: dict,
             stats: dict | None = None, log=None) -> dict | None:
    """One ``raw.events`` message through the whole pipeline. THE single code
    path for both entry points -- ``run()`` (batch/tests) and the daemon
    handler (via ``make_handler``) -- so the gap-hunt divergence (dead-letter
    key set vs None, drops counted as acked with no log line) is structurally
    impossible: whatever one does, both do.

    Returns the normalized event, or ``None`` if the message was
    dead-lettered (already produced to ``raw.events.deadletter``). Dead-letters
    are counted in ``stats[\"dropped\"]`` (when stats given) and warn-logged."""
    event, errors = normalize_one(payload)
    if event is None or errors:
        dlq_key = _deadletter_key(payload, msg_key)
        bus.produce("raw.events.deadletter", key=dlq_key,
                    payload=_deadletter_payload(payload, errors, dlq_key))
        if stats is not None:
            stats["dropped"] += 1
        if log is not None:
            log.warn("deadlettered raw.events", key=dlq_key,
                     error=errors[0] if errors else "invalid event")
        return None
    key = (event.get("src_endpoint") or {}).get("ip", "0.0.0.0")
    bus.produce("normalized.events", key=key, payload=event)
    if stats is not None:
        stats["normalized"] += 1
    return event


def make_handler(bus, stats: dict | None = None, log=None):
    """Daemon entry point for shared/runner.py's ``serve`` (handler signature
    ``handler(payload: dict) -> None``). Funnels every message through
    ``_process`` -- the same code path ``run()`` uses -- so the daemon and
    the tested batch path cannot drift apart again. ``stats`` (a mutable
    ``{\"normalized\": int, \"dropped\": int}`` dict) is the daemon's explicit
    dropped/deadletter+counter, observable via serve()'s ``metrics_provider``.
    """
    def handler(payload: dict) -> None:
        _process(bus, None, payload, stats=stats, log=log)
    return handler


def run(bus) -> dict:
    stats = {"normalized": 0, "dropped": 0}
    from shared.log import get_logger  # noqa: E402
    log = get_logger("ws2-normalization")
    for msg in bus.consume("raw.events", group="cg-normalize"):
        _process(bus, msg.key, msg.payload, stats=stats, log=log)
    return stats


def main():
    # Daemon (T0): consume raw.events via the shared runner. run() above stays the
    # batch path used by tests / the e2e harness. BOTH funnel through _process
    # (via make_handler here) so the daemon and the tested path are one code
    # path -- the 2026-08-26 gap-hunt divergence (dead-letter key set vs None,
    # drops recorded as 'acked' with no counter/log) cannot come back.
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
    log = get_logger("ws2-normalization")
    # Explicit dropped/dead-letter counter for the daemon path (gap-hunt
    # finding: a dead-lettered event used to return normally from the handler,
    # so the runner's /metrics counted it as 'acked' -- no 'dropped' anywhere
    # in the daemon, no log line). The handler runs on exactly one worker
    # thread (one topic), so plain int increments are safe; the /metrics
    # thread only ever READS this dict.
    daemon_stats = {"normalized": 0, "dropped": 0}
    shutdown = threading.Event()

    handler = make_handler(handler_bus, stats=daemon_stats, log=log)

    # P2.4: watch WS-2's own output topic for backpressure buildup (see
    # start_depth_watchdog's docstring for why this is signal-only, never a trim).
    warn_at = _int_env("NORMALIZED_EVENTS_DEPTH_WARN", 100000, log)
    watchdog = start_depth_watchdog(Bus(), log, shutdown, ["normalized.events"],
                                    warn_at=warn_at)
    try:
        serve({"raw.events": ("cg-normalize", handler)},
              health_port=int(os.getenv("PORT", "8002")),
              service_name="ws2-normalization", shutdown=shutdown,
              metrics_provider=lambda: dict(daemon_stats))
    finally:
        if watchdog is not None:
            watchdog.join(timeout=5)


if __name__ == "__main__":
    main()
