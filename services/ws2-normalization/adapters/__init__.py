"""WS-2 shipper adapters (WP-1.3): real shipper shapes -> parser-expected input.

Why this exists: the structured parsers (windows_eventlog, sysmon, ...) take
``raw`` as a dict in their OWN key convention (EventID, TimeCreated, Computer,
SubjectUserName, ...). The JSON that Fluent Bit, Winlogbeat or Docker actually
emit is a DIFFERENT shape. An adapter is a pure, total function that rewrites a
shipper record into the dict the target parser already expects, so shippers
can feed ws1's HTTP ingest without any parser change.

Selection: an adapter is chosen by ``meta.shipper`` (the sender labels itself
with ``X-Fengarde-Shipper`` on the HTTP ingest edge; ws1 stamps it into meta)
and, when the label is absent, by deterministic shape detection (``sniffs``).
A record that matches neither is returned UNCHANGED (no-op) — labels and
shapes unknown to this registry must never be mangled.

Contract (all enforced by test_adapters.py):
- ``adapt(payload: dict) -> dict`` never raises on ANY input (None, lists,
  junk, hostile values) — total function.
- The tiny per-family source_type routing is authoritative WITHIN the family:
  windows-shaped records route to sysmon or windows_eventlog by ProviderName /
  EventID (a mixed Security+Sysmon channel is the documented winlog usage),
  journald/docker-shaped records route through generic_syslog so the existing
  text-sniff can hand sshd lines to linux_ssh. All other fields flow through.
- Existing parser fixtures are untouched; adapters run BEFORE resolve() and
  only rewrite records they can positively identify.
"""
from __future__ import annotations

from typing import Optional

from . import docker_json, fluentbit_journald, fluentbit_winevtlog, winlogbeat

#: adapter-id -> module. Adapter ids are the values a sender places in
#: ``meta.shipper`` (X-Fengarde-Shipper header) and the keys of
#: docs/input-adapters.md. Keep the id short and hyphenated.
ADAPTERS = {
    "fluentbit-winevtlog": fluentbit_winevtlog,
    "winlogbeat": winlogbeat,
    "fluentbit-journald": fluentbit_journald,
    "docker-json": docker_json,
}


def _meta(payload) -> Optional[dict]:
    if isinstance(payload, dict):
        m = payload.get("meta")
        return m if isinstance(m, dict) else None
    return None


def _shipper_of(payload) -> Optional[str]:
    m = _meta(payload)
    if m is None:
        return None
    v = m.get("shipper")
    return v if isinstance(v, str) and v else None


def _raw_of(payload) -> object:
    if isinstance(payload, dict):
        return payload.get("raw")
    return None


def adapt_record(payload: dict) -> dict:
    """WS-2 entry: rewrite ONE raw.events payload through the adapter stage.

    Pure and total: unknown shipper + unknown shape -> the payload returned
    unchanged. Never raises; a hostile record is forwarded to the normal
    resolve/parse path (which will dead-letter it with its own errors) rather
    than being dropped or mangled here.
    """
    if not isinstance(payload, dict):
        return payload
    raw = _raw_of(payload)
    if not isinstance(raw, dict):
        return payload  # text lines are not adapter material
    shipper = _shipper_of(payload)
    if shipper in ADAPTERS:
        return ADAPTERS[shipper].adapt(payload)
    # No shipper label: deterministic shape detection. Order matters — a
    # winlogbeat record never looks like a docker record, but be conservative:
    # the first sniffer that positively identifies the shape wins.
    for module in ADAPTERS.values():
        if module.sniffs(raw):
            return module.adapt(payload)
    return payload


__all__ = ["ADAPTERS", "adapt_record"]