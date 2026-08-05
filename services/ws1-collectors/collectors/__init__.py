"""WS-1 pluggable collector modules.

Each collector ingests raw events from one protocol and yields raw payloads of
the shape ``{"source_type", "raw", "meta"}`` (Contract B, topic ``raw.events``).
Collectors do NOT normalize to OCSF — that is WS-2's job.

Every collector exposes:
  * a ``SOURCE_TYPE`` class attribute (string identifying the protocol/product),
  * either ``handle_line(line)`` (push/streaming sources like syslog) or
    ``poll()`` (pull sources like SNMP / NetFlow file readers),
  * an optional ``asset_observations()`` generator yielding
    ``{"mac", "ip", "hostname", "seen_at"}`` dicts for the ``assets.updates`` topic.

**A collector must only yield an observation when it actually has a MAC.**
``contracts/bus-topics.md`` names ``mac`` as ``assets.updates``' partition key,
and the topic's only consumer (WS-6) keys inventory on it -- an observation
without a MAC cannot be stored and is discarded on arrival, so emitting one is
bus traffic plus a misleading warning, never an inventory update. Collectors
that cannot see a MAC abstain entirely rather than yielding ``mac: None``:
``netflow_collector`` has always done this, and ``syslog_collector`` does too
since 2026-08-05 (it previously emitted macless observations that were 100%
dropped -- see its ``handle_line`` comment). Enforced by
``test_asset_observations.py``.

A produced raw payload looks like::

    {
        "source_type": "syslog_rfc5424",
        "raw": "<134>1 2024-... host app - - - message",
        "meta": {"ip": "10.0.0.5", "transport": "udp", "received_at": 1750000000},
    }

The partition key for ``raw.events`` is the source IP, read from ``meta["ip"]``.
"""
