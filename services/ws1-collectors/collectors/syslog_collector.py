"""Syslog collector (RFC 5424, UDP/TCP).

Parses RFC 5424 framed syslog lines into raw payloads. It does NOT normalize to
OCSF; it only does enough light parsing to (a) discover the source IP for the
``raw.events`` partition key and (b) emit an ``assets.updates`` observation when a
hostname is present in the syslog header.

RFC 5424 header layout::

    <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [STRUCTURED-DATA] MSG

The collector is transport-agnostic: a real deployment feeds bytes from a UDP or
TCP socket into :meth:`handle_line`, passing the peer IP. For offline runs the
``meta["ip"]`` falls back to the parsed HOSTNAME if it is an IP literal.
"""
from __future__ import annotations

import re
import time
from typing import Iterator, Optional

from shared.envelope import stamp_meta

# <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP SP PROCID SP MSGID SP (SD|-) SP MSG
_RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d{1,2})\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<app>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<sd>(?:\[[^\]]*\])+|-)\s*"
    r"(?P<msg>.*)$"
)

_IP_LITERAL = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+:[0-9a-fA-F:]+$"
)


class SyslogCollector:
    """Pluggable collector for RFC 5424 syslog lines."""

    SOURCE_TYPE = "syslog_rfc5424"

    def __init__(self, transport: str = "udp"):
        self.transport = transport

    def handle_line(self, line: str, peer_ip: Optional[str] = None) -> Optional[dict]:
        """Parse one syslog line; return a raw payload or ``None`` if unparseable.

        :param line: a single RFC 5424 line (no transport framing).
        :param peer_ip: source IP from the socket, when available. Used as the
            authoritative partition key. Falls back to the parsed HOSTNAME if it
            is an IP literal, else ``"0.0.0.0"``.
        """
        line = line.strip()
        if not line:
            return None

        m = _RFC5424.match(line)
        hostname = None
        if m:
            hostname = None if m.group("hostname") == "-" else m.group("hostname")

        ip = peer_ip
        if ip is None and hostname and _IP_LITERAL.match(hostname):
            ip = hostname
        if ip is None:
            ip = "0.0.0.0"

        received_at = int(time.time())

        meta = {
            "ip": ip,
            "transport": self.transport,
            "received_at": received_at,
        }
        if m:
            meta["hostname"] = hostname
            meta["app"] = None if m.group("app") == "-" else m.group("app")
            meta["pri"] = int(m.group("pri"))
            meta["timestamp"] = m.group("timestamp")
            meta["parsed"] = True
        else:
            meta["parsed"] = False  # leave full normalization to WS-2

        # NO asset observation is emitted here, deliberately -- syslog headers
        # carry no MAC, and `assets.updates` is MAC-keyed.
        #
        # This used to append {"mac": None, "ip": ip, "hostname": hostname, ...}
        # whenever a non-IP hostname was parsed. Live-verified 2026-08-05: every
        # one of those was discarded on arrival. `contracts/bus-topics.md` names
        # `mac` as the topic's partition key, and WS-6's
        # `InventoryStore.upsert_with_diff()` returns None for any observation
        # without one ("inventory is MAC-keyed (Contract C)"), so the consumer
        # logged `assets.updates observation missing mac, dropped` and moved on.
        # Measured on a real stack: 3 of the 5 observations WS-1 seeds at startup
        # were syslog-sourced and 100% of them were dropped, every run. The path
        # was invisible until WS-6's bus consumer was actually wired up, because
        # until then nothing consumed the topic at all.
        #
        # `netflow_collector` already documents this same abstention for the same
        # reason. Emitting a message the only consumer is structurally guaranteed
        # to discard is pure bus traffic plus a misleading warn-log, and it hides
        # a genuine macless bug should one ever appear.
        #
        # Enriching an ALREADY-KNOWN asset from a macless sighting (match the
        # observation's IP against `ip_history` via WS-6's existing
        # `InventoryStore.resolve()`) is a real, useful feature -- tracked
        # separately, not done here. It needs its own handling of DHCP/NAT
        # address reuse, which can otherwise attach a hostname to the wrong
        # device silently. See SSOT.md's 2026-08-05 rows.

        return {"source_type": self.SOURCE_TYPE, "raw": line, "meta": stamp_meta(meta)}

    def poll(self, lines: Iterator[str]) -> Iterator[dict]:
        """Convenience: run :meth:`handle_line` over an iterable of lines."""
        for line in lines:
            payload = self.handle_line(line)
            if payload is not None:
                yield payload

    def asset_observations(self) -> Iterator[dict]:
        """Syslog carries no MAC — yields nothing. Uniform interface.

        Same form as ``netflow_collector`` for the same reason: ``assets
        .updates`` is MAC-keyed and its only consumer discards a macless
        observation, so a collector that cannot see a MAC abstains outright.
        See ``handle_line`` for the measured finding behind this.

        Deliberately NOT a drain loop over an accumulator. This used to be
        ``while self._assets: yield self._assets.pop(0)`` with a ``self._assets``
        list that, once the emission was removed, nothing ever appended to --
        live-looking machinery that reads as a working buffer and invites the
        next person adding an OT or DHCP-derived observation to append to it,
        silently reintroducing a macless emission the collector contract now
        forbids. Returning an empty iterator with no accumulator makes the
        abstention structural rather than incidental.
        """
        return iter(())
