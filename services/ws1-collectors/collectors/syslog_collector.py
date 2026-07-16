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
        # Buffer of asset observations discovered while parsing lines.
        self._assets: list[dict] = []

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

        # Record an asset observation when we have both a hostname and an IP.
        if hostname and not _IP_LITERAL.match(hostname):
            self._assets.append(
                {
                    "mac": None,  # syslog headers carry no MAC
                    "ip": ip,
                    "hostname": hostname,
                    "seen_at": received_at,
                }
            )

        return {"source_type": self.SOURCE_TYPE, "raw": line, "meta": stamp_meta(meta)}

    def poll(self, lines: Iterator[str]) -> Iterator[dict]:
        """Convenience: run :meth:`handle_line` over an iterable of lines."""
        for line in lines:
            payload = self.handle_line(line)
            if payload is not None:
                yield payload

    def asset_observations(self) -> Iterator[dict]:
        """Drain discovered ``assets.updates`` observations (mac/ip/hostname/seen_at)."""
        while self._assets:
            yield self._assets.pop(0)
