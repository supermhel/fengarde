"""Adapter: Fluent Bit ``systemd`` (journald) records -> generic_syslog input.

Fluent Bit's ``systemd`` input emits each journal entry as the record of its
documented fields (per systemd's own ``journal-fields(5)``): ``MESSAGE`` (the
log text), ``_HOSTNAME``, ``_PID``, ``_COMM`` / ``SYSLOG_IDENTIFIER``,
``_SOURCE_REALTIME_TIMESTAMP`` (microseconds since the epoch as a string),
``_TRANSPORT``, ``_SYSTEMD_UNIT``, ...

The parsers read TEXT syslog lines, not field maps — so the adapter rebuilds
the RFC 3164 line the record represents, using ONLY fields present in the
record (nothing is invented):

- ``MESSAGE`` -> the message body;
- ``_HOSTNAME`` -> the host part of the header;
- ``SYSLOG_IDENTIFIER``/``_COMM`` == ``sshd`` -> identifier ``sshd[_PID]:``
  so the existing text-sniff hands auth failures to the ``linux_ssh`` parser
  (journald strips the ``sshd[PID]:`` syslog prefix from MESSAGE);
- ``_SOURCE_REALTIME_TIMESTAMP`` -> RFC 3164 date part;
- any other identifier -> ``<ident>[<_PID>]:`` as present.

Fixture provenance: field NAMES from systemd's ``journal-fields(5)`` manual
(freedesktop.org/software/systemd/man/latest/systemd.journal-fields.html) and
Fluent Bit's ``systemd`` input manual (docs.fluentbit.io); VALUES model an
sshd auth-failure entry (a representative real-world line). SCHEMA-DERIVED,
not a captured specimen — labelled as such per repo honesty rule.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

FIXTURE = {
    "MESSAGE": "Failed password for invalid user admin from 198.51.100.7 "
               "port 51000 ssh2",
    "_HOSTNAME": "web01",
    "_PID": "2154",
    "_COMM": "sshd",
    "SYSLOG_IDENTIFIER": "sshd",
    "_SOURCE_REALTIME_TIMESTAMP": "1673963459303000",
    "_TRANSPORT": "syslog",
    "_SYSTEMD_UNIT": "ssh.service",
}

NON_SSH_FIXTURE = {
    "MESSAGE": "Accepted publickey for jdoe from 203.0.113.9 port 54000 ssh2",
    "_HOSTNAME": "web01",
    "_PID": "2210",
    "SYSLOG_IDENTIFIER": "sshd",
    "_SOURCE_REALTIME_TIMESTAMP": "1673963459304000",
}


def _rfc3164_time(usec) -> Optional[str]:
    if isinstance(usec, bool):
        return None
    try:
        v = int(usec)  # journald usec since epoch, may be a numeric string
    except (TypeError, ValueError, OverflowError):
        return None
    if v <= 0:
        return None
    try:
        dt = datetime.fromtimestamp(v / 1_000_000, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    return dt.strftime("%b %d %H:%M:%S")


SOURCE_TYPES = frozenset({"generic_syslog", "linux_ssh"})


def _ident(raw: dict) -> Optional[str]:
    for key in ("SYSLOG_IDENTIFIER", "_COMM"):
        v = raw.get(key)
        if isinstance(v, str) and v and v != "-":
            return v
    return None


def _pid(raw: dict) -> Optional[str]:
    v = raw.get("_PID")
    if v is None:
        return None
    s = str(v)
    return s if (s.isdigit() or (s.startswith("-") and s[1:].isdigit())) else None


def sniffs(raw) -> bool:
    """journald schema: MESSAGE + at least one journald-only underscore key."""
    if not isinstance(raw, dict):
        return False
    if not isinstance(raw.get("MESSAGE"), str):
        return False
    return any(key in raw for key in
               ("_HOSTNAME", "_COMM", "_PID", "_SYSTEMD_UNIT",
                "_SOURCE_REALTIME_TIMESTAMP", "_TRANSPORT",
                "SYSLOG_IDENTIFIER", "__REALTIME_TIMESTAMP"))


def adapt(payload: dict) -> dict:
    raw = payload.get("raw")
    meta = payload.get("meta") if isinstance(payload, dict) else None
    if not isinstance(raw, dict):
        return payload
    message = raw.get("MESSAGE")
    if not isinstance(message, str):
        return payload
    host = raw.get("_HOSTNAME")
    host = host if isinstance(host, str) and host and host != "-" else None
    if host is None:
        return payload  # no honest host for the header: leave the record unchanged (never put the program in the host slot)
    ident = _ident(raw)
    pid = _pid(raw)
    stamp = _rfc3164_time(raw.get("_SOURCE_REALTIME_TIMESTAMP")
                          or raw.get("__REALTIME_TIMESTAMP"))
    if ident == "sshd":
        ident = f"sshd[{pid}]" if pid else "sshd"
    elif ident and pid:
        ident = f"{ident}[{pid}]"
    header = " ".join(x for x in (stamp, host, ident) if x)
    line = f"{header}: {message}" if header else message
    out_meta = dict(meta) if isinstance(meta, dict) else {}
    if host:
        out_meta.setdefault("hostname", host)
    return {"source_type": "generic_syslog", "raw": line, "meta": out_meta}