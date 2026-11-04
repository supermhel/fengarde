"""Adapter: Docker json-file / Fluent Bit container records -> generic_syslog.

Docker's ``json-file`` logging driver writes one JSON object per log line:

    {"log": "Log line is here\\n", "stream": "stdout", "time": "..."}

The WS-2 ``generic_syslog`` parser is RFC-3164-strict (it REQUIRES a
``MMM DD HH:MM:SS host prog: msg`` header and declines headerless text), so a
bare docker line cannot be parsed as-is. The adapter rebuilds the header from
the RECORD'S OWN fields, never from invented ones:

- date part   <- ``time`` (the daemon/container clock, converted ISO->RFC3164);
- ``host``    <- ``docker_id`` first 12 chars (a real container identifier);
- ``prog``    <- ``docker_name`` (or ``docker`` when only the id is present);
- PRI         <- derived from ``stream``: stdout -> ``<14>`` (user.notice),
  stderr -> ``<11>`` (user.err). Stderr IS the error-class stream; documented
  semantic, and the parser maps PRI severity to OCSF severity_id.

A record carrying NEITHER ``docker_id`` NOR ``docker_name`` (the naked
json-file line, no Fluent Bit ``docker`` filter / no ``--log-opt tag`` source)
has no identifier the header could honestly use: the adapter returns the
payload UNCHANGED and it dead-letters with ws2's normal "set source_type"
hint. The shipping recipe therefore points at Fluent Bit's ``tail`` +
``docker`` filter (which adds both ids) — see docs/input-adapters.md.

``time`` is evidence only: it never overrides ``meta.received_at`` (that would
corrupt the Q12/clock-skew semantics) and rides along as ``meta.docker_time``.

Fixture provenance: the byte shape is Docker's OWN canonical example from the
official ``json-file`` driver documentation (docs.docker.com/engine/logging/
drivers/json-file); ``docker_id``/``docker_name`` are the fields Fluent Bit's
``docker`` filter adds (docs.fluentbit.io, "Docker" filter). DOCUMENTED
EXAMPLE, not a local capture — labelled as such per repo honesty rule.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

FIXTURE = {
    "log": "User info: admin@bankcorp.example\n",
    "stream": "stdout",
    "time": "2019-01-01T11:11:11.111111111Z",
    "docker_id": "1d8f02f0f8a9d0c1",   # fluent-bit docker filter, top-level
    "docker_name": "n8n_bankcorp",
}

SSH_FIXTURE = {
    "log": "sshd[731]: Failed password for invalid user root from 198.51.100.23 port 51234 ssh2\n",
    "stream": "stderr",
    "time": "2019-01-01T11:11:12.111111111Z",
    "docker_id": "5f9e2c4a1b8d7e3f",
    "docker_name": "bastion_prod",
}

#: The naked json-file line (no docker filter): NO identifier -> adapter no-op
NO_CONTAINER_FIXTURE = {
    "log": "sshd[731]: Failed password for invalid user root from 198.51.100.23 port 51234 ssh2\n",
    "stream": "stderr",
    "time": "2019-01-01T11:11:12.111111111Z",
}

_PRI = {"stdout": 14, "stderr": 11}  # user.notice / user.err


def sniffs(raw) -> bool:
    """Docker json-file record: the three canonical keys, no journald/winlog."""
    if not isinstance(raw, dict):
        return False
    if "winlog" in raw or "MESSAGE" in raw:  # other families' key signatures
        return False
    return (isinstance(raw.get("log"), str) and "stream" in raw
            and "time" in raw)


def _rfc3164_date(iso: str) -> Optional[str]:
    base = iso[:-1] + "+00:00" if iso.endswith("Z") else iso
    try:
        dt = datetime.fromisoformat(base)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1)  # RFC3164 pads day


def adapt(payload: dict) -> dict:
    raw = payload.get("raw")
    meta = payload.get("meta") if isinstance(payload, dict) else None
    if not isinstance(raw, dict):
        return payload
    message = raw.get("log")
    if not isinstance(message, str):
        return payload
    cid = raw.get("docker_id")
    cname = raw.get("docker_name")
    cid = cid if isinstance(cid, str) and cid else None
    cname = cname if isinstance(cname, str) and cname else None
    raw_time = raw.get("time")
    stamp = _rfc3164_date(raw_time) if isinstance(raw_time, str) else None
    # No identifier (or no useable time) -> nothing honest to build a header
    # from: leave the payload untouched (dead-letters with the normal hint).
    if (cid is None and cname is None) or stamp is None:
        return payload
    host = (cid[:12] if cid else cname)  # real container identifier as host
    prog = cname if cname else "docker"
    stream = raw.get("stream")
    pri = _PRI.get(stream) if isinstance(stream, str) else None
    header = f"<{pri}>" if pri is not None else ""
    line = f"{header}{stamp} {host} {prog}: {message}"
    out_meta = dict(meta) if isinstance(meta, dict) else {}
    if cid:
        out_meta["docker_id"] = cid
    if cname:
        out_meta["docker_name"] = cname
    if isinstance(raw.get("time"), str) and raw["time"]:
        out_meta["docker_time"] = raw["time"]  # evidence only; never the receipt clock
    return {"source_type": "generic_syslog", "raw": line, "meta": out_meta}