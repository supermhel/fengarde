"""Cisco ASA parser: syslog -> OCSF Network Activity (4001).

ASA firewall messages carry a ``%ASA-<sev>-<msgid>:`` tag. We map the
accept/deny semantics to Network Activity activity_ids:

    activity_id 6 = Deny, 7 = Accept   (Contract A / ocsf-classes.md)

Typical built lines::

    %ASA-6-302013: Built outbound TCP connection ... for outside:203.0.113.5/51000 (..) to inside:10.0.0.10/22 (..)
    %ASA-4-106023: Deny tcp src outside:203.0.113.5/51000 dst inside:10.0.0.10/22 by access-group ...

The collector hands us ``{source_type, raw, meta}`` where ``raw`` is the syslog
line and ``meta`` may include ``ip`` / ``timestamp`` / ``received_at``.
"""
from __future__ import annotations

import re
import time
from typing import Optional

from .base import (Parser, SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_HIGH,
                   SEV_CRITICAL, IPV4)

# Cisco ASA syslog severity (0-7) -> OCSF severity_id. The old two-level map
# (<=4 -> MEDIUM else INFO) capped emergency/alert/critical (0/1/2) at MEDIUM,
# losing the most urgent signals; map the full range.
_ASA_SEV_MAP = {
    0: SEV_CRITICAL,  # emergency (system unusable)
    1: SEV_CRITICAL,  # alert
    2: SEV_CRITICAL,  # critical
    3: SEV_HIGH,      # error
    4: SEV_MEDIUM,    # warning
    5: SEV_LOW,       # notification
    6: SEV_INFO,      # informational
    7: SEV_INFO,      # debugging
}

# Cisco ASA syslog tag: %ASA-<sev>-<msgid>: <text>
_ASA_TAG = re.compile(r"%ASA-(?P<sev>\d)-(?P<msgid>\d+):\s*(?P<text>.*)$")

# The endpoint IPs are captured loosely below and validated here, so an
# out-of-range octet in a (possibly injected) log line drops the address instead
# of producing an event that fails Contract A's endpoint pattern (see base.IPV4).
_IPV4_FULL = re.compile(IPV4 + r"\Z")

# Endpoints appear in several ASA syntaxes:
#   ACL deny (106023):        src outside:IP/port ... dst inside:IP/port
#   Built/teardown (302013):  ... for outside:IP/port (..) to inside:IP/port
#   Conn denied (106001/6/15):... denied from IP/port to IP/port   (no "zone:" prefix)
# Source keyword = src|from|for, dest keyword = dst|to, each with an OPTIONAL
# "zone:" prefix (\S*?:) so both the zoned and the bare IP/port forms are captured.
_IPP = r"(?:\S*?:)?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})/(?P<port>\d+)"
_SRC = re.compile(r"\b(?:src|from|for)\s+" + _IPP)
_DST = re.compile(r"\b(?:dst|to)\s+" + _IPP)

_CLASS = 4001  # Network Activity


class CiscoAsaParser(Parser):
    SOURCE_TYPE = "cisco_asa"
    SECTOR = "common"
    ORIGINAL_FORMAT = "syslog"
    PRODUCT = {"name": "ASA", "vendor_name": "Cisco"}

    def parse(self, raw: dict) -> Optional[dict]:
        line = raw.get("raw")
        if not isinstance(line, str):
            return None
        meta = raw.get("meta") or {}

        m = _ASA_TAG.search(line)
        if not m:
            return None
        text = m.group("text")
        asa_sev = int(m.group("sev"))

        low = text.lower()
        if low.startswith("deny") or " deny " in low or "denied" in low:
            activity_id, status = 6, "Failure"  # Deny
        else:
            activity_id, status = 7, "Success"  # Accept / Built

        # endpoints (src|from|for -> source, dst|to -> destination)
        sm = _SRC.search(text)
        dm = _DST.search(text)

        time_ms = self._time_ms(meta)
        severity_id = _ASA_SEV_MAP.get(asa_sev, SEV_INFO)

        event = self.base_event(
            class_uid=_CLASS,
            activity_id=activity_id,
            severity_id=severity_id,
            time_ms=time_ms,
            ingest_id=meta.get("ingest_id"),
            logged_time=self._logged_time(meta),
            status=status,
            message=text.strip(),
            meta=meta,
            sector=self.resolve_sector(meta),
        )

        src_ip = sm.group("ip") if sm else None
        if src_ip and _IPV4_FULL.match(src_ip):
            event["src_endpoint"] = {"ip": src_ip, "port": int(sm.group("port"))}
        elif meta.get("ip"):
            event["src_endpoint"] = {"ip": meta["ip"]}
        dst_ip = dm.group("ip") if dm else None
        if dst_ip and _IPV4_FULL.match(dst_ip):
            event["dst_endpoint"] = {"ip": dst_ip, "port": int(dm.group("port"))}

        return event

    @staticmethod
    def _time_ms(meta: dict) -> int:
        ra = meta.get("received_at")
        if isinstance(ra, (int, float)):
            return int(ra * 1000) if ra < 1e12 else int(ra)
        return int(time.time() * 1000)

    @staticmethod
    def _logged_time(meta: dict) -> Optional[int]:
        ra = meta.get("received_at")
        if isinstance(ra, (int, float)):
            return int(ra * 1000) if ra < 1e12 else int(ra)
        return None
