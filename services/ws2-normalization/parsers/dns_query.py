"""DNS query-log parser: dnsmasq/BIND-style query lines -> OCSF DNS/HTTP Activity (4002).

v0.5 Track A4 (unblocks the first class-4002 producer, see
contracts/detection-coverage.md's long-standing gap). Targets the common
`dnsmasq` query-log line shape (BIND's `named` query log is textually very
similar: ``client <ip>#<port>: query: <name> IN <type>``, not separately
handled here since the field extraction is the same).

Typical line::

    Jul 20 10:15:03 dnsmasq[123]: query[A] evil-c2.example.com from 10.0.0.5

Mapping (Contract A / ocsf-classes.md): class 4002, activity_id 1 (best-fit
"query" activity -- Contract A's worked table doesn't enumerate 4002
activity_ids explicitly; 1 follows the same "first/primary activity" pattern
used for 3002 Logon and 6003 Create). The queried domain goes in
``dst_endpoint.hostname`` (the field already mapped in
contracts/opensearch-mappings/events-common.json), so no new schema field is
needed and common_dns_exfil.yml can group/distinct-count on it directly.
"""
from __future__ import annotations

import re
import time
from typing import Optional

from .base import Parser, SEV_INFO
from .timeutil import to_epoch_ms
from shared.ocsf import valid_ip

_CLASS = 4002  # DNS / HTTP Activity

# "query[A] evil-c2.example.com from 10.0.0.5" (dnsmasq)
_QUERY = re.compile(
    r"query\[(?P<qtype>[A-Za-z]+)\]\s+(?P<name>\S+)\s+from\s+(?P<ip>[0-9A-Fa-f:.]+)"
)


# Second-level labels that, under a two-letter country code, make the REGISTERED
# domain three labels long (example.co.uk, example.com.au). A real public-suffix
# list is the right tool; this is the deliberately small, dependency-free
# approximation, and its failure mode is benign: an unlisted multi-part suffix
# groups one label too high (everything under ".xx.yy" pools together), which can
# only OVER-count a window, never hide one.
_SLD = frozenset({"co", "com", "org", "net", "gov", "edu", "ac"})
_REVERSE_ZONES = (".in-addr.arpa", ".ip6.arpa")
_MAX_NAME = 253


def parent_domain(name: str) -> Optional[str]:
    """The registered-domain-ish parent of a queried name, lower-cased, or None.

    ``chunk007.t3.exfil.example.invalid`` -> ``example.invalid``;
    ``a.b.example.co.uk`` -> ``example.co.uk``. None for names that must not be
    pooled: a bare label, an over-long name, an IP literal, and reverse-lookup
    zones (``*.in-addr.arpa`` / ``*.ip6.arpa``) -- every PTR query for every
    address would otherwise pool under one parent and look like a tunnel."""
    n = name.strip().rstrip(".").lower()
    if not n or len(n) > _MAX_NAME or valid_ip(n) is not None:
        return None
    if any(n.endswith(z) for z in _REVERSE_ZONES):
        return None
    labels = n.split(".")
    if len(labels) < 2 or any(not lab for lab in labels):
        return None
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SLD:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


class DnsQueryParser(Parser):
    SOURCE_TYPE = "dns_query"
    SECTOR = "common"
    ORIGINAL_FORMAT = "syslog"
    PRODUCT = {"name": "dnsmasq", "vendor_name": "Simon Kelley"}

    def parse(self, raw: dict) -> Optional[dict]:
        line = raw.get("raw")
        if not isinstance(line, str):
            return None
        m = _QUERY.search(line)
        if not m:
            return None
        meta = raw.get("meta") or {}
        name = m.group("name").rstrip(".")
        if not name:
            return None

        # The regex captures a loose hex/dot/colon token so a malformed address
        # still matches the line (we keep the query, don't drop the whole
        # event); the address itself is validated here and dropped if it
        # isn't a real IP, same discipline as every other parser in this repo
        # (linux_ssh.py's _valid_ip, cef.py/k8s_audit.py/cloudtrail.py's
        # shared.ocsf.valid_ip) -- an invalid IP placed straight into
        # src_endpoint.ip would fail Contract A's endpoint pattern and
        # dead-letter the whole event.
        ip = valid_ip(m.group("ip")) or meta.get("ip")

        event = self.base_event(
            class_uid=_CLASS,
            activity_id=1,
            severity_id=SEV_INFO,
            time_ms=self._time_ms(meta),
            ingest_id=meta.get("ingest_id"),
            message=f"DNS query {m.group('qtype')} {name} from {m.group('ip')}",
            meta=meta,
            sector=self.resolve_sector(meta),
        )
        if ip:
            event["src_endpoint"] = {"ip": ip}
        event["dst_endpoint"] = {"hostname": name}
        # Parent-domain grouping key for common_dns_tunnel_by_domain.yml: the
        # grammar has no "group by parent domain" primitive, so the parser
        # derives one. Omitted (not null) when the name must not be pooled.
        parent = parent_domain(name)
        if parent:
            event["unmapped"] = {"dns": {"parent_domain": parent}}
        return event

    @staticmethod
    def _time_ms(meta: dict) -> int:
        # FIX 15: route through to_epoch_ms (FILETIME / ISO / epoch handling).
        parsed = to_epoch_ms(meta.get("received_at"))
        return parsed if parsed is not None else int(time.time() * 1000)
