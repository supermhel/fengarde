"""Dependency-free IP/MAC/string canonicalization helpers.

Split out of ``shared/ocsf.py`` (2026-09-02 review round) so services that
only need canonicalization -- not OCSF schema validation -- can import it
without pulling in ``tools/validate_contract.py``. That dependency isn't
shipped in every service's container image (e.g. ws8-correlation,
ws9-resolver), which previously forced those services to either duplicate
this logic (ws8's now-removed ``_canonical_ip``) or crash at import time
(ws9's ``entity_id.py`` importing ``shared.ocsf`` for ``valid_ip`` alone).

``shared/ocsf.py`` re-exports these three names for backward compatibility
with existing callers (the ws2-normalization parsers) that already import
them from ``shared.ocsf`` in a container that does ship ``tools/``.
"""
from __future__ import annotations
import ipaddress
import re
from typing import Optional


def valid_ip(value) -> Optional[str]:
    """Return ``value`` normalized to a real IPv4/IPv6 address, else ``None``.

    Parsers that build ``src_endpoint``/``dst_endpoint`` from a *structured*
    record (JSON dict fields, not a regex `.group()` capture that is always a
    string by construction) must run any candidate IP through this before
    assignment: an attacker-controlled JSON field can carry any type -- an
    int, a list, a dict -- and Contract A's endpoint schema requires ``ip``
    to be a pattern-matching string. Found by Hypothesis property fuzzing
    (M1, `parsers/test_property_hardening.py`) against db_audit's unguarded
    `rec.get("ipAddress")` assignment; the same unguarded-JSON-field pattern
    existed in five other structured-record parsers, fixed alongside it.

    P0-1 (2026-07-21 audit): an IPv4-mapped IPv6 address ("::ffff:a.b.c.d" --
    what Windows/dual-stack sockets log for locally-routed IPv4 traffic, seen
    live in both Splunk attack_data and EVTX-ATTACK-SAMPLES Kerberos
    brute-force/spray captures) parses fine via ``ipaddress.ip_address`` but
    fails Contract A's ``ip`` schema pattern -- its IPv6 branch forbids
    embedded dots. Passing it through unnormalized silently dead-lettered
    every one of those auth-failure events, so the brute-force/password-spray
    rules never saw them. Collapse it to the plain IPv4 form here (the two
    are the same address; nothing is lost) so validate() and the detection
    engine both see it. (2026-08-29 review): IPv6 is case- and
    compression-insensitive -- ``2001:DB8::1`` and
    ``2001:0db8:0000:0000:0000:0000:0000:0001`` are the SAME address, so the
    canonical return is ``ipaddress``'s ``str()`` (lowercased + de-compressed),
    collapsing every spelling of one address to ONE identity for parsers,
    WS-8's tracks, and WS-9's entity plane alike.
    """
    if not isinstance(value, str):
        return None
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        return str(mapped)
    # Canonical form for every valid address: ipaddress's str() lowercases
    # AND de-compresses IPv6 (2001:0DB8::1, 2001:db8:0:0:0:0:0:1 and
    # 2001:0db8:0000:0000:0000:0000:0000:0001 all -> "2001:db8::1"), so one
    # address is one identity, not one-per-spelling. IPv4 is already
    # dotted-quad canonical.
    return str(addr)


_MAC_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def valid_mac(value) -> Optional[str]:
    """Return ``value`` if it matches Contract A's MAC pattern, else ``None``
    -- same unguarded-JSON-field risk as :func:`valid_ip`, for endpoint.mac."""
    if isinstance(value, str) and _MAC_PATTERN.match(value):
        return value
    return None


def safe_str(value) -> Optional[str]:
    """Return ``value`` if it's a non-empty string, else ``None``. For
    hostname-shaped fields (Contract A has no format pattern for hostname,
    only a type constraint) pulled from a structured record -- same
    unguarded-JSON-field risk as :func:`valid_ip`, just a type check instead
    of a format check since hostnames have no fixed shape to validate."""
    if isinstance(value, str) and value.strip():
        return value
    return None
