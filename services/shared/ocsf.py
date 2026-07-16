"""Shared OCSF helpers (Contract A) reused across workstreams."""
from __future__ import annotations
import ipaddress
import re
import sys
from pathlib import Path
from typing import Optional

# Reuse the single source-of-truth validator in tools/. Resolve its location for
# BOTH the repo layout (repo/services/shared -> repo/tools, parents[2]) and the
# container layout (/app/shared -> /app/tools, parents[1]).
_here = Path(__file__).resolve()
for _cand in (_here.parents[2] / "tools", _here.parents[1] / "tools", Path("/app/tools")):
    if (_cand / "validate_contract.py").exists():
        sys.path.insert(0, str(_cand))
        break
from validate_contract import load, validate_event, SCHEMA_PATH  # noqa: E402

_SCHEMA = load(SCHEMA_PATH)


def make_type_uid(class_uid: int, activity_id: int) -> int:
    """Always derive type_uid; never hand-set it."""
    return class_uid * 100 + activity_id


def validate(event: dict) -> list[str]:
    """Return list of contract errors ([] means valid)."""
    return validate_event(event, _SCHEMA)


def is_valid(event: dict) -> bool:
    return not validate(event)


def valid_ip(value) -> Optional[str]:
    """Return ``value`` if it's a real IPv4/IPv6 address, else ``None``.

    Parsers that build ``src_endpoint``/``dst_endpoint`` from a *structured*
    record (JSON dict fields, not a regex `.group()` capture that is always a
    string by construction) must run any candidate IP through this before
    assignment: an attacker-controlled JSON field can carry any type -- an
    int, a list, a dict -- and Contract A's endpoint schema requires ``ip``
    to be a pattern-matching string. Found by Hypothesis property fuzzing
    (M1, `parsers/test_property_hardening.py`) against db_audit's unguarded
    `rec.get("ipAddress")` assignment; the same unguarded-JSON-field pattern
    existed in five other structured-record parsers, fixed alongside it."""
    if not isinstance(value, str):
        return None
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        return None


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
