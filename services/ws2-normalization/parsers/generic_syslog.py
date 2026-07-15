"""Generic syslog parser: RFC 3164 syslog lines -> OCSF Kernel/Process (1002).

Handles syslog lines that don't match any product-specific parser.
Supports the two common forms:

  <PRI>MMM DD HH:MM:SS hostname program[pid]: message
  MMM DD HH:MM:SS hostname program[pid]: message

The PRI field encodes facility (bits 7-3) and severity (bits 2-0).  When
present, the syslog severity is mapped to OCSF severity_id.  When absent,
severity_id defaults to 1 (Informational).

class_uid 1002 (Kernel / Process) is used — it covers "process exec,
privilege use" and is the closest match for arbitrary system-level syslog
messages that do not belong to a more-specific OCSF class.  activity_id 1
(generic first-in-class activity) is used for all events from this parser.

Syslog PRI severity -> OCSF severity_id mapping:
  0 Emergency  -> 6 Fatal
  1 Alert      -> 5 Critical
  2 Critical   -> 5 Critical
  3 Error      -> 4 High
  4 Warning    -> 3 Medium
  5 Notice     -> 2 Low
  6 Info        -> 1 Informational
  7 Debug       -> 1 Informational
"""
from __future__ import annotations

import hashlib
import re
import time
from typing import Optional

from .base import Parser, SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_HIGH, SEV_CRITICAL, SEV_FATAL

_CLASS = 1002       # Kernel / Process
_ACTIVITY = 1       # generic open/create (first-in-class)

# Syslog PRI field: <NN>
_PRI = re.compile(r"^<(?P<pri>\d{1,3})>")

# RFC 3164 header: MMM DD HH:MM:SS  (DD may be space-padded: " 1")
_HEADER = re.compile(
    r"(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<hms>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<prog>[^\s:\[]+)"                    # program name (no spaces, no brackets, no colon)
    r"(?:\[(?P<pid>\d+)\])?"                  # optional [pid]
    r":\s*"                                    # colon separator
    r"(?P<msg>.*)",                            # rest is message
    re.DOTALL,
)

# syslog severity bits (PRI & 0x07)
_SYSLOG_SEV_MAP = {
    0: SEV_FATAL,
    1: SEV_CRITICAL,
    2: SEV_CRITICAL,
    3: SEV_HIGH,
    4: SEV_MEDIUM,
    5: SEV_LOW,
    6: SEV_INFO,
    7: SEV_INFO,
}

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5,  "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _sev_from_pri(pri: int) -> int:
    return _SYSLOG_SEV_MAP.get(pri & 0x07, SEV_INFO)


def _best_effort_epoch_ms(month_str: str, day: int, hms: str) -> int:
    """Parse a no-year RFC 3164 timestamp to epoch ms (best-effort; uses current year)."""
    try:
        import datetime
        month = _MONTHS[month_str]
        h, m, s = (int(x) for x in hms.split(":"))
        year = datetime.datetime.now(datetime.timezone.utc).year
        dt = datetime.datetime(year, month, day, h, m, s,
                               tzinfo=datetime.timezone.utc)
        return int(dt.timestamp() * 1000)
    except Exception:
        return int(time.time() * 1000)


def _deterministic_ingest_id(line: str) -> str:
    """SHA-256-derived UUID-like string for idempotent ingest."""
    digest = hashlib.sha256(line.encode("utf-8", errors="replace")).hexdigest()
    # format as xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    return f"{digest[0:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"


class GenericSyslogParser(Parser):
    SOURCE_TYPE = "generic_syslog"
    SECTOR = "common"
    ORIGINAL_FORMAT = "syslog"
    PRODUCT = {"name": "Generic Syslog", "vendor_name": "RFC 3164"}

    def parse(self, raw: dict) -> Optional[dict]:
        line = raw.get("raw")
        if not isinstance(line, str) or not line.strip():
            return None

        meta = raw.get("meta") or {}
        text = line.strip()

        # strip PRI if present
        severity_id = SEV_INFO
        pri_m = _PRI.match(text)
        if pri_m:
            severity_id = _sev_from_pri(int(pri_m.group("pri")))
            text = text[pri_m.end():]

        # parse RFC 3164 header
        hdr = _HEADER.match(text)
        if hdr is None:
            return None

        month_str = hdr.group("month")
        day = int(hdr.group("day"))
        hms = hdr.group("hms")
        hostname = hdr.group("host")
        prog = hdr.group("prog")
        pid_str = hdr.group("pid")
        msg = hdr.group("msg") or ""

        time_ms = _best_effort_epoch_ms(month_str, day, hms)

        # ingest_id: from meta, else deterministic from raw line
        ingest_id = meta.get("ingest_id") or _deterministic_ingest_id(line)

        event = self.base_event(
            class_uid=_CLASS,
            activity_id=_ACTIVITY,
            severity_id=severity_id,
            time_ms=time_ms,
            ingest_id=ingest_id,
            sector=self.resolve_sector(meta),
        )
        event["message"] = msg or line

        event["src_endpoint"] = {"hostname": hostname}

        actor: dict = {"process": {"name": prog}}
        if pid_str is not None:
            try:
                actor["process"]["pid"] = int(pid_str)
            except ValueError:
                pass
        event["actor"] = actor

        return event
