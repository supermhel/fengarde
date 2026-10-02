#!/usr/bin/env python3
"""Measure DNS parent-domain cardinality on a real query log, to vet the allowlist.

Why this exists
---------------
contracts/rules/common_dns_tunnel_by_domain.yml fires when 40+ DISTINCT queried
names share one parent domain inside a 60 s window, counted across ALL clients.
It is suppressed for the parents in contracts/allowlists/
dns_high_cardinality_parents.yml, which is an UNVERIFIED starter set. This tool
replays a resolver query log through the same window semantics and reports which
parents WOULD trip the rule, so the operator can validate and extend the
allowlist on their own traffic instead of guessing.

It NEVER writes the allowlist. A high-cardinality parent is, by definition, what
the rule exists to detect: it can be a CDN or it can be a tunnel. The report
prints the allowlist admission test beside the suggestions and emits them
COMMENTED OUT, so adding one is a deliberate act.

Usage
-----
    python tools/dns_cardinality_report.py <log-file | ->  [--json]
        [--format auto|zeek|bind|dnsmasq|csv|jsonl] [--threshold N] [--window S]
        [--rule PATH] [--allowlist PATH] [--assume-year YYYY] [--fold-case]

Input formats (auto-detected from the first lines, or forced with --format):
  zeek     Zeek dns.log, TSV with a ``#fields`` header (query, ts, id.orig_h)
  bind     BIND query log: ``... client @0x.. 10.0.0.5#5353 (n): query: n IN A +``
  dnsmasq  ``... query[A] name from 10.0.0.5`` (the shape the repo's own parser reads)
  csv      header row with a name column (qname|query|name|domain), optional
           ts/time/timestamp and client/src/id.orig_h columns
  jsonl    one JSON object per line with a qname|query|name key (Zeek JSON works)

Semantics (identical to the rule; thresholds are read from the rule YAML):
  * group key = parent_domain(name) from the ws2 dns_query parser (imported, not copied)
  * measure   = distinct queried names (dst_endpoint.hostname) per parent
  * window    = sliding, ALL clients pooled (tenant-wide), a name stays in the window
                while ts >= newest_ts - window (same eviction rule as shared/window.py)
  * fires at  = count >= threshold
  * names are compared as logged apart from a stripped trailing dot, exactly like the
    parser (case-sensitive); --fold-case lower-cases them first and so DEVIATES from
    the rule (it is for resolvers that randomise query case)

Without timestamps the window cannot be applied: the whole file is then treated as ONE
window (an upper bound), and the report says so loudly. Memory is bounded: per parent
only the entries inside the window are kept; parents that fell out of the window are
swept; per-parent totals use capped sets. The input should be roughly time-ordered:
a record more than one window older than the newest timestamp is excluded from window
counts and reported (``late_records``), never silently mixed in.

Stdlib plus the repo's own modules (PyYAML is already a repo dependency).
"""
from __future__ import annotations

import argparse
import bisect
import calendar
import csv
import io
import json
import math
import re
import sys
from collections import deque
from datetime import datetime, timezone
from itertools import chain, islice
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional, TextIO

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
sys.path.insert(0, str(SERVICES / "ws2-normalization"))
sys.path.insert(0, str(SERVICES))

import yaml  # noqa: E402
from parsers.dns_query import parent_domain  # noqa: E402

DEFAULT_RULE = ROOT / "contracts" / "rules" / "common_dns_tunnel_by_domain.yml"
ALLOWLISTS_DIR = ROOT / "contracts" / "allowlists"
DEFAULT_THRESHOLD = 40          # fallbacks only; the rule YAML is the source of truth
DEFAULT_WINDOW_SECONDS = 60
FORMATS = ("zeek", "bind", "dnsmasq", "csv", "jsonl")

# Per-parent caps for the whole-file (not windowed) statistics, so one tunnel zone with
# millions of names cannot exhaust memory. A capped figure is printed with a trailing "+".
MAX_TRACKED_NAMES = 200_000
MAX_TRACKED_CLIENTS = 10_000
SWEEP_EVERY = 100_000           # timed records between sweeps of expired parents

NAME_KEYS = ("qname", "query", "name", "domain")
TS_KEYS = ("ts", "time", "timestamp", "@timestamp", "datetime")
CLIENT_KEYS = ("id.orig_h", "client", "client_ip", "src", "src_ip", "source", "orig_h")

ADMISSION_TEST = (
    "Allowlist admission test (header of contracts/allowlists/dns_high_cardinality_parents.yml):\n"
    "  (a) the parent is registered to and operated by a vendor, so an attacker cannot be that\n"
    "      zone's authoritative name server, AND\n"
    "  (b) the vendor does not hand out NS delegations for its subdomains.\n"
    "  A free-subdomain / dynamic-DNS / bring-your-own-DNS zone must NEVER be listed. Never list a\n"
    "  parent merely because it appears in your logs, and never a bare public suffix."
)

TUNNEL_WARNING = (
    "A parent listed below may be a DNS TUNNEL, not a CDN. Many distinct names under one parent is\n"
    "exactly the signal the rule exists to catch. Do NOT allowlist a parent because it appears in\n"
    "this report: look at the sample names and the client count, then apply the admission test."
)

# Advisory deny list (text only, never enforcement; the engine does not read it). Each entry
# was decided with the admission test:
#   "never"   customers can point a name at infrastructure they control, and several of these
#             offer NS delegation or wildcard / ephemeral hosts. They fail (a) or (b) outright,
#             and high cardinality under them is a stronger sign of abuse, not a reason to
#             suppress. Never allowlist.
#   "caution" the vendor, not the customer, answers for the zone and offers no NS delegation, so
#             (a) and (b) hold strictly. They are still multi-tenant free-subdomain zones, which
#             the allowlist header forbids categorically, so the tool never suggests them; an
#             operator may list one after a deliberate review.
# cloudfront.net is deliberately NOT here: its names are vendor-assigned distribution ids, there
# is no delegation, and it passes the test (it stays in the starter allowlist).
DENY_LIST: dict[str, tuple[str, str]] = {
    "afraid.org": ("never", "FreeDNS: free subdomains and NS delegation to the customer's own server"),
    "ddns.net": ("never", "No-IP shared dynamic-DNS zone: every customer owns a label"),
    "duckdns.org": ("never", "free dynamic-DNS subdomains: every customer owns a label"),
    "dyndns.org": ("never", "Dyn dynamic-DNS service: customer-chosen hostnames"),
    "hopto.org": ("never", "No-IP shared dynamic-DNS zone: every customer owns a label"),
    "ngrok-free.app": ("never", "ngrok tunnel service: customer-chosen or ephemeral subdomains"),
    "ngrok.io": ("never", "ngrok tunnel service: customer-chosen or ephemeral subdomains"),
    "no-ip.com": ("never", "No-IP dynamic-DNS vendor: customer hostnames live in its sibling zones"
                           " (ddns.net, hopto.org, zapto.org); treat the whole family as never-list"),
    "serveo.net": ("never", "SSH reverse-tunnel service: customer-chosen subdomains"),
    "trycloudflare.com": ("never", "Cloudflare quick tunnels: ephemeral hosts anyone can create"),
    "zapto.org": ("never", "No-IP shared dynamic-DNS zone: every customer owns a label"),
    "azurewebsites.net": ("caution", "multi-tenant app hosting, one label per customer; Microsoft"
                                     " answers for the zone and offers no NS delegation, so it cannot"
                                     " carry a DNS tunnel, but it is a free-subdomain zone"),
    "github.io": ("caution", "GitHub Pages, one label per user; GitHub answers for the zone and offers no"
                             " NS delegation. It is a public suffix the approximate parent_domain does not"
                             " know, so all of *.github.io pools under one parent"),
    "herokuapp.com": ("caution", "multi-tenant app hosting, one label per customer; Heroku answers for"
                                 " the zone and offers no NS delegation, but it is a free-subdomain zone"),
}


class FormatError(Exception):
    """The input cannot be read as any supported format (usage error, exit 2)."""


# ---------------------------------------------------------------------------
# timestamps
# ---------------------------------------------------------------------------

_MONTHS = {m: i for i, m in enumerate(
    ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), start=1)}
# BIND native print-time: 02-Oct-2026 10:15:03.123 (month names parsed by table, not by locale)
_BIND_TS = re.compile(r"^\s*(\d{1,2})-([A-Za-z]{3})-(\d{4})\s+(\d\d):(\d\d):(\d\d)(?:\.(\d+))?")
# BIND print-time iso8601 / iso8601-utc, and generic ISO prefixes
_ISO_TS = re.compile(r"^\s*(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?)")
# syslog prefix (dnsmasq): Jul 20 10:15:03 -- carries no year
_SYSLOG_TS = re.compile(r"^\s*([A-Za-z]{3})\s+(\d{1,2})\s+(\d\d):(\d\d):(\d\d)\b")


def _utc_epoch(year: int, month: int, day: int, hh: int, mm: int, ss: int, frac: str = "") -> float:
    try:
        base = calendar.timegm((year, month, day, hh, mm, ss))
    except (ValueError, OverflowError) as exc:
        raise ValueError(f"bad date: {exc}") from exc
    return base + (float("0." + frac) if frac else 0.0)


def parse_ts(value: Any) -> Optional[float]:
    """Epoch seconds for a timestamp cell, None when it is legitimately absent
    (empty / '-' / '(empty)'), ValueError when something is there but unreadable.
    Naive times are read as UTC (only differences matter to the window)."""
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError("bad timestamp")
    if isinstance(value, (int, float)):
        num = float(value)
    else:
        s = str(value).strip()
        if s in ("", "-", "(empty)"):
            return None
        try:
            num = float(s)
        except ValueError:
            m = _ISO_TS.match(s)
            if m:
                iso = m.group(1).replace(" ", "T")
                if iso.endswith("Z"):
                    iso = iso[:-1] + "+00:00"
                dt = datetime.fromisoformat(iso)   # ValueError propagates
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.timestamp()
            m2 = _BIND_TS.match(s)
            if m2 and m2.group(2).lower() in _MONTHS:
                d, mon, y, hh, mm, ss, frac = m2.groups()
                return _utc_epoch(int(y), _MONTHS[mon.lower()], int(d), int(hh), int(mm), int(ss), frac or "")
            raise ValueError(f"unreadable timestamp {s!r}") from None
    if not math.isfinite(num) or num < 0:
        raise ValueError("bad timestamp")
    return num / 1000.0 if num > 1e11 else num     # epoch milliseconds vs seconds


def _prefix_ts(line: str, assume_year: int) -> Optional[float]:
    """The optional leading timestamp of a BIND / dnsmasq line, or None when the line has none."""
    m = _ISO_TS.match(line)
    if m:
        try:
            return parse_ts(m.group(1))
        except ValueError:
            return None
    m2 = _BIND_TS.match(line)
    if m2 and m2.group(2).lower() in _MONTHS:
        d, mon, y, hh, mm, ss, frac = m2.groups()
        try:
            return _utc_epoch(int(y), _MONTHS[mon.lower()], int(d), int(hh), int(mm), int(ss), frac or "")
        except ValueError:
            return None
    m3 = _SYSLOG_TS.match(line)
    if m3 and m3.group(1).lower() in _MONTHS:
        mon, d, hh, mm, ss = m3.groups()
        try:
            return _utc_epoch(assume_year, _MONTHS[mon.lower()], int(d), int(hh), int(mm), int(ss))
        except ValueError:
            return None
    return None


# ---------------------------------------------------------------------------
# readers: line -> record
# ---------------------------------------------------------------------------

# A record is (ts_seconds_or_None, name, client_or_None). A reader returns a record, None for a
# malformed line (counted, skipped), IGNORE for a line that is not data (comment / header), or
# NOQUERY for a data line that legitimately carries no query name (Zeek '-').
Record = tuple[Optional[float], str, Optional[str]]
IGNORE: Any = object()
NOQUERY: Any = object()

_BIND = re.compile(
    r"client\s+(?:@0x[0-9A-Fa-f]+\s+)?(?P<ip>[0-9A-Fa-f:.]+)#\d+\s+\([^)]*\):\s+(?:view\s+\S+:\s+)?"
    r"query:\s+(?P<name>\S+)\s+IN\s+\S+"
)
_DNSMASQ = re.compile(r"query\[(?P<qtype>[A-Za-z0-9]+)\]\s+(?P<name>\S+)\s+from\s+(?P<ip>[0-9A-Fa-f:.]+)")
_DNSMASQ_DAEMON = re.compile(r"dnsmasq(?:-dhcp)?\[\d+\]:")


class _Reader:
    def __init__(self, assume_year: int):
        self.assume_year = assume_year

    def read(self, line: str) -> Any:        # pragma: no cover - interface
        raise NotImplementedError


class _BindReader(_Reader):
    def read(self, line: str) -> Any:
        m = _BIND.search(line)
        if not m:
            return None
        return (_prefix_ts(line, self.assume_year), m.group("name"), m.group("ip"))


class _DnsmasqReader(_Reader):
    def read(self, line: str) -> Any:
        m = _DNSMASQ.search(line)
        if m:
            return (_prefix_ts(line, self.assume_year), m.group("name"), m.group("ip"))
        if _DNSMASQ_DAEMON.search(line):
            return IGNORE        # reply / forwarded / cached / config: not a query line
        return None


class _ZeekReader(_Reader):
    def __init__(self, assume_year: int):
        super().__init__(assume_year)
        self.sep = "\t"
        self.cols: Optional[list[str]] = None

    def read(self, line: str) -> Any:
        if line.startswith("#"):
            if line.startswith("#separator"):
                spec = line.split(None, 1)[1].strip() if len(line.split(None, 1)) > 1 else "\\x09"
                try:
                    self.sep = spec.encode("ascii").decode("unicode_escape") or "\t"
                except (UnicodeError, ValueError):
                    self.sep = "\t"
            elif line.startswith("#fields"):
                self.cols = line.rstrip("\r\n").split(self.sep)[1:]
                if "query" not in self.cols:
                    raise FormatError("Zeek #fields header has no 'query' column (is this dns.log?)")
            return IGNORE
        if self.cols is None:
            return None
        parts = line.rstrip("\r\n").split(self.sep)
        if len(parts) < len(self.cols):
            return None
        row = dict(zip(self.cols, parts))
        name = row.get("query", "-")
        try:
            ts = parse_ts(row.get("ts"))
        except ValueError:
            return None
        if name in ("-", "(empty)", ""):
            return NOQUERY
        client = row.get("id.orig_h")
        return (ts, name, None if client in (None, "-", "(empty)", "") else client)


class _CsvReader(_Reader):
    def __init__(self, assume_year: int):
        super().__init__(assume_year)
        self.idx: Optional[dict[str, int]] = None

    def read(self, line: str) -> Any:
        try:
            row = next(csv.reader([line.lstrip("\ufeff")]))
        except (csv.Error, StopIteration):
            return None
        if self.idx is None:
            low = [c.strip().lower() for c in row]
            name_i = next((low.index(k) for k in NAME_KEYS if k in low), None)
            if name_i is None:
                raise FormatError("CSV header has no name column (expected one of: " + ", ".join(NAME_KEYS) + ")")
            ts_i = next((low.index(k) for k in TS_KEYS if k in low), None)
            cl_i = next((low.index(k) for k in CLIENT_KEYS if k in low), None)
            self.idx = {"name": name_i}
            if ts_i is not None:
                self.idx["ts"] = ts_i
            if cl_i is not None:
                self.idx["client"] = cl_i
            return IGNORE
        if len(row) <= max(self.idx.values()):
            return None
        name = row[self.idx["name"]].strip()
        if not name:
            return None
        try:
            ts = parse_ts(row[self.idx["ts"]]) if "ts" in self.idx else None
        except ValueError:
            return None
        client = row[self.idx["client"]].strip() if "client" in self.idx else None
        return (ts, name, client or None)


class _JsonlReader(_Reader):
    def read(self, line: str) -> Any:
        try:
            obj = json.loads(line)
        except ValueError:
            return None
        if not isinstance(obj, dict):
            return None
        key = next((k for k in NAME_KEYS if k in obj), None)
        if key is None:
            return None
        name = obj[key]
        if name is None or name in ("-", ""):
            return NOQUERY
        if not isinstance(name, str):
            return None
        ts = None
        tkey = next((k for k in TS_KEYS if k in obj), None)
        if tkey is not None:
            try:
                ts = parse_ts(obj[tkey])
            except ValueError:
                return None
        ckey = next((k for k in CLIENT_KEYS if k in obj), None)
        client = obj[ckey] if ckey is not None and isinstance(obj[ckey], str) and obj[ckey] not in ("", "-") else None
        return (ts, name, client)


_READERS = {"zeek": _ZeekReader, "bind": _BindReader, "dnsmasq": _DnsmasqReader,
            "csv": _CsvReader, "jsonl": _JsonlReader}


def detect_format(head: Iterable[str]) -> Optional[str]:
    """Format of a log from its first lines, or None when nothing is recognisable."""
    for raw in head:
        s = raw.strip().lstrip("\ufeff")
        if not s:
            continue
        if s.startswith(("#separator", "#fields", "#set_separator")):
            return "zeek"
        if s.startswith("{"):
            return "jsonl"
        if _BIND.search(s):
            return "bind"
        if _DNSMASQ.search(s):
            return "dnsmasq"
        try:
            low = [c.strip().lower() for c in next(csv.reader([s]))]
        except (csv.Error, StopIteration):
            continue
        if any(k in low for k in NAME_KEYS):
            return "csv"
    return None


# ---------------------------------------------------------------------------
# analysis
# ---------------------------------------------------------------------------

class _Parent:
    __slots__ = ("total", "timed", "names", "names_capped", "clients", "clients_capped", "first_ms", "last_ms",
                 "dq", "counts", "hwm", "max_distinct", "peak_ms", "sample")

    def __init__(self) -> None:
        self.total = 0
        self.timed = 0
        self.names: set[str] = set()
        self.names_capped = False
        self.clients: set[str] = set()
        self.clients_capped = False
        self.first_ms: Optional[int] = None
        self.last_ms: Optional[int] = None
        self.dq: deque[tuple[int, str]] = deque()
        self.counts: dict[str, int] = {}
        self.hwm: Optional[int] = None
        self.max_distinct = 0
        self.peak_ms: Optional[int] = None
        self.sample: list[str] = []


class Analyzer:
    """Streaming replay of the rule's distinct-name sliding window, per parent domain."""

    def __init__(self, window_seconds: int, fold_case: bool = False, sweep_every: int = SWEEP_EVERY):
        self.window_ms = int(window_seconds) * 1000
        self.fold_case = fold_case
        self.sweep_every = max(1, sweep_every)
        self.parents: dict[str, _Parent] = {}
        self.records = 0
        self.no_parent = 0
        self.untimed = 0
        self.late = 0
        self.timed_records = 0
        self.client_records = 0
        self.max_window_entries = 0          # largest deque ever held (memory-bound evidence)
        self._global_hwm: Optional[int] = None
        self._since_sweep = 0

    def add(self, ts: Optional[float], name: str, client: Optional[str]) -> None:
        self.records += 1
        name = name.strip().rstrip(".")      # same normalisation as the dns_query parser
        if self.fold_case:
            name = name.lower()
        parent = parent_domain(name) if name else None
        if parent is None:
            self.no_parent += 1
            return
        st = self.parents.get(parent)
        if st is None:
            st = self.parents[parent] = _Parent()
        st.total += 1
        if len(st.names) < MAX_TRACKED_NAMES:
            st.names.add(name)
        elif name not in st.names:
            st.names_capped = True
        if client:
            self.client_records += 1
            if len(st.clients) < MAX_TRACKED_CLIENTS:
                st.clients.add(client)
            elif client not in st.clients:
                st.clients_capped = True
        if ts is None:
            self.untimed += 1
            return
        ms = int(round(ts * 1000))
        self.timed_records += 1
        st.timed += 1
        st.first_ms = ms if st.first_ms is None or ms < st.first_ms else st.first_ms
        st.last_ms = ms if st.last_ms is None or ms > st.last_ms else st.last_ms
        if self._global_hwm is None or ms > self._global_hwm:
            self._global_hwm = ms
        self._window_add(st, ms, name)
        self._since_sweep += 1
        if self._since_sweep >= self.sweep_every:
            self._since_sweep = 0
            self._sweep()

    def _window_add(self, st: _Parent, ms: int, name: str) -> None:
        w = self.window_ms
        gh = self._global_hwm if self._global_hwm is not None else ms
        if (st.hwm is not None and ms < st.hwm - w) or ms < gh - w:
            self.late += 1
            return
        if st.dq and ms < st.dq[-1][0]:
            items = list(st.dq)
            bisect.insort(items, (ms, name))
            st.dq = deque(items)
        else:
            st.dq.append((ms, name))
        st.counts[name] = st.counts.get(name, 0) + 1
        if st.hwm is None or ms > st.hwm:
            st.hwm = ms
        horizon = st.hwm - w
        while st.dq and st.dq[0][0] < horizon:
            _, old = st.dq.popleft()
            left = st.counts[old] - 1
            if left:
                st.counts[old] = left
            else:
                del st.counts[old]
        if len(st.dq) > self.max_window_entries:
            self.max_window_entries = len(st.dq)
        distinct = len(st.counts)
        if distinct > st.max_distinct:
            st.max_distinct = distinct
            st.peak_ms = st.hwm
            st.sample = list(islice(st.counts, 3))

    def _sweep(self) -> None:
        """Free the window of every parent that has fallen a full window behind the newest
        timestamp: its peak is already recorded and nothing in range can still reach it."""
        if self._global_hwm is None:
            return
        horizon = self._global_hwm - self.window_ms
        for st in self.parents.values():
            if st.dq and st.hwm is not None and st.hwm < horizon:
                st.dq = deque()
                st.counts = {}

    @property
    def live_windows(self) -> int:
        return sum(1 for st in self.parents.values() if st.dq)

    @property
    def single_window(self) -> bool:
        """No record carried a timestamp: the 60 s window cannot be applied."""
        return self.timed_records == 0 and any(self.parents)


def _iso(ms: Optional[int]) -> Optional[str]:
    if ms is None:
        return None
    return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ---------------------------------------------------------------------------
# rule / allowlist
# ---------------------------------------------------------------------------

def load_rule_params(rule_path: Path) -> dict[str, Any]:
    """threshold / window_seconds / allowlist name straight from the rule YAML."""
    rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    siem = rule.get("siem") or {}
    out: dict[str, Any] = {"threshold": siem.get("threshold"), "window_seconds": siem.get("window_seconds"),
                           "allowlist_name": None}
    for sel in (rule.get("detection") or {}).values():
        if isinstance(sel, dict):
            for cond in sel.values():
                if isinstance(cond, dict) and isinstance(cond.get("not_in"), str):
                    out["allowlist_name"] = cond["not_in"]
    return out


def load_allowlist_entries(path: Path) -> Optional[set[str]]:
    """Exact-match entries, or None when unreadable (the engine then fails OPEN: nothing is suppressed)."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        entries = raw.get("entries") if isinstance(raw, dict) else None
        if not isinstance(entries, list):
            return None
        return {e for e in entries if isinstance(e, str)}
    except (OSError, yaml.YAMLError):
        return None


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

def build_report(an: Analyzer, *, threshold: int, window_seconds: int, allowlist: Optional[set[str]],
                 meta: dict[str, Any]) -> dict[str, Any]:
    single = an.single_window
    rows = []
    for parent, st in an.parents.items():
        if single:
            maxd, capped = len(st.names), st.names_capped
        else:
            maxd, capped = st.max_distinct, False
        rows.append((parent, st, maxd, capped))
    rows.sort(key=lambda r: (-r[2], r[0]))

    def row_dict(parent: str, st: _Parent, maxd: int, capped: bool) -> dict[str, Any]:
        deny = DENY_LIST.get(parent)
        on_list = bool(allowlist) and parent in (allowlist or set())
        return {
            "parent": parent,
            "max_distinct_names_in_window": maxd,
            "max_distinct_capped": capped,
            "peak_at": None if single else _iso(st.peak_ms),
            "total_queries": st.total,
            "distinct_names": len(st.names),
            "distinct_names_capped": st.names_capped,
            "distinct_clients": len(st.clients),
            "distinct_clients_capped": st.clients_capped,
            "first_seen": _iso(st.first_ms),
            "last_seen": _iso(st.last_ms),
            "on_allowlist": on_list,
            "deny_list": None if deny is None else {"tier": deny[0], "reason": deny[1]},
            "sample_names": [] if single else list(st.sample),
        }

    flagged = [row_dict(*r) for r in rows if r[2] >= threshold]
    below = [row_dict(*r) for r in rows if r[2] < threshold][:5]
    suggested = sorted(f["parent"] for f in flagged if not f["on_allowlist"] and f["deny_list"] is None)

    warnings: list[str] = []
    if single:
        warnings.append(
            "NO TIMESTAMPS FOUND. The 60 s window cannot be applied, so the WHOLE FILE WAS TREATED AS ONE "
            "WINDOW: every distinct name under a parent counts, however far apart the queries were. Figures "
            "below are an UPPER BOUND on what the rule would see, and a parent listed may never reach the "
            "threshold in real time. Re-run on a log that carries timestamps before deciding anything.")
    elif an.untimed:
        warnings.append(
            f"{an.untimed} record(s) had no timestamp and were EXCLUDED from the window counts "
            "(they still count in the totals).")
    if an.late:
        warnings.append(
            f"{an.late} record(s) were more than one window older than the newest timestamp seen (input "
            "not time-ordered) and were EXCLUDED from the window counts; sort the log by time for exact results.")
    if meta.get("malformed"):
        warnings.append(f"{meta['malformed']} malformed line(s) were counted and skipped.")
    if allowlist is None:
        warnings.append("The allowlist could not be read, so 'already on the allowlist' is unknown "
                        "(the engine fails OPEN in that case: nothing is suppressed).")
    if any(f["deny_list"] and f["deny_list"]["tier"] == "never" for f in flagged):
        warnings.append("A flagged parent is a dynamic-DNS / tunnel-service zone. Do not allowlist it; "
                        "find the hosts that query it.")

    sugg_lines = []
    by_parent = {f["parent"]: f for f in flagged}
    for p in suggested:
        f = by_parent[p]
        ev = f"max {f['max_distinct_names_in_window']} names/{window_seconds}s, {f['distinct_clients']} client(s)"
        if f["sample_names"]:
            ev += "; e.g. " + ", ".join(f["sample_names"])
        sugg_lines.append(f'  # - "{p}"   # {ev}')
    suggested_yaml = (
        "# Suggested NEW entries for contracts/allowlists/dns_high_cardinality_parents.yml\n"
        "# COMMENTED OUT on purpose: un-comment one only after it passes the admission test,\n"
        "# and keep the list alphabetical. This tool never edits the allowlist.\n"
        + "\n".join(sugg_lines) + ("\n" if sugg_lines else "")
    )

    return {
        "tool": "dns_cardinality_report",
        "input": meta,
        "rule": {"threshold": threshold, "window_seconds": window_seconds},
        "timestamps": {"present": an.timed_records > 0, "single_window": single},
        "warnings": warnings,
        "parents_analysed": len(an.parents),
        "records_without_parent": an.no_parent,
        "untimed_records": an.untimed,
        "late_records": an.late,
        "max_window_entries": an.max_window_entries,
        "flagged": flagged,
        "highest_below_threshold": below,
        "suggested_allowlist_entries": suggested,
        "suggested_yaml": suggested_yaml if sugg_lines else "",
        "tunnel_warning": TUNNEL_WARNING,
        "admission_test": ADMISSION_TEST,
    }


def render_text(rep: dict[str, Any]) -> str:
    out: list[str] = []
    inp, rule = rep["input"], rep["rule"]
    out.append("FENGARDE DNS cardinality report (common_dns_tunnel_by_domain)")
    out.append(f"input     : {inp.get('path')}  format={inp.get('format')}  lines={inp.get('lines_read')}"
               f"  records={inp.get('records')}  malformed={inp.get('malformed')}")
    out.append(f"rule      : >= {rule['threshold']} distinct names per parent within {rule['window_seconds']} s,"
               " all clients pooled")
    out.append(f"allowlist : {inp.get('allowlist')}")
    if rep["timestamps"]["single_window"]:
        out.append("")
        out.append("!" * 78)
        out.append("!! NO TIMESTAMPS: the whole file was treated as ONE window (upper bound only).")
        out.append("!" * 78)
    for w in rep["warnings"]:
        out.append("")
        out.append("WARNING: " + w)
    flagged = rep["flagged"]
    out.append("")
    out.append(f"Parents at or above the threshold: {len(flagged)} of {rep['parents_analysed']} analysed")
    if flagged:
        hdr = (f"{'PARENT':<30} {'MAX/WIN':>8} {'QUERIES':>8} {'NAMES':>8} {'CLIENTS':>8}  "
               f"{'FIRST SEEN':<24} {'LAST SEEN':<24} STATUS")
        out.append(hdr)
        out.append("-" * len(hdr))
        for f in flagged:
            plus = "+" if f["max_distinct_capped"] else ""
            names = f"{f['distinct_names']}{'+' if f['distinct_names_capped'] else ''}"
            clients = f"{f['distinct_clients']}{'+' if f['distinct_clients_capped'] else ''}"
            if f["on_allowlist"]:
                status = "ALREADY ON ALLOWLIST"
            elif f["deny_list"] and f["deny_list"]["tier"] == "never":
                status = "DYNAMIC-DNS / TUNNEL SERVICE: never allowlist"
            elif f["deny_list"]:
                status = "FREE-SUBDOMAIN ZONE (caution): not suggested"
            else:
                status = "REVIEW: may be a DNS tunnel"
            out.append(f"{f['parent']:<30} {str(f['max_distinct_names_in_window']) + plus:>8} {f['total_queries']:>8} "
                       f"{names:>8} {clients:>8}  {f['first_seen'] or '-':<24} {f['last_seen'] or '-':<24} {status}")
        for f in flagged:
            if f["deny_list"]:
                out.append(f"  note {f['parent']}: {f['deny_list']['reason']}")
            if f["sample_names"] and not f["on_allowlist"]:
                out.append(f"  sample {f['parent']} (peak {f['peak_at']}): " + ", ".join(f["sample_names"]))
    elif rep["highest_below_threshold"]:
        out.append("Highest parents below the threshold: " + ", ".join(
            f"{b['parent']}={b['max_distinct_names_in_window']}" for b in rep["highest_below_threshold"][:3]))
    if any(not f["on_allowlist"] for f in flagged):
        out.append("")
        out.append(rep["tunnel_warning"])
    if rep["suggested_yaml"]:
        out.append("")
        out.append(rep["suggested_yaml"].rstrip("\n"))
    if flagged:
        out.append("")
        out.append(rep["admission_test"])
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# driver
# ---------------------------------------------------------------------------

def _iter_lines(src: Iterable[str]) -> Iterator[str]:
    for line in src:
        yield line.rstrip("\n")


def analyze_stream(lines: Iterable[str], *, fmt: str, analyzer: Analyzer, assume_year: int) -> dict[str, Any]:
    """Run ``lines`` through the reader for ``fmt`` (or auto-detect) into ``analyzer``; return input stats."""
    it = _iter_lines(lines)
    head = list(islice(it, 50))
    if fmt == "auto":
        detected = detect_format(head)
        if detected is None:
            raise FormatError("could not recognise the log format (zeek / bind / dnsmasq / csv / jsonl); "
                              "force one with --format")
        fmt = detected
    reader = _READERS[fmt](assume_year)
    stats: dict[str, Any] = {"format": fmt, "lines_read": 0, "malformed": 0, "malformed_examples": [],
                             "ignored_lines": 0, "no_query_records": 0}
    for lineno, line in enumerate(chain(head, it), start=1):
        stats["lines_read"] += 1
        if not line.strip():
            continue
        rec = reader.read(line)
        if rec is IGNORE:
            stats["ignored_lines"] += 1
        elif rec is NOQUERY:
            stats["no_query_records"] += 1
        elif rec is None:
            stats["malformed"] += 1
            if len(stats["malformed_examples"]) < 3:
                stats["malformed_examples"].append({"line": lineno, "text": line[:120]})
        else:
            analyzer.add(*rec)
    stats["records"] = analyzer.records
    return stats


def main(argv: Optional[list[str]] = None, stdin: Optional[TextIO] = None, stdout: Optional[TextIO] = None) -> int:
    ap = argparse.ArgumentParser(description="Report which DNS parent domains would trip "
                                             "common_dns_tunnel_by_domain on a real query log.")
    ap.add_argument("log", help="DNS query log file, or '-' for stdin")
    ap.add_argument("--format", choices=("auto",) + FORMATS, default="auto")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--threshold", type=int, help="override the rule's threshold")
    ap.add_argument("--window", type=int, help="override the rule's window_seconds")
    ap.add_argument("--rule", type=Path, default=DEFAULT_RULE, help="rule YAML to read threshold/window/allowlist from")
    ap.add_argument("--allowlist", type=Path, help="allowlist YAML (default: the one the rule names)")
    ap.add_argument("--assume-year", type=int, default=2000,
                    help="year for syslog-style timestamps that carry none (dnsmasq); only relative time matters")
    ap.add_argument("--fold-case", action="store_true",
                    help="lower-case names before counting (DEVIATES from the rule, which is case-sensitive)")
    args = ap.parse_args(argv)
    out = stdout if stdout is not None else sys.stdout
    err = sys.stderr

    try:
        params = load_rule_params(args.rule)
    except (OSError, yaml.YAMLError, AttributeError) as exc:
        print(f"error: cannot read rule {args.rule}: {exc}", file=err)
        return 2
    threshold = args.threshold if args.threshold is not None else (params["threshold"] or DEFAULT_THRESHOLD)
    window = args.window if args.window is not None else (params["window_seconds"] or DEFAULT_WINDOW_SECONDS)
    if threshold < 1 or window < 1:
        print("error: threshold and window must be >= 1", file=err)
        return 2
    al_path = args.allowlist or (ALLOWLISTS_DIR / f"{params['allowlist_name']}.yml" if params["allowlist_name"] else None)
    allowlist = load_allowlist_entries(al_path) if al_path else None

    an = Analyzer(window, fold_case=args.fold_case)
    try:
        if args.log == "-":
            src: TextIO = stdin if stdin is not None else io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8", errors="replace")
            stats = analyze_stream(src, fmt=args.format, analyzer=an, assume_year=args.assume_year)
        else:
            with open(args.log, "r", encoding="utf-8", errors="replace", newline="") as fh:
                stats = analyze_stream(fh, fmt=args.format, analyzer=an, assume_year=args.assume_year)
    except (OSError, FormatError) as exc:
        print(f"error: {exc}", file=err)
        return 2

    meta = {"path": "<stdin>" if args.log == "-" else args.log,
            "allowlist": None if al_path is None else (str(al_path) + (f" ({len(allowlist)} entries)" if allowlist is not None
                                                                         else " (UNREADABLE)")),
            **stats}
    rep = build_report(an, threshold=threshold, window_seconds=window, allowlist=allowlist, meta=meta)
    if args.json:
        out.write(json.dumps(rep, indent=2) + "\n")
    else:
        out.write(render_text(rep))
    return 0


if __name__ == "__main__":
    sys.exit(main())
