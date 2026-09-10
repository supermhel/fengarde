"""A5: OCSF-additive event enrichment (WS-2 post-normalize stage).

Annotates a normalized OCSF event with local, offline context:
  - ``src_endpoint.reputation`` from a local IOC list (contracts/enrichment/ioc.yml)
  - ``src_endpoint.location``   from a local CIDR->country map (contracts/enrichment/geoip.yml)

Design rules (non-negotiable, from the v0.3 plan and the project's contracts):

- **Additive only.** Enrichment NEVER changes a field a parser set; it only adds
  optional extension objects. Downstream is a tolerant reader -- an event without
  these fields is still fully valid, so nothing may HARD-depend on them.
- **Offline / air-gap-safe.** Reads local YAML only, never an external service
  (sovereignty constraint). No network, no DNS, no API calls.
- **Fail-open, never raise.** Enrichment is best-effort context, not a gate: a
  missing/malformed data file, a bad IP, or any error leaves the event untouched
  and flowing. Losing an alert because a geo lookup hiccupped would be absurd.

Load-once: the default module-level ``Enricher`` reads both files at import and
caches parsed networks. ``enrich(event)`` uses it; tests construct their own
``Enricher(ioc_path=..., geoip_path=...)`` for isolation.

Per-IP result cache (WP-2-H): distinct source IPs are attacker-controlled, so
repeated events from the same IP used to re-run the same linear CIDR scans
every time. The Enricher now memoizes each IP's enrichment outcome -- the
(reputation, location) pair, or an explicit ``(None, None)`` miss marker so an
unknown IP is scanned once, not on every event -- in a BOUNDED LRU cache
(``_IP_CACHE_MAXSIZE``, ``OrderedDict.move_to_end`` + ``popitem(last=False)``,
the same discipline as ws4-detection/tenants.py's per-tenant cache). A spray
of distinct IPs cannot grow memory without limit: the cap evicts the
least-recently-used entry. Non-IP garbage strings are never cached (re-parsing
them is nearly free; caching them would let arbitrary garbage fill the cache
for free -- tenants.py's stated rationale). Cache reads/writes are guarded by
an instance lock that is held ONLY around the dict critical section, never
across a scan or any other lock, so it cannot introduce a deadlock.
"""
from __future__ import annotations

import ipaddress
import logging
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Optional

import yaml

from shared.ip_utils import valid_ip as _canonical_ip

# Fail-open by design, but NEVER silent (2026-08-26 gap-hunt finding: both
# except paths swallowed every exception with no log line, so a malformed
# IOC file or an enrich() bug made the whole A5 stage a silent no-op in
# production -- indistinguishable from \"data matched nothing\"). stdlib
# logging, not shared.log, to keep this module dependency-light and testable
# via assertLogs.
_LOGGER = logging.getLogger("ws2-normalization.enrichment")

# WP-2-H: bounded per-IP result cache cap. IPs are attacker-controlled, so this
# MUST be a hard ceiling -- an unbounded dict keyed by seen IPs would be a
# memory-growth primitive under a source-IP spray (same class as the ws8
# side-table finding). 10000 mirrors ws5-ai/_TriageCache._SEEN_CAP (the
# per-event-load dedup analog); tenants.py uses 1000 for a far cheaper lookup,
# but each entry here is a full CIDR scan's worth of saved work, and 10000
# tuples is still a flat few MB worst case.
_IP_CACHE_MAXSIZE = 10000


def _contracts_dir() -> Path:
    """Probe candidate bases rather than trust a fixed `parents[N]` depth.

    2026-08-07: `parents[3]` assumed this module always sits 4 levels below
    the repo root, true for a local checkout (repo/services/ws2-normalization/
    enrichment/__init__.py) but NOT for the built image -- the Dockerfile
    `COPY`s `services/ws2-normalization` straight to `/app/ws2-normalization`
    (dropping the `services/` prefix) and `contracts` to `/app/contracts`, so
    in the container this module is only 3 levels below `/`, `parents[3]`
    lands on `/`, and every IOC/geo lookup path silently pointed at
    `/contracts/...` (which doesn't exist) instead of `/app/contracts/...`.
    The fail-open contract this module already deliberately has (see the
    module docstring) meant this was never an error, just a silently
    always-empty enrichment stage in every deployed image -- identical bug
    class already found and fixed once in ws3-indexer's `rules_view.py`/
    `webhooks.py` (SSOT.md), same dual-path-probe fix applied here.
    """
    here = Path(__file__).resolve()
    for base in (here.parents[3], here.parents[2]):
        if (base / "contracts" / "enrichment" / "ioc.yml").exists():
            return base / "contracts"
    return here.parents[3] / "contracts"


_CONTRACTS = _contracts_dir()
_DEFAULT_IOC = _CONTRACTS / "enrichment" / "ioc.yml"
_DEFAULT_GEOIP = _CONTRACTS / "enrichment" / "geoip.yml"


def _load_entries(path: Path) -> list[dict]:
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        # Expected-ish misconfiguration (missing data file) but still worth a
        # line: an operator should know the IOC/geo stage is a silent no-op.
        _LOGGER.warning("enrichment data file missing (fail-open, no enrichment "
                        "from it): %s", path)
        return []
    except Exception as exc:  # noqa: BLE001
        # Malformed/unreadable file: fail-open per contract, but never swallow
        # silently -- gap-hunt finding 4 (a broken file used to be
        # indistinguishable from an empty one).
        _LOGGER.warning("enrichment data file unreadable/malformed (fail-open, "
                        "no enrichment from it): %s (%s: %s)",
                        path, type(exc).__name__, exc)
        return []
    entries = raw.get("entries") if isinstance(raw, dict) else None
    return [e for e in entries if isinstance(e, dict)] if isinstance(entries, list) else []


class Enricher:
    """Local offline IOC/GeoIP enrichment with a bounded per-IP result cache.

    ``enrich(event)`` is fail-open and additive (see the module docstring).
    Lookups go through ``_cached_result``: first time an IP is seen the
    reputation/location scans actually run and the outcome is memoized; every
    later event from that IP (the common case under a source-IP spray) is
    answered from the LRU cache without touching the CIDR lists.
    """

    def __init__(self, ioc_path: Path | str = _DEFAULT_IOC,
                 geoip_path: Path | str = _DEFAULT_GEOIP,
                 cache_cap: int = _IP_CACHE_MAXSIZE):
        self._ioc_exact: dict[str, dict] = {}
        self._ioc_nets: list[tuple] = []          # (network, entry)
        self._geo_nets: list[tuple] = []          # (network, country)
        # WP-2-H: ip -> (reputation_or_None, location_or_None); (None, None) is
        # the cached-miss marker (an IP that matched nothing locally). Bounded
        # at cache_cap and LRU-evicted exactly like tenants.py's per-tenant
        # cache (move_to_end on hit, popitem(last=False) when over cap).
        self._ip_cache: "OrderedDict[str, tuple]" = OrderedDict()
        self._ip_cache_cap = max(1, int(cache_cap))
        # Leaf lock: held ONLY around the OrderedDict critical sections below,
        # never across a scan, logging, or any other lock -- the module has no
        # other lock, so this cannot create a deadlock. (The current WS-2
        # consumer already runs one handler thread per topic, so this is
        # defense-in-depth for any future shared-Enricher wiring.)
        self._cache_lock = threading.Lock()
        for e in _load_entries(Path(ioc_path)):
            self._index_ioc(e)
        for e in _load_entries(Path(geoip_path)):
            self._index_geo(e)

    def _index_ioc(self, entry: dict) -> None:
        score = entry.get("score")
        if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
            return  # a reputation entry with no valid 0-100 score is meaningless
        cats = entry.get("categories")
        cats = [c for c in cats if isinstance(c, str)] if isinstance(cats, list) else []
        record = {"score": score, "categories": cats, "source": "local-ioc"}
        ip = entry.get("ip")
        if isinstance(ip, str):
            # Key on the SAME canonical spelling every parser now normalizes
            # to (shared.ip_utils.valid_ip, since shared/ocsf.py's 2026-08-29
            # IPv6 canonicalization change) -- keying on the IOC file's raw,
            # arbitrarily-cased/compressed literal used to silently break the
            # exact-match lookup for any IOC entry whose spelling differed
            # from the canonical form (2026-09-02 review): a real log event
            # for a flagged IPv6 address stopped matching its own IOC entry.
            canonical = _canonical_ip(ip)
            if canonical is not None:
                self._ioc_exact[canonical] = record
                return
        cidr = entry.get("cidr")
        if isinstance(cidr, str):
            try:
                self._ioc_nets.append((ipaddress.ip_network(cidr, strict=False), record))
            except ValueError:
                pass

    def _index_geo(self, entry: dict) -> None:
        country = entry.get("country")
        cidr = entry.get("cidr")
        if not isinstance(country, str) or not isinstance(cidr, str):
            return
        try:
            self._geo_nets.append((ipaddress.ip_network(cidr, strict=False), country))
        except ValueError:
            pass

    def _cache_lookup(self, ip_str: str):
        """Cached (rep, loc) tuple for ip_str, or None if not cached.

        A hit refreshes LRU recency (move_to_end). Lock discipline: the lock is
        acquired only for this dict critical section; the caller never holds it
        while scanning or logging, so no re-entrancy/deadlock is possible.
        """
        with self._cache_lock:
            cached = self._ip_cache.get(ip_str)
            if cached is not None:
                self._ip_cache.move_to_end(ip_str)
            return cached

    def _cache_store(self, ip_str: str, result: tuple) -> None:
        """Memoize result for ip_str; evict the LRU entry when over cap.

        Boundedness is the security property here: a spray of distinct
        attacker-controlled IPs can never grow this dict past the cap (same
        discipline as ws4-detection/tenants.py and ws5-ai/_TriageCache).
        """
        with self._cache_lock:
            self._ip_cache[ip_str] = result
            self._ip_cache.move_to_end(ip_str)
            while len(self._ip_cache) > self._ip_cache_cap:
                self._ip_cache.popitem(last=False)  # evict least-recently-used

    def _cached_result(self, ip_str: str):
        """Enrichment outcome for ip_str: (rep_or_None, loc_or_None).

        Returns the cached tuple on a hit; on a first sighting runs the real
        scans once, memoizes the outcome (including a (None, None) miss marker
        for an IP that matched nothing), and returns it -- so a repeated
        unknown IP is scanned exactly once and a cached miss is identical to a
        live scan. Non-IP garbage strings are NEVER cached: re-parsing them is
        nearly free, and caching them would let an attacker fill the cache with
        arbitrary junk for free (tenants.py's stated rationale).
        """
        hit = self._cache_lookup(ip_str)
        if hit is not None:
            return hit
        try:
            ipaddress.ip_address(ip_str)  # validity gate: garbage never cached
        except ValueError:
            return None
        rep = self._reputation_for(ip_str)
        loc = self._location_for(ip_str)
        self._cache_store(ip_str, (rep, loc))
        return (rep, loc)

    def _reputation_for(self, ip_str: str) -> Optional[dict]:
        exact = self._ioc_exact.get(ip_str)
        if exact is not None:
            return exact
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return None
        # Most-specific (longest-prefix) matching network wins; among equal
        # prefixes, the highest score. Deterministic regardless of file order.
        best = None
        for net, record in self._ioc_nets:
            if addr.version == net.version and addr in net:
                if best is None or net.prefixlen > best[0].prefixlen or (
                        net.prefixlen == best[0].prefixlen
                        and record["score"] > best[1]["score"]):
                    best = (net, record)
        return best[1] if best else None

    def _location_for(self, ip_str: str) -> Optional[dict]:
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return None
        best = None
        for net, country in self._geo_nets:
            if addr.version == net.version and addr in net:
                if best is None or net.prefixlen > best[0].prefixlen:
                    best = (net, country)
        return {"country": best[1], "source": "local-geoip"} if best else None

    def enrich(self, event: dict) -> dict:
        """Add reputation/location to event['src_endpoint'] in place (and return
        it). No-op when there's no src_endpoint.ip or no local data matches.
        Never overwrites an existing key; never raises.

        Per-IP memoization (WP-2-H): when any lookup is actually needed, the
        outcome is served from / stored into the bounded per-IP cache, so the
        CIDR scans run at most once per distinct IP -- never per event. A
        cached miss returns exactly what a live scan would (nothing added).
        Events that already carry both fields (or have no IP) never touch the
        cache."""
        try:
            src = event.get("src_endpoint") if isinstance(event, dict) else None
            if not isinstance(src, dict):
                return event
            ip = src.get("ip")
            if not isinstance(ip, str) or not ip:
                return event
            need_rep = "reputation" not in src
            need_loc = "location" not in src
            if need_rep or need_loc:
                result = self._cached_result(ip)
                if result is not None:
                    rep, loc = result
                    if need_rep and rep is not None:
                        # Copy, don't alias (gap-hunt 2026-09-04): same
                        # sharing hazard as `location` below -- `rep` is the
                        # SAME cached object for every event sharing this
                        # source IP. Missed in the 2026-09-02 location fix;
                        # this field was one line over from the comment
                        # explaining exactly why it needed the same treatment.
                        src["reputation"] = dict(rep)
                    if need_loc and loc is not None:
                        # Copy, don't alias (2026-09-02 review): `loc` is the
                        # SAME dict object cached for every event sharing this
                        # source IP (`_cached_result` computes it once and
                        # stores the literal object). Before the WP-2-H cache
                        # existed, `_location_for` built a fresh dict per
                        # event, so nothing was ever shared; assigning the
                        # cached object by reference would let any future
                        # in-place mutation of one event's location silently
                        # corrupt every other event that shares the IP.
                        src["location"] = dict(loc)
        except Exception as exc:  # noqa: BLE001
            # fail-open: enrichment must never drop or corrupt an event -- but
            # the exception MUST be visible (gap-hunt finding 4), or a bug in
            # this stage is indistinguishable from \"data matched nothing\".
            _LOGGER.warning("enrichment exception, returning event unchanged "
                            "(fail-open): %s: %s", type(exc).__name__, exc)
        return event


_default_enricher: Optional[Enricher] = None


def enrich(event: dict) -> dict:
    """Enrich via the process-wide default Enricher (loads local files once)."""
    global _default_enricher
    if _default_enricher is None:
        _default_enricher = Enricher()
    return _default_enricher.enrich(event)
