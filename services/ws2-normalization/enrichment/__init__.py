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
"""
from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Optional

import yaml

_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_IOC = _ROOT / "contracts" / "enrichment" / "ioc.yml"
_DEFAULT_GEOIP = _ROOT / "contracts" / "enrichment" / "geoip.yml"


def _load_entries(path: Path) -> list[dict]:
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return []  # missing/unreadable/malformed -> no enrichment, never raise
    entries = raw.get("entries") if isinstance(raw, dict) else None
    return [e for e in entries if isinstance(e, dict)] if isinstance(entries, list) else []


class Enricher:
    def __init__(self, ioc_path: Path | str = _DEFAULT_IOC,
                 geoip_path: Path | str = _DEFAULT_GEOIP):
        self._ioc_exact: dict[str, dict] = {}
        self._ioc_nets: list[tuple] = []          # (network, entry)
        self._geo_nets: list[tuple] = []          # (network, country)
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
            try:
                ipaddress.ip_address(ip)
                self._ioc_exact[ip] = record
                return
            except ValueError:
                pass
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
        Never overwrites an existing key; never raises."""
        try:
            src = event.get("src_endpoint") if isinstance(event, dict) else None
            if not isinstance(src, dict):
                return event
            ip = src.get("ip")
            if not isinstance(ip, str) or not ip:
                return event
            if "reputation" not in src:
                rep = self._reputation_for(ip)
                if rep is not None:
                    src["reputation"] = rep
            if "location" not in src:
                loc = self._location_for(ip)
                if loc is not None:
                    src["location"] = loc
        except Exception:
            pass  # fail-open: enrichment must never drop or corrupt an event
        return event


_default_enricher: Optional[Enricher] = None


def enrich(event: dict) -> dict:
    """Enrich via the process-wide default Enricher (loads local files once)."""
    global _default_enricher
    if _default_enricher is None:
        _default_enricher = Enricher()
    return _default_enricher.enrich(event)
