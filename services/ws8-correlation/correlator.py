"""WS-8 correlation engine: per-entity alert tracks -> promoted incidents.

Design: `docs/superpowers/specs/2026-08-18-ws8-correlation-build-plan.md`
(this repo) and `fengarde-sec`'s `docs/2026-08-11-cross-alert-correlation-
design.md` (private repo, full rationale). This module implements the
`Correlator` class only -- bus wiring lives in `main.py`.

Core rules (see INTERFACE.md for the full account):
  - Every alert updates BOTH an `actor:{name}` track and an `ip:{addr}`
    track independently. The two NEVER merge -- no compound key, no
    transitive join across shared entities.
  - A track is promoted to an incident once its live members carry >=2
    DISTINCT `mitre.tactic` values. Score-sum is the incident's `severity`
    (ranking), never the trigger.
  - Tenant is part of the track key, never a filter -- a tenant-agnostic
    key would silently correlate across customers.
  - An allowlisted `src_endpoint.ip` (contracts/allowlists/
    shared_infrastructure.yml) never opens an `ip:` track at all.
  - `incident_id` is deterministic (T7-style fixed-epoch bucket), so a
    growing incident re-emits under the SAME id and WS-3's existing OCC/CAS
    path updates one document instead of accumulating duplicates.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))

from shared.allowlist import Allowlist, load_allowlist  # noqa: E402
from shared.envelope import valid_tenant_id  # noqa: E402
from shared.window import DequeWindowCounter  # noqa: E402

DEFAULT_TENANT = "default"
DEFAULT_HORIZON_S = 86400  # 24h -- a starting default, not a measured one (see INTERFACE.md)
DEFAULT_MEMBER_CAP = 200

_ALLOWLIST_NAME = "shared_infrastructure"


def _to_str(x) -> str:
    """Decode a possibly-bytes value to str. NOT the same as ``str(x)`` --
    ``str(b"bz1")`` produces the literal ``"b'bz1'"``, not ``"bz1"``; found
    this exact mistake in this file's own first attempt at the live
    2026-08-18 bytes-vs-str fix (see main.py's decode_responses note), so
    the wrong fix is preserved here as the reason this helper exists at
    all rather than a plain ``str()`` call at each use site."""
    return x.decode() if isinstance(x, bytes) else str(x)


def _contracts_dir() -> Path:
    """contracts/ lives at repo/contracts on a host checkout or /app/contracts
    inside the container (the Dockerfile's `COPY contracts /app/contracts`)
    -- SERVICES (/app or repo/services) is a different ancestor depth in
    each case. Same dual-probe helper `ws4-detection/main.py::_contracts_dir`
    already uses, for the exact same reason. Found crash-looping live
    (2026-08-18, first `docker compose up`): a single hardcoded
    `SERVICES.parent / "contracts"` resolved to the host path correctly but
    to `/contracts` (one level too high) inside the container, so the
    shared-infrastructure allowlist silently failed to load -- failing
    open on failed-to-load is safe here (see shared/allowlist.py's own
    fail-closed-on-load docstring: it never suppresses when unloadable), but
    it's still a bug, not a feature, and would confuse an operator who
    populated the file expecting it to take effect."""
    for base in (SERVICES, SERVICES.parent):
        if (base / "contracts" / "allowlists").exists():
            return base / "contracts"
    return SERVICES.parent / "contracts"


class InvalidTenant(ValueError):
    """Raised when an alert's tenant_id isn't safe to embed in a track key
    or incident_id (reject-at-edge, same discipline as WS-3's router.py
    ``_validated_tenant`` -- never normalize a bad tenant_id, since
    normalizing two different bad ids to the same value would silently
    merge two customers' correlation state)."""


def _validated_tenant(tenant) -> str:
    tenant = tenant or DEFAULT_TENANT
    if tenant != DEFAULT_TENANT and not valid_tenant_id(tenant):
        raise InvalidTenant(f"invalid tenant_id {tenant!r}")
    return tenant


class Correlator:
    """Tracks per-(tenant, entity_type, entity_value) alert activity and
    promotes a track to an incident on multi-tactic evidence.

    ``window_counter`` is a DequeWindowCounter (default, in-process, tests)
    or RedisWindowCounter (multi-replica, real deployments) -- the exact
    primitive WS-4's stateful rules already use, reused rather than
    reinvented (see module docstring).
    """

    def __init__(self, window_counter=None, *, horizon_s: int = DEFAULT_HORIZON_S,
                 member_cap: int = DEFAULT_MEMBER_CAP,
                 allowlists_dir: Path | str | None = None,
                 allowlist: Allowlist | None = None,
                 now_fn=time.time):
        self.window_counter = window_counter or DequeWindowCounter()
        self.horizon_s = horizon_s
        self.horizon_ms = horizon_s * 1000
        self.member_cap = member_cap
        self._now_fn = now_fn
        if allowlist is not None:
            self._allowlist = allowlist
        else:
            self._allowlist = load_allowlist(
                Path(allowlists_dir) if allowlists_dir else
                (_contracts_dir() / "allowlists"),
                _ALLOWLIST_NAME,
            )
        # incident_id -> last-emitted incident dict, so a re-emission can be
        # recognized as an UPDATE (same id) rather than manufacturing a
        # fresh one every call. Bounded implicitly by window-key eviction
        # (a track's members age out via the window counter; a stale
        # incident_id entry here is harmless dead weight, not a correctness
        # issue -- see metrics()/note on unbounded growth in INTERFACE.md).
        self._last_incident: dict[str, dict] = {}
        # track_key -> {alert_id: {tactic, score, time}}. The window_counter
        # only knows MEMBERSHIP (alert_id + time); tactic/score need a side
        # table keyed the same way, pruned to the same live-member set on
        # every hit. Instance attribute (not class-level) -- a class-level
        # dict here would silently share state across every Correlator
        # instance, which is exactly the kind of cross-tenant/cross-test
        # leak this module's own tenant-isolation discipline exists to
        # prevent elsewhere.
        self._sides: dict[str, dict] = {}
        self.truncated_count = 0
        self.promotions_count = 0

    def _now_ms(self) -> int:
        return int(self._now_fn() * 1000)

    def _track_key(self, tenant: str, entity_type: str, entity_value: str) -> str:
        return f"{tenant}:{entity_type}:{entity_value}"

    def _horizon_bucket(self, now_ms: int) -> int:
        return now_ms // self.horizon_ms

    def _incident_id(self, tenant: str, entity_type: str, entity_value: str, now_ms: int) -> str:
        return f"{tenant}:{entity_type}:{entity_value}:{self._horizon_bucket(now_ms)}"

    def _update_track(self, tenant: str, entity_type: str, entity_value: str,
                       alert: dict, now_ms: int) -> dict | None:
        """Record ``alert`` on one entity track; return a fresh incident
        dict if the track is (still, or newly) promoted, else None."""
        key = self._track_key(tenant, entity_type, entity_value)
        member = _to_str(alert.get("alert_id"))
        self.window_counter.hit(key, now_ms, self.horizon_ms, member=member)
        # _to_str()-normalized, NOT str(): a real (non-fake) redis-py client
        # without decode_responses=True returns bytes from ZRANGE, which
        # would never string-equal the plain-str keys `side` below is keyed
        # by -- found exactly this way live (2026-08-18, see main.py's own
        # fix note). Defense in depth: main.py's client IS constructed with
        # decode_responses=True, but this method should not silently break
        # again if that ever regresses or a future caller passes a
        # differently-configured client/backend.
        live_ids = {_to_str(m) for m in self.window_counter.members(key)}

        # Evicted on the same schedule as the window itself: any id no
        # longer reported by window.members() (aged out past the horizon)
        # is dropped from the side table too, so a quiet track's side entry
        # shrinks to empty exactly when its window state does.
        side = self._sides.setdefault(key, {})
        side[member] = {
            "alert_id": member,
            "tactic": (alert.get("mitre") or {}).get("tactic"),
            "score": alert.get("score") or 0,
            "time": alert.get("time") or now_ms,
        }
        for stale_id in list(side):
            if stale_id not in live_ids:
                del side[stale_id]

        live = [side[m] for m in live_ids if m in side]
        truncated = False
        if len(live) > self.member_cap:
            live.sort(key=lambda m: m["time"], reverse=True)
            live = live[: self.member_cap]
            truncated = True
            self.truncated_count += 1

        tactics = sorted({m["tactic"] for m in live if m["tactic"]})
        if len(tactics) < 2:
            return None  # single-tactic (or untagged-only) track: not yet an incident

        incident_id = self._incident_id(tenant, entity_type, entity_value, now_ms)
        incident = {
            "incident_id": incident_id,
            "tenant_id": tenant,
            "entity_type": entity_type,
            "entity_value": entity_value,
            "first_seen": min(m["time"] for m in live),
            "last_seen": max(m["time"] for m in live),
            "tactics": tactics,
            "member_alert_ids": sorted(m["alert_id"] for m in live),
            "member_count": len(live),
            "severity": min(sum(m["score"] for m in live), 1000),
            "truncated": truncated,
        }
        is_new = incident_id not in self._last_incident
        self._last_incident[incident_id] = incident
        if is_new:
            self.promotions_count += 1
        return incident

    def ingest_alert(self, alert: dict) -> list[dict]:
        """Feed one alert through both its entity tracks. Returns 0-2 fresh/
        updated incident dicts (actor-track incident, ip-track incident) --
        empty if neither track is promoted, or if the alert's IP is
        allowlisted shared infrastructure (no ip: track opened at all)."""
        tenant = _validated_tenant(alert.get("tenant_id"))
        now_ms = self._now_ms()
        incidents: list[dict] = []

        actor_name = (alert.get("actor") or {}).get("user", {}).get("name")
        if actor_name:
            inc = self._update_track(tenant, "actor", str(actor_name), alert, now_ms)
            if inc is not None:
                incidents.append(inc)

        src_ip = (alert.get("src_endpoint") or {}).get("ip")
        if src_ip and not self._allowlist.matches(src_ip):
            inc = self._update_track(tenant, "ip", str(src_ip), alert, now_ms)
            if inc is not None:
                incidents.append(inc)

        return incidents

    def metrics(self) -> dict:
        return {
            "ws8_active_tracks": len(self._sides),
            "ws8_promotions_total": self.promotions_count,
            "ws8_truncated_total": self.truncated_count,
        }
