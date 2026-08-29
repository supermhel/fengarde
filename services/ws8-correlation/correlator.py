"""WS-8 correlation engine: per-entity alert tracks -> promoted incidents.

Design: `docs/superpowers/specs/2026-08-18-ws8-correlation-build-plan.md`
(this repo) and `fengarde-sec`'s `docs/2026-08-11-cross-alert-correlation-
design.md` (private repo, full rationale). This module implements the
`Correlator` class only -- bus wiring lives in `main.py`.

Core rules (see INTERFACE.md for the full account):
  - Every alert updates an `actor:{name}` track, an `ip:{addr}` track, and
    (2026-08-19, pivot-correlation) a `device:{mac-or-hostname}` track,
    each independently. The three NEVER merge -- no compound key, no
    transitive join across shared entities. `device:` closes the
    documented "actor pivots to a new IP" gap for the case that's actually
    evidenced without inference: a DHCP lease renewal or NAT re-mapping
    changes an attacker's `src_endpoint.ip` mid-attack, but
    `src_endpoint.mac` (falling back to `.hostname`) identifies the same
    physical/virtual host across that IP churn, straight off the same
    parser-populated OCSF field, never guessed. An authenticated actor
    pivoting IP was ALREADY correlated before this change -- `actor:{name}`
    is keyed on identity alone with no IP component, so two alerts naming
    the same actor from two different IPs already land on one track. The
    `device:` track's real job is the harder, previously-unclosed case:
    activity with NO captured actor identity (pre-auth recon, unauth
    probing) that moves IP on the same host. Two alerts with no
    `mac`/`hostname` at all, or an attacker who genuinely switches to a
    different physical host under a brand-new identity, remain the honest,
    accepted-limitation residual -- no real signal is left to link them
    without fabricating one.
  - A track is promoted to an incident once its live members carry >=2
    DISTINCT `mitre.tactic` values. Score-sum is the incident's `severity`
    (ranking), never the trigger.
  - Tenant is part of the track key, never a filter -- a tenant-agnostic
    key would silently correlate across customers.
  - An allowlisted `src_endpoint.ip` (contracts/allowlists/
    shared_infrastructure.yml) never opens an `ip:` track at all; since
    2026-08-26 the same suppression applies to a `device:` track keyed on
    an allowlisted (spoofable, unauthenticated) hostname/mac.
  - `incident_id` is deterministic (T7-style fixed-epoch bucket), so a
    growing incident re-emits under the SAME id and WS-3's existing OCC/CAS
    path updates one document instead of accumulating duplicates.
  - Every incident promotion/update ALSO emits the ADR-009 `incident.graph`
    payload (2026-08-28, WP-2-C) -- purely ADDITIVE, the incident dict
    above is untouched. Nodes are the incident's member entities
    (actor/user, ip, device -- the SAME track identity the incident already
    captures, as `{entity_type}:{entity_value}`); edges are ONLY the
    relationships a SINGLE alert's own fields provide (actor+src_ip,
    src_ip+device mac/hostname, actor+device), each carrying `event_id` +
    `ts_ms` provenance from the alert that evidenced it. NO transitive
    inference: two alerts that merely share an entity never yield an edge
    between their other entities. The payload is rebuilt from the track's
    LIVE members on every promotion (deterministic + idempotent under
    redelivery) and is bounded by them; see `_build_incident_graph` and
    `incident_graph()`.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import math
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))

from shared.allowlist import Allowlist, load_allowlist, invalidate_dir  # noqa: E402
from shared.envelope import valid_tenant_id  # noqa: E402
from shared.log import get_logger  # noqa: E402
from shared.window import DequeWindowCounter  # noqa: E402

_log = get_logger("ws8-correlation")

DEFAULT_TENANT = "default"
DEFAULT_HORIZON_S = 86400  # 24h -- a starting default, not a measured one (see INTERFACE.md)
DEFAULT_MEMBER_CAP = 200

# OpenSearch rejects document ids longer than 512 bytes, and the incident
# doc id embeds entity_value (`{tenant}:{etype}:{value}:{horizon_bucket}`).
# 448 leaves headroom for the tenant/etype/bucket suffix on top of the
# value. Attacker-controlled usernames/hostnames are the classic way a
# 513-byte id would silently dead-letter an incident (gap-hunt finding,
# 2026-08-26) -- see `_bounded_entity_value`.
_ENTITY_VALUE_MAX_BYTES = 448

# Tolerated source clock drift for alert `time` values that drive the
# correlator's per-track anchors (first_seen -> incident_id bucket, and the
# member-cap eviction ordering). Same ceiling WS-4's
# engine.py::_MAX_CLOCK_SKEW_MS applies to a stateful rule's event time:
# an attacker who stamps an alert implausibly far ahead of wall-clock
# must not be able to shift a track's first_seen (and thereby the whole
# incident_id horizon bucket) or its eviction ordering.
_MAX_CLOCK_SKEW_MS = 300_000  # 5 minutes of tolerated source clock drift

_ALLOWLIST_NAME = "shared_infrastructure"

# How often (in _update_track calls) Correlator sweeps _sides/_last_incident
# for tracks whose window membership has gone fully empty. Same amortized-
# full-scan pattern and same period as shared/window.py's own _SWEEP_EVERY
# (a group that stops producing alerts is never revisited on its own -- we
# only touch a track's _sides entry on a hit for THAT exact key), and the
# same reason: an internet-facing correlator grouping by actor/ip/device is
# otherwise an unbounded-growth OOM vector for an attacker who sprays many
# distinct identities once and never repeats one (see `_sweep_dead_tracks`'s
# own docstring and the 2026-08-19 independent-review finding this closes).
_SIDES_SWEEP_EVERY = 256


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


def _valid_window_time(value, now_ms: int) -> int | None:
    """Return alert ``time`` as epoch-ms int if it can safely drive the
    track's anchors (first_seen -> incident_id bucket, member-cap eviction
    ordering), else None (fail closed). Rejects bool, non-numeric, NaN/inf,
    and timestamps implausibly far ahead of the correlator's wall clock
    (see _MAX_CLOCK_SKEW_MS). Past timestamps always pass -- that is
    legitimate historical replay. Same guard WS-4's
    engine.py::_valid_window_time applies to ITS stateful windows; WS-8's
    alert ``time`` is equally attacker-controlled, so a skew-future
    timestamp must not drive first_seen/incident_id/eviction ordering
    (gap-hunt finding, 2026-08-27)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    now = int(value)
    if now > now_ms + _MAX_CLOCK_SKEW_MS:
        return None
    return now


def _file_mtime_ns(path: Path) -> "int | None":
    """st_mtime_ns of ``path``, or None if the file is absent/stat fails."""
    try:
        return path.stat().st_mtime_ns
    except OSError:
        return None


# ADR-009 `incident.graph` edge kinds (version 1, flat field-pair
# semantics; Phase 3 upgrades to the typed causal DAG -- caused_by /
# invoked / authenticated_as / wrote_to / changed -- via version: 2).
# Each kind names the relationship a SINGLE alert's own fields evidence:
#   used_ip       actor  -> src_endpoint.ip            (actor.user.name + ip)
#   used_device   actor  -> src_endpoint.mac|hostname  (actor.user.name + device)
#   seen_at_ip    device -> src_endpoint.ip            (mac|hostname + ip)
# Direction is fixed by the pair semantics (never by which track promoted),
# so the same co-occurring pair renders the same directed edge in every
# incident. There is no same-type kind: one alert carries at most one value
# per entity type, so an alert can never evidence an actor-actor (or ip-ip)
# edge -- inventing one would be transitive inference, which is prohibited.
_EDGE_KINDS = {
    ("actor", "ip"): ("used_ip", "actor", "ip"),
    ("actor", "device"): ("used_device", "actor", "device"),
    ("device", "ip"): ("seen_at_ip", "device", "ip"),
}
_ENTITY_TYPE_ORDER = ("actor", "device", "ip")  # canonical unordered-pair keying


def _edge_spec(type_a: str, type_b: str) -> "tuple[str, str, str] | None":
    """Canonical ``(kind, from_type, to_type)`` for a co-occurring entity
    type pair (see _EDGE_KINDS), or None for a same-type pair (unreachable
    from one alert, and prohibited -- same-type linkage would be
    cross-alert inference). The unordered pair maps to exactly ONE directed
    edge; a pair is never reversed into a second edge and never dropped for
    ordering reasons."""
    if type_a == type_b:
        return None
    pair: "tuple[str, str]" = tuple(sorted((type_a, type_b), key=_ENTITY_TYPE_ORDER.index))  # type: ignore[assignment]
    return _EDGE_KINDS[pair]


def _provenance_event_id(alert: dict, member_id: str) -> str:
    """The ``event_id`` provenance recorded on a graph edge.

    The alert's own underlying event handle: the first ``event_ids``
    element when present (WS-4's make_alert carries the event(s) that
    fired the rule), else the alert-level member id (``alert_id``, or the
    deterministic synthetic id for id-less alerts). Deterministic under
    redelivery -- a re-delivered alert re-derives the same provenance on
    every edge it evidences."""
    event_ids = alert.get("event_ids")
    if event_ids:
        ev = event_ids if isinstance(event_ids, (list, tuple)) else [event_ids]
        if ev and _to_str(ev[0]):
            return _to_str(ev[0])
    return member_id


def _canonical_ip(value) -> str:
    """Canonical spelling of an IP for track identity (IPv6 identity gap,
    2026-08-29 review): IPv6 is case- AND compression-insensitive --
    ``2001:DB8::1``, ``2001:db8:0:0:0:0:0:1`` and
    ``2001:0db8:0000:0000:0000:0000:0000:0001`` are ONE address. Keying
    ``ip:`` tracks on the raw parser spelling would split one address into
    several tracks (identity-evasion: a two-tactic spray across spellings
    never promotes). stdlib-only on purpose: this container cannot import
    ``shared.ocsf`` (its tools/ dependency is not shipped in the ws8 image),
    so mirror ``valid_ip``'s canonical output here. Non-IP values pass
    through unchanged.
    """
    try:
        addr = ipaddress.ip_address(str(value))
    except ValueError:
        return str(value)
    mapped = getattr(addr, "ipv4_mapped", None)
    return str(mapped) if mapped is not None else str(addr)


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
            # No on-disk reload source: a caller-injected allowlist (tests)
            # has no directory to watch, so the reload hook is a no-op.
            self._allowlists_dir: "Path | None" = None
            self._allowlist_path: "Path | None" = None
            self._allowlist_mtime: "int | None" = None
        else:
            self._allowlists_dir = Path(allowlists_dir) if allowlists_dir else (
                _contracts_dir() / "allowlists")
            self._allowlist_path = self._allowlists_dir / f"{_ALLOWLIST_NAME}.yml"
            # R3-59 (2026-08-26): remember the on-disk mtime so
            # reload_allowlist_if_changed() can detect an operator edit.
            self._allowlist_mtime = _file_mtime_ns(self._allowlist_path)
            self._allowlist = load_allowlist(self._allowlists_dir, _ALLOWLIST_NAME)
        # incident_id -> last-emitted incident dict, so a re-emission can be
        # recognized as an UPDATE (same id) rather than manufacturing a
        # fresh one every call. NOT bounded implicitly by window-key
        # eviction (that claim was inaccurate -- an independent 2026-08-19
        # review found window eviction only frees the window_counter's OWN
        # state; this dict and `_sides` below are separate side tables that
        # were only ever written, never pruned, so a track touched exactly
        # once grew both dicts forever). Actually bounded now by
        # `_sweep_dead_tracks()`, called periodically from `_update_track`.
        self._last_incident: dict[str, dict] = {}
        # incident_id -> ADR-009 `incident.graph` payload emitted alongside
        # the SAME incident promotion/update (2026-08-28, WP-2-C). Mirrors
        # `_last_incident` exactly: same key set (written together in the
        # promotion branch, pruned together by `_sweep_dead_tracks`), so it
        # inherits the same boundedness -- never more than one entry per
        # live promoted track, evicted when the track's window membership
        # dies. No separate unbounded side table.
        self._incident_graphs: dict[str, dict] = {}
        # track_key -> {alert_id: {tactic, score, time}}. The window_counter
        # only knows MEMBERSHIP (alert_id + time); tactic/score need a side
        # table keyed the same way, pruned to the same live-member set on
        # every hit AND capped at `member_cap` (2026-08-26 gap-hunt finding:
        # member_cap used to bound only the emitted payload, so a sustained
        # attack past the cap grew `_sides[key]` without limit -- reproduced
        # as 401 side-table entries at member_cap=200). Oldest members are
        # evicted when the cap binds; the tracked evidence survives in
        # `_side_meta` below, so capping never erases a track's tactics.
        # Instance attribute (not class-level) -- a class-level
        # dict here would silently share state across every Correlator
        # instance, which is exactly the kind of cross-tenant/cross-test
        # leak this module's own tenant-isolation discipline exists to
        # prevent elsewhere.
        self._sides: dict[str, dict] = {}
        # track_key -> {"first_seen": ms, "tactics": set, "truncated": bool}.
        # The STABLE per-track aggregate that survives `_sides` member-cap
        # eviction (and horizon eviction, for as long as the track itself
        # stays live): promotion tactics and the incident_id anchor
        # (first_seen) must never depend on which members happen to have
        # survived truncation -- a 1-recon + 400-brute-force track used to
        # silently freeze (truncated list showed one tactic) and could emit
        # under multiple incident_ids as the truncation minimum shifted
        # (2026-08-26 gap-hunt findings). Bounded: one tiny dict per live
        # track, pruned by the same `_sweep_dead_tracks()` sweep as `_sides`.
        self._side_meta: dict[str, dict] = {}
        # track_key -> now_ms of its most recent _update_track call -- mirrors
        # shared/window.py's own `_last[key]` exactly (same field, same
        # purpose: staleness is measured from processing time, the SAME
        # basis `window_counter.hit()` uses to evict, not from an event's
        # own possibly-attacker-controlled `time` field). Used by
        # `_sweep_dead_tracks` instead of asking the window_counter itself,
        # since `members()` doesn't self-trim by current time -- it only
        # reflects whatever the window counter's OWN periodic sweep (a
        # different cadence, keyed off total hit count across every key)
        # has gotten around to evicting so far, which is not necessarily by
        # the time OUR sweep runs.
        self._last_touch: dict[str, int] = {}
        # reason -> count of alerts that opened NO track (no_trackable_entity
        # -- e.g. WS-5's enrichment alerts carry no actor/src_endpoint at
        # all -- or allowlisted_device/allowlisted_ip shared infrastructure).
        # 2026-08-26 gap-hunt: every WS-5 alert used to be a SILENT no-op in
        # correlation; degrade-don't-crash means the silence is observable.
        self._skip_reasons: dict[str, int] = {}
        self.truncated_count = 0
        self.promotions_count = 0
        self._update_calls = 0  # counts _update_track calls, for _sweep_dead_tracks' cadence

    def _now_ms(self) -> int:
        return int(self._now_fn() * 1000)

    def _track_key(self, tenant: str, entity_type: str, entity_value: str) -> str:
        return f"{tenant}:{entity_type}:{entity_value}"

    def _horizon_bucket(self, basis_ms: int) -> int:
        return basis_ms // self.horizon_ms

    def _incident_id(self, tenant: str, entity_type: str, entity_value: str, basis_ms: int) -> str:
        return f"{tenant}:{entity_type}:{entity_value}:{self._horizon_bucket(basis_ms)}"

    def _bounded_entity_value(self, entity_value) -> str:
        """Bound entity_value so the incident doc id -- which embeds it --
        can never exceed OpenSearch's 512-byte document-id limit. An
        attacker-controlled username/hostname past that limit used to make
        the whole incident an OpenSearch rejection, treated as permanent /
        dead-lettered: an attacker-suppressible incident (2026-08-26
        gap-hunt finding). Truncate + a stable sha256 suffix, rather than
        skip: two distinct long values keep DISTINCT keys (no false merge --
        this module's never-merge discipline must survive the cap), and a
        redelivered alert re-derives the same key (idempotent)."""
        raw = str(entity_value)
        encoded = raw.encode("utf-8", errors="replace")
        if len(encoded) <= _ENTITY_VALUE_MAX_BYTES:
            return raw
        digest = hashlib.sha256(encoded).hexdigest()[:16]
        head = encoded[: _ENTITY_VALUE_MAX_BYTES - 17].decode("utf-8", errors="replace")
        return f"{head}:{digest}"

    def _member_id(self, alert: dict) -> str:
        """The window/side-table member id for ``alert``.

        ``alert_id`` when present. A missing (or empty) ``alert_id`` used to
        stringify to the literal ``'None'``, so every id-less alert collapsed
        onto ONE member -- unrelated alerts deduplicated against each other
        and a two-tactic pair of id-less alerts could never promote
        (2026-08-26 gap-hunt finding). Fall back to a synthetic id built
        from the fields that DO identify the alert (time/rule_id/event_ids):
        deterministic, so redelivery of the same id-less alert re-derives
        the same member (idempotency preserved), and distinct for different
        alerts (no false dedup). A fully anonymous alert (none of those
        fields either) gets a deterministic hash of its own payload -- it
        can't be deduplicated on a field, but it must never MERGE with a
        different alert, and redelivery of the SAME anon alert must re-derive
        the same member (2026-08-27 finding: the old per-instance anon-seq
        counter made the same anon alert redelivered 3x inflate to 3 members).
        """
        alert_id = alert.get("alert_id")
        if alert_id not in (None, ""):
            return _to_str(alert_id)
        parts: list[str] = []
        t = alert.get("time")
        if t is not None:
            parts.append(str(t))
        rule_id = alert.get("rule_id")
        if rule_id is not None:
            parts.append(str(rule_id))
        event_ids = alert.get("event_ids")
        if event_ids:
            ev = event_ids if isinstance(event_ids, (list, tuple)) else [event_ids]
            parts.append("|".join(_to_str(e) for e in ev))
        if parts:
            return "anon:" + ":".join(parts)
        # A fully anonymous alert (none of alert_id/time/rule_id/event_ids
        # either) can't be deduplicated on any of those fields. Used to mint
        # a per-instance sequence id (anon-seq:{n}) -- the ONE
        # non-deterministic member id in the correlator: the same anon alert
        # redelivered 3x (at-least-once bus) inflated into 3 members, and a
        # multi-replica deployment couldn't agree on a member id at all.
        # Now hash the payload instead: deterministic across processes, so
        # redelivery re-derives the same member (idempotency preserved) and
        # distinct anon alerts stay distinct (a 64-bit digest collision is
        # negligible for a member id). Mirrors WS-4
        # engine.py::_event_fingerprint's sorted-key JSON approach.
        try:
            blob = json.dumps(alert, sort_keys=True, default=str)
        except (TypeError, ValueError):
            blob = repr(alert)
        digest = hashlib.sha256(blob.encode("utf-8", "replace")).hexdigest()[:16]
        return f"anon:{digest}"

    def _cooccurring_entities(self, alert: dict, own_type: str) -> list[tuple[str, str]]:
        """The OTHER entity fields this single alert carries, as
        ``(entity_type, entity_value)`` pairs -- the provenance-backed
        relationship sources of the incident graph (WP-2-C, ADR-009).

        Mirrors ingest_alert's per-leg extraction EXACTLY (same
        degrade-don't-crash handling for a non-dict ``actor.user``, same
        mac-or-hostname device fallback, same raw values the tracks key
        on), minus the leg that IS this track: ``own_type`` excludes the
        track's own entity, because a track's member can never co-occur
        with itself. An allowlisted shared-infra ip/hostname still appears
        here -- it is a fact evidenced by the recording alert's own fields
        (never a cross-alert merge; the allowlist's job, not opening an
        ``ip:``/``device:`` TRACK, is untouched)."""
        out: list[tuple[str, str]] = []
        actor = alert.get("actor") or {}
        user = actor.get("user") or {}
        if not isinstance(user, dict):
            user = {}
        if user.get("name") and own_type != "actor":
            out.append(("actor", str(user["name"])))
        src = alert.get("src_endpoint") or {}
        if src.get("ip") and own_type != "ip":
            # Canonical spelling, same IPv6 identity discipline as the ip:
            # track leg (an expanded/case-variant co-occurring address must
            # reference the SAME node the track would key).
            out.append(("ip", _canonical_ip(src["ip"])))
        device = src.get("mac") or src.get("hostname")
        if device and own_type != "device":
            out.append(("device", str(device)))
        return out

    def _build_incident_graph(self, tenant: str, entity_type: str, entity_value: str,
                              incident: dict, side: dict) -> dict:
        """Build the ADR-009 ``incident.graph`` payload for a promoted
        track from its live member side-table entries.

        - ``nodes``: the incident's member entities -- the track's own
          anchor plus every co-occurring entity its member alerts carry --
          as ``{entity_type}:{entity_value}`` (the SAME track identity the
          incident itself captures). Every value was bounded at STORE time
          by ``_update_track`` (``entry["cooccur"]`` goes through
          ``_bounded_entity_value``), so an attacker-controlled >448-byte
          name cannot blow the payload here (same doc-id-budget discipline
          as the incident's own entity_value).
        - ``edges``: ONLY pairs co-occurring within a SINGLE member alert's
          own fields, deduped with the EARLIEST (ts_ms, event_id)
          provenance kept. **No transitive inference**: two alerts that
          merely share an entity never produce an edge between their other
          entities -- an edge exists iff one member alert carries both
          endpoints itself.
        - ``tactic_sources``: tactic -> member alert ids (live members)
          carrying it, mirroring the incident's own member_alert_ids
          attribution (a tactic whose only member was cap-evicted lists no
          live source; the tactic still appears, exactly as it does in the
          incident's ``tactics``).
        Deterministic under redelivery (same members -> same nodes, edges,
        provenance) and bounded by the member set: <=3 co-occurring pairs
        per member, so <=3*len(live) edges; nodes = 1 anchor + distinct
        co-occurring values across live members."""
        anchor = f"{entity_type}:{entity_value}"
        nodes = {anchor}
        # (from,to,kind) -> (ts_ms, event_id); the EARLIEST provenance wins,
        # so an edge evidenced by several members cites the first evidence.
        best: dict[tuple, tuple] = {}
        for member_id, entry in side.items():
            refs = [(entity_type, entity_value)]
            for other_type, other_value in entry.get("cooccur") or []:
                # Already bounded at STORE time -- `_update_track` writes
                # `entry["cooccur"]` through `_bounded_entity_value` (the
                # single writer of this table), so no re-bound here.
                refs.append((other_type, other_value))
            for i in range(len(refs)):
                for j in range(i + 1, len(refs)):
                    spec = _edge_spec(refs[i][0], refs[j][0])
                    if spec is None:
                        continue
                    kind, from_type, to_type = spec
                    a, b = refs[i], refs[j]
                    fv = a[1] if a[0] == from_type else b[1]
                    tv = b[1] if b[0] == to_type else a[1]
                    f_node, t_node = f"{from_type}:{fv}", f"{to_type}:{tv}"
                    nodes.add(f_node)
                    nodes.add(t_node)
                    key = (f_node, t_node, kind)
                    # Edge provenance, deterministic under redelivery. For a
                    # member whose entry time was the wall-clock fallback
                    # (time-less / skew-future alert -- entry time may differ
                    # across redeliveries), pin ts_ms to a stable digest of the
                    # member id instead, so the graph is identical no matter
                    # when it is rebuilt (independent-review WP-2-C #2: the
                    # "identical graph under redelivery" claim must hold for
                    # time-less alerts too). event_id is already deterministic
                    # via _provenance_event_id.
                    if entry.get("time_fallback"):
                        import hashlib  # local: fallback path only
                        ts = int(hashlib.sha256(
                            str(member_id).encode("utf-8", errors="replace")
                        ).hexdigest()[:12], 16)
                    else:
                        ts = entry.get("time", 0)
                    cand = (ts, entry.get("event_id") or member_id)
                    if key not in best or cand < best[key]:
                        best[key] = cand
        edges = [{"from": f, "to": t, "kind": k, "event_id": ev, "ts_ms": ts}
                 for (f, t, k), (ts, ev) in sorted(best.items())]
        tactic_sources = {
            tactic: sorted(mid for mid, e in side.items() if e.get("tactic") == tactic)
            for tactic in incident["tactics"]
        }
        return {
            "version": 1,
            "incident_id": incident["incident_id"],
            "tenant_id": incident["tenant_id"],
            "nodes": sorted(nodes),
            "edges": edges,
            "tactic_sources": tactic_sources,
        }

    def _sweep_dead_tracks(self, now_ms: int) -> None:
        """Drop `_sides`/`_side_meta`/`_last_incident`/`_last_touch` entries
        for tracks not touched within the last `horizon_s` (2026-08-19
        review finding, closed).

        `_update_track`'s own per-hit prune (below) only touches the ONE key
        being hit right now -- a track that simply stops receiving alerts is
        never revisited, so its `_sides[key]` entry (and any `_last_incident`
        entries pointing at it) would otherwise live forever, exactly the
        unbounded per-key-dict growth `shared/window.py`'s own `_sweep()`
        exists to prevent for the window counter itself. This is the same
        fix at the correlator's OWN side-table layer, on the same "a full
        scan every N calls is cheap enough, an unbounded dict is not"
        tradeoff `shared/window.py:_SWEEP_EVERY` already accepts -- and the
        SAME staleness basis (processing-time `now_ms`, via `_last_touch`,
        not the window_counter's own independently-timed internal sweep).

        A key only gets dropped once it hasn't been touched for a full
        horizon -- not merely "not touched this instant" -- so a still-live
        track (and the incident_id `test_replay_idempotency` depends on
        staying stable across redeliveries) is never touched.
        """
        stale_before = now_ms - self.horizon_ms
        dead_keys = [k for k, ts in self._last_touch.items() if ts < stale_before]
        if not dead_keys:
            return
        for k in dead_keys:
            self._sides.pop(k, None)
            self._side_meta.pop(k, None)
            self._last_touch.pop(k, None)
        dead_keys_set = set(dead_keys)
        for incident_id, incident in list(self._last_incident.items()):
            track_key = self._track_key(
                incident["tenant_id"], incident["entity_type"], incident["entity_value"])
            if track_key in dead_keys_set:
                del self._last_incident[incident_id]
                # WP-2-C: the incident.graph payload dies WITH its incident
                # (same key set, written together in the same promotion
                # branch, pruned together here) -- never an orphaned entry.
                self._incident_graphs.pop(incident_id, None)

    def _update_track(self, tenant: str, entity_type: str, entity_value: str,
                       alert: dict, now_ms: int) -> dict | None:
        """Record ``alert`` on one entity track; return a fresh incident
        dict if the track is (still, or newly) promoted, else None."""
        self._update_calls += 1
        if self._update_calls % _SIDES_SWEEP_EVERY == 0:
            self._sweep_dead_tracks(now_ms)
        # entity_value is attacker-controlled and embedded in the incident
        # doc id; bound it BEFORE any keying so the bounded form is the
        # single source of truth everywhere (track key, incident id, the
        # sweep's `_last_incident` reconstruction). The full value stays
        # visible on the incident as `entity_value_full` when truncated.
        bounded_value = self._bounded_entity_value(entity_value)
        entity_value_full = entity_value if bounded_value != entity_value else None
        entity_value = bounded_value
        key = self._track_key(tenant, entity_type, entity_value)
        self._last_touch[key] = now_ms
        # `_member_id()`, NOT `_to_str(alert.get("alert_id"))`: a missing
        # alert_id used to stringify to the literal 'None', collapsing every
        # id-less alert onto ONE shared member (see `_member_id`'s own
        # docstring for the synthetic-id fallback).
        member = self._member_id(alert)
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
        # Attacker-controlled alert `time` must not be trusted to drive the
        # track's anchors (first_seen -> incident_id bucket, member-cap
        # eviction ordering): present a skew-future/non-numeric time and it
        # used to shift first_seen and the whole horizon bucket (2026-08-27
        # finding). Apply the same _valid_window_time guard WS-4 uses; a
        # rejected value falls back to now_ms (honest processing time).
        valid_time = _valid_window_time(alert.get("time"), now_ms)
        entry = {
            "alert_id": member,
            "tactic": (alert.get("mitre") or {}).get("tactic"),
            "score": alert.get("score") or 0,
            # `valid_time or now_ms`: a rejected/falsy time (None, 0, NaN,
            # non-numeric, skew-future) falls back to the honest processing
            # time -- preserving the original `alert.get("time") or now_ms`
            # fallback WHILE adding the _valid_window_time guard, and keeping
            # a data-anchored first_seen only for genuine nonzero past times.
            "time": valid_time or now_ms,
            # Additive provenance flag (independent-review WP-2-C #2): records
            # that this entry's time was the wall-clock FALLBACK, not the
            # alert's own time -- so the incident graph can derive a stable
            # edge ts for time-less alerts instead of re-observing a different
            # wall clock on every redelivery. No consumer reads it; it exists
            # only for the graph's deterministic-provenance path. NOTE: the
            # falsy check `not valid_time` (not `valid_time is None`) covers
            # the `time: 0` case too -- a zero timestamp is not a usable anchor
            # (entry["time"] falls back to now_ms), so it must get the stable
            # digest, not a wall-clock edge ts (adversarial-reverify finding).
            "time_fallback": not valid_time,
        }
        side[member] = entry
        # WP-2-C (ADR-009): remember this single alert's other entity fields
        # (the provenance-backed relationship sources) and its underlying
        # event handle, so the incident graph -- built on promotion below --
        # can emit edges with event_id + ts_ms provenance. Additive entry
        # fields only: the member-keyed entry set (and _sides[key]'s length)
        # is unchanged, so the existing member-cap/window eviction discipline
        # still bounds this table exactly as before. NO cross-alert state is
        # accumulated here -- an edge is only ever evidenced by one alert.
        # Each co-occurring value is bounded at STORE time (not just graph
        # build) so an attacker-controlled >448-byte name cannot be retained
        # verbatim in the side table -- independent-review WP-2-C #3.
        entry["event_id"] = _provenance_event_id(alert, member)
        entry["cooccur"] = [
            (t, self._bounded_entity_value(v))
            for t, v in self._cooccurring_entities(alert, entity_type)
        ]
        for stale_id in list(side):
            if stale_id not in live_ids:
                del side[stale_id]

        # Stable per-track aggregate that survives member_cap eviction
        # (below): first_seen is the min member time EVER seen on this
        # still-live track, tactics the set EVER seen. A sustained attack
        # past the cap can therefore neither FREEZE the incident (gap-hunt
        # repro: 1 recon + 400 brute-force -> alerts #199-399 used to emit
        # nothing, because truncation left only the one-tactic flood) nor
        # shift the incident_id by truncating the earliest evidence away
        # (the same incident used to emit under 3 different ids as the
        # truncation minimum jumped). Bounded: one tiny dict per live track,
        # pruned alongside `_sides` by `_sweep_dead_tracks`.
        meta = self._side_meta.setdefault(
            key, {"first_seen": entry["time"], "tactics": set(), "truncated": False})
        meta["first_seen"] = min(meta["first_seen"], entry["time"])
        if entry["tactic"]:
            meta["tactics"].add(entry["tactic"])

        # member_cap bounds the side table ITSELF, not just the emitted
        # payload (gap-hunt finding: reproduced as 401 side-table entries at
        # member_cap=200). Evict the OLDEST members (by time) when the cap
        # binds -- the tracked evidence survives in `meta`, so capping never
        # erases a track's tactics.
        if len(side) > self.member_cap:
            excess = len(side) - self.member_cap
            for evict_id in sorted(side, key=lambda m: side[m]["time"])[:excess]:
                del side[evict_id]
            meta["truncated"] = True
            self.truncated_count += 1

        live = [side[m] for m in live_ids if m in side]
        if not live:
            return None  # in-window set empty (e.g. cap just dropped the only member)

        tactics = sorted(meta["tactics"])
        if len(tactics) < 2:
            return None  # single-tactic (or untagged-only) track: not yet an incident

        # Bucketed on first_seen (a property of the DATA), never on now_ms
        # (wall-clock processing time) -- the exact anti-pattern WS-4's own
        # Rule.alert_key() docstring calls out and avoids: "a stateful 'open
        # incident' anchor would key the id on processing order... the exact
        # undeduplicatable-duplicate failure this key exists to prevent."
        # Keying on now_ms was a real bug (caught by adversarial review,
        # 2026-08-19): a redelivery or a late-arriving alert for the SAME
        # growing track, processed at a different wall-clock moment than the
        # first promotion, would land in a different horizon bucket and mint
        # a SECOND incident_id for one conceptual incident -- silently
        # forking it into two documents, defeating the whole point of a
        # deterministic id. first_seen here is the `_side_meta` minimum
        # (stable even under member_cap truncation -- gap-hunt finding),
        # so the id stays anchored to the track's earliest evidence for as
        # long as the track itself stays live.
        first_seen = meta["first_seen"]
        incident_id = self._incident_id(tenant, entity_type, entity_value, first_seen)
        incident = {
            "incident_id": incident_id,
            "tenant_id": tenant,
            "entity_type": entity_type,
            "entity_value": entity_value,
            "first_seen": first_seen,
            "last_seen": max(m["time"] for m in live),
            "tactics": tactics,
            "member_alert_ids": sorted(m["alert_id"] for m in live),
            "member_count": len(live),
            "severity": min(sum(m["score"] for m in live), 1000),
            "truncated": meta["truncated"],
        }
        if entity_value_full is not None:
            incident["entity_value_full"] = entity_value_full
        is_new = incident_id not in self._last_incident
        self._last_incident[incident_id] = incident
        # WP-2-C (ADR-009): emit the incident.graph payload alongside EVERY
        # promotion/update -- purely ADDITIVE; the incident dict above keeps
        # its exact shape, the tactic-accumulation path is untouched (the
        # contract tests exercise that path unchanged). Rebuilt from the
        # track's LIVE members each call, so it is deterministic and
        # idempotent under redelivery (same members -> identical payload
        # under the same incident_id) and bounded by the member set
        # (<=3 edges per live member; one cache entry per incident_id,
        # pruned by _sweep_dead_tracks with _last_incident).
        self._incident_graphs[incident_id] = self._build_incident_graph(
            tenant, entity_type, entity_value, incident, side)
        if is_new:
            self.promotions_count += 1
        return incident

    def reload_allowlist_if_changed(self) -> bool:
        """R3-59 (2026-08-26): hot-reload the allowlist when the file on disk
        changes.

        WS-8 never called ``allowlist.invalidate_dir``, so once a
        shared_infrastructure.yml was loaded (cached in shared/allowlist's
        module cache) a subsequent operator edit stayed invisible for the
        process lifetime -- and, worse, an allowlist that failed to load was
        cached ``ok=False`` forever, so a broken file that was later fixed
        kept NOT suppressing (opening ip:/device: tracks) until restart.
        This is called on every ingest (cheap stat against the remembered
        mtime); when the file changed, invalidate_dir() drops the stale cache
        entry and load_allowlist() re-reads the new one.

        Returns True if a reload actually happened. A no-op when the
        correlator was constructed with a caller-injected ``allowlist`` (no
        on-disk source to watch)."""
        if self._allowlists_dir is None or self._allowlist_path is None:
            return False
        mtime = _file_mtime_ns(self._allowlist_path)
        if mtime is None or mtime == self._allowlist_mtime:
            return False
        invalidate_dir(self._allowlists_dir)  # the R3-59 hook that was never called
        self._allowlist_mtime = mtime
        self._allowlist = load_allowlist(self._allowlists_dir, _ALLOWLIST_NAME)
        _log.info("allowlist re-loaded after on-disk change",
                  path=str(self._allowlist_path))
        return True

    def ingest_alert(self, alert: dict) -> list[dict]:
        """Feed one alert through its entity tracks. Returns 0-3 fresh/
        updated incident dicts (actor-track, ip-track, and device-track
        incidents) -- empty if no track is promoted, or if the alert has no
        trackable entity at all (recorded as a skip reason in metrics(), so
        WS-5's enrichment alerts are an observable no-op, never a silent
        one)."""
        tenant = _validated_tenant(alert.get("tenant_id"))
        now_ms = self._now_ms()
        incidents: list[dict] = []

        # R3-59 run-loop reload: an on-disk allowlist edit (or a repaired
        # previously-broken file) must take effect without a restart. Cheap
        # stat; no-op unless the file changed.
        self.reload_allowlist_if_changed()

        # Degrade, don't crash on a malformed actor block: `.get("user") or
        # {}` alone still returns a plain-string user, and a string has no
        # `.get` -- so a non-dict user must be flattened to "no actor name"
        # explicitly, or the whole ingest would raise AttributeError
        # (gap-hunt finding; the alert's OTHER legs must keep working).
        actor = alert.get("actor") or {}
        user = actor.get("user") or {}
        if not isinstance(user, dict):
            user = {}
        actor_name = user.get("name")
        src_endpoint = alert.get("src_endpoint") or {}
        src_ip = src_endpoint.get("ip")
        device_id = src_endpoint.get("mac") or src_endpoint.get("hostname")

        opened = False
        if actor_name:
            opened = True
            inc = self._update_track(tenant, "actor", str(actor_name), alert, now_ms)
            if inc is not None:
                incidents.append(inc)

        ip_suppressed = False
        if src_ip:
            # Canonical spelling for BOTH the allowlist check and the track
            # key (IPv6 identity gap, 2026-08-29 review): one address spelled
            # in case/compression variants must be ONE identity -- a spelling
            # split would both evade multi-tactic promotion and duplicate
            # allowlist lookups.
            ip_value = _canonical_ip(src_ip)
            if self._allowlist.matches(ip_value):
                ip_suppressed = True  # shared infra: no ip: track, by design
            else:
                opened = True
                inc = self._update_track(tenant, "ip", ip_value, alert, now_ms)
                if inc is not None:
                    incidents.append(inc)

        device_suppressed = False
        if device_id:
            # Pivot-correlation (2026-08-19): mac/hostname is a directly
            # parser-populated OCSF field, not an inferred link -- prefer mac
            # (stable across a DHCP-driven IP change on the same interface),
            # fall back to hostname when mac is absent. Since 2026-08-26 the
            # shared-infrastructure allowlist suppresses the device: track
            # too (gap-hunt finding): a hostname is as spoofable and
            # unauthenticated as the src ip the ip: leg already allowlists,
            # so shared infra must never open a device: track either.
            # Fails closed: an unloadable allowlist matches nothing.
            if self._allowlist.matches(str(device_id)):
                device_suppressed = True
            else:
                opened = True
                inc = self._update_track(tenant, "device", str(device_id), alert, now_ms)
                if inc is not None:
                    incidents.append(inc)

        if not opened:
            # Degrade, don't crash: an alert that opened no track is a
            # correlation no-op -- record WHY so the silence is observable
            # instead of silently vanishing (WS-5's enrichment alerts carry
            # no actor/src_endpoint at all, so EVERY one of them used to be
            # an invisible no-op; gap-hunt finding).
            if device_suppressed:
                reason = "allowlisted_device"
            elif ip_suppressed:
                reason = "allowlisted_ip"
            else:
                reason = "no_trackable_entity"
            self._skip_reasons[reason] = self._skip_reasons.get(reason, 0) + 1

        return incidents

    def incident_graph(self, incident_id: str) -> dict | None:
        """The ADR-009 ``incident.graph`` payload last emitted for
        ``incident_id`` (stored alongside every incident promotion/update,
        same promotion path as the incident itself), or None when that
        incident is not live (never promoted, or already swept with its
        dead track).

        This is the produce source for the ``incident.graph`` bus topic
        (partition key ``incident_id``, same as ``incidents``): a bus
        wiring (main.py) pairs each incident it publishes with this payload.
        The ``incidents`` emission itself is completely unchanged -- the
        graph is purely additive. Returns a deep copy so callers can never
        mutate the correlator's cached payload."""
        graph = self._incident_graphs.get(incident_id)
        return copy.deepcopy(graph) if graph is not None else None

    def metrics(self) -> dict:
        # ws8_active_tracks: was cumulative ever-seen (2026-08-19 review
        # finding) since nothing ever removed a dead key from `_sides`. Now
        # tracks genuinely-active tracks, lagging real time by at most
        # `_SIDES_SWEEP_EVERY` calls (`_sweep_dead_tracks`'s own cadence) --
        # same staleness bound `shared/window.py`'s own key count already
        # accepts for the identical reason.
        #
        # ws8_skipped_alerts_by_reason stays as the nested dict -- that is the
        # /metrics JSON contract (test_ws5_shaped_alert_is_skipped_with_reason
        # reads it). render_prometheus (shared/runner.py) only emits NUMERIC
        # leaves as gauges, so the nested dict was invisible to /metrics/prom:
        # add a sibling FLAT `ws8_skipped_reason_<reason>` numeric key per
        # reason (2026-08-27 finding) -- sibling series, never repurposing the
        # honest nested field.
        out = {
            "ws8_active_tracks": len(self._sides),
            "ws8_promotions_total": self.promotions_count,
            "ws8_truncated_total": self.truncated_count,
            "ws8_skipped_alerts_by_reason": dict(self._skip_reasons),
            "ws8_skipped_total": sum(self._skip_reasons.values()),
        }
        for reason, count in self._skip_reasons.items():
            out[f"ws8_skipped_reason_{reason}"] = count
        return out
