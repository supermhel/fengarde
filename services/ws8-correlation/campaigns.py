"""WS-8 campaign view: group incidents that share direct alert evidence.

WHY THIS EXISTS (2026-10-01)
    WS-8 promotes one incident per ENTITY TRACK (actor / ip / device) and, by
    ratified design (ADR-009/010), never merges tracks: no compound key, no
    transitive join across a shared entity. That is the right default -- it is
    what stops one shared NAT address from pulling unrelated people into a false
    "incident". The price is that an attack which PIVOTS (attacker address ->
    stolen account -> internal foothold) is reported as several incidents, one
    per entity, even though it is a single campaign. The multi-storyline
    harness measured it: `it_intrusion` -> 3-4 incidents, `ai_to_ot` -> 2.

    This module does NOT change any promotion, id, or emitted payload. It is a
    pure READ-SIDE view over incidents WS-8 has already produced: two incidents
    belong to the same campaign iff they share at least one MEMBER ALERT.

WHY THAT IS SAFE (the property the NAT case demands)
    A shared ALERT is direct evidence in a way a shared ENTITY is not. One alert
    carries its own actor, source address and device together, so an alert that
    sits in both the `actor:deploy` track and the `ip:10.50.0.46` track is the
    observation "deploy was seen at 10.50.0.46" -- a single-event fact, the same
    standard the incident.graph edges already hold themselves to. Two unrelated
    users behind one NAT share the NAT's ip track but share NO alert, so they do
    not link. (Their incidents stay separate exactly as before.)

    The link is still transitive across a CHAIN of shared alerts (A-B and B-C
    => A, B, C one campaign), which is the point: pivoting is a chain. It is
    bounded by tenant (never across customers) and by the incidents handed in.

NOT DONE HERE, deliberately: persisting a campaign id on the incident, emitting
it on the bus, or indexing it. Each is a contract change (the `incidents` index
is `dynamic: false`) that belongs to the owner -- see
docs/proposals/2026-10-01-ws8-campaign-view.md.

STDLIB ONLY. Pure and deterministic: order of the input does not change the
result; the campaign id is derived from its members.
"""
from __future__ import annotations

import hashlib
from typing import Iterable

_MAX_INCIDENTS = 50_000      # a hostile / runaway input must not make this quadratic


def _members(incident: dict) -> list:
    m = incident.get("member_alert_ids")
    return [x for x in m if isinstance(x, str) and x] if isinstance(m, list) else []


def link_campaigns(incidents: Iterable[dict]) -> list:
    """Group ``incidents`` into campaigns by shared member alert.

    Returns a list of campaign dicts, deterministic and order-independent::

        {"campaign_id": "campaign:<tenant>:<sha256[:16]>",
         "tenant_id": str,
         "incident_ids": [sorted ...],
         "entities": [sorted "type:value" ...],
         "member_alert_ids": [sorted ...],
         "tactics": [sorted ...],
         "incident_count": int}

    Incidents with no usable ``incident_id`` are skipped (not fabricated).
    Singletons are returned too: a campaign of one is the ordinary case, and
    callers should not need a second code path for it.
    """
    by_tenant: dict = {}
    for inc in incidents:
        if not isinstance(inc, dict):
            continue
        iid = inc.get("incident_id")
        if not isinstance(iid, str) or not iid:
            continue
        by_tenant.setdefault(inc.get("tenant_id") or "", {})[iid] = inc

    out: list = []
    for tenant in sorted(by_tenant):
        group = by_tenant[tenant]
        ids = sorted(group)[:_MAX_INCIDENTS]
        parent = {i: i for i in ids}

        def find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        # inverted index: alert -> first incident that carried it; every later
        # incident carrying the same alert is unioned with it (linear, not pairwise)
        first_owner: dict = {}
        for iid in ids:
            for alert_id in _members(group[iid]):
                owner = first_owner.setdefault(alert_id, iid)
                if owner != iid:
                    ra, rb = find(owner), find(iid)
                    if ra != rb:
                        parent[max(ra, rb)] = min(ra, rb)   # deterministic root

        comps: dict = {}
        for iid in ids:
            comps.setdefault(find(iid), []).append(iid)

        for members in comps.values():
            members = sorted(members)
            alerts = sorted({a for i in members for a in _members(group[i])})
            tactics = sorted({t for i in members for t in (group[i].get("tactics") or [])
                              if isinstance(t, str)})
            entities = sorted({f"{group[i].get('entity_type')}:{group[i].get('entity_value')}"
                               for i in members})
            digest = hashlib.sha256("|".join(members).encode("utf-8")).hexdigest()[:16]
            out.append({
                "campaign_id": f"campaign:{tenant}:{digest}",
                "tenant_id": tenant,
                "incident_ids": members,
                "entities": entities,
                "member_alert_ids": alerts,
                "tactics": tactics,
                "incident_count": len(members),
            })
    out.sort(key=lambda c: (c["tenant_id"], c["incident_ids"][0]))
    return out
