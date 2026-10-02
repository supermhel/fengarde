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

TENANCY
    Linking never crosses a tenant. An incident with a missing / empty /
    non-string ``tenant_id`` has no tenant to be bounded by, so it is NOT
    linkable to anything: it is returned as its own singleton campaign
    (``tenant_id == ""``, ``untenanted == True``) and never pooled with other
    tenant-less incidents or with tenanted ones, even if they share an alert.
    Real WS-8 incidents always carry a tenant; this is the fail-safe for input
    that does not.

NO SILENT CAPS
    Every well-formed incident handed in is processed and appears in exactly
    one returned campaign. There is deliberately no input cap: union-find with
    an alert->owner inverted index is near-linear, so a cap would guard nothing
    and could only drop evidence without a signal (which is what the previous
    50_000 slice did). Callers that must bound work should bound the input.
    The only incidents omitted are the malformed ones (no usable string
    ``incident_id``), which are skipped rather than fabricated.

CAMPAIGN ID (a persistable handle -- read this before storing one)
    ``campaign_id = "campaign:<tenant>:<sha256(root incident_id)[:16]>"`` where
    the root is the lexicographically smallest member ``incident_id`` (the
    union-find root, chosen deterministically). It does NOT depend on the other
    members, so:

      * the id is UNCHANGED when an incident joins a campaign whose current
        smallest incident id is not beaten by the newcomer (the common case:
        a pivoting attack gains a later incident), and
      * the id is independent of input order.

    Two residual cases move the id, and both are reported rather than hidden:

      1. two campaigns MERGE (a new incident bridges them): the survivor keeps
         the id of the smaller root; the other campaign's id disappears.
      2. a joining incident whose ``incident_id`` sorts BELOW the current root
         becomes the new root, so the id changes.

    This function is stateless, so it can only report lineage if told what the
    caller saw last time: pass ``previous=`` (an earlier ``link_campaigns``
    result, or any list of dicts with ``campaign_id`` + ``incident_ids``) and
    each returned campaign carries ``merged_from`` = the sorted previous
    campaign ids that now live inside it (excluding its own id). A persisted
    handle can then be re-pointed. Without ``previous`` ``merged_from`` is
    ``[]``. ``previous`` is lineage only; it never influences the id.

NOT DONE HERE, deliberately: persisting a campaign id on the incident, emitting
it on the bus, or indexing it. Each is a contract change (the `incidents` index
is `dynamic: false`) that belongs to the owner -- see
docs/proposals/2026-10-01-ws8-campaign-view.md.

STDLIB ONLY. Pure and deterministic: order of the input does not change the
result; the campaign id is derived from its smallest member incident id.
"""
from __future__ import annotations

import hashlib
from typing import Iterable, Optional


def _members(incident: dict) -> list:
    m = incident.get("member_alert_ids")
    return [x for x in m if isinstance(x, str) and x] if isinstance(m, list) else []


def _tenant(incident: dict) -> str:
    """The incident's tenant, or "" when it has none usable."""
    t = incident.get("tenant_id")
    return t if isinstance(t, str) and t.strip() else ""


def _previous_index(previous: Optional[Iterable]) -> dict:
    """incident_id -> set of previous campaign ids that contained it (malformed entries ignored)."""
    idx: dict = {}
    for camp in previous or ():
        if not isinstance(camp, dict):
            continue
        cid, iids = camp.get("campaign_id"), camp.get("incident_ids")
        if not isinstance(cid, str) or not cid or not isinstance(iids, list):
            continue
        for iid in iids:
            if isinstance(iid, str) and iid:
                idx.setdefault(iid, set()).add(cid)
    return idx


def link_campaigns(incidents: Iterable[dict], previous: Optional[Iterable] = None) -> list:
    """Group ``incidents`` into campaigns by shared member alert.

    Returns a list of campaign dicts, deterministic and order-independent::

        {"campaign_id": "campaign:<tenant>:<sha256(smallest incident_id)[:16]>",
         "tenant_id": str,            # "" for an untenanted incident
         "untenanted": bool,          # True: no usable tenant_id; never linked
         "incident_ids": [sorted ...],
         "entities": [sorted "type:value" ...],
         "member_alert_ids": [sorted ...],
         "tactics": [sorted ...],
         "incident_count": int,
         "merged_from": [sorted previous campaign ids absorbed ...]}

    Incidents with no usable ``incident_id`` are skipped (not fabricated).
    Singletons are returned too: a campaign of one is the ordinary case, and
    callers should not need a second code path for it. See the module
    docstring for tenancy, the no-cap guarantee and id stability.
    """
    # key = tenant for tenanted incidents; ("", incident_id) pseudo-tenant for untenanted ones,
    # so each of those is alone in its own group and can never link to anything.
    groups: dict = {}
    for inc in incidents:
        if not isinstance(inc, dict):
            continue
        iid = inc.get("incident_id")
        if not isinstance(iid, str) or not iid:
            continue
        tenant = _tenant(inc)
        key = (0, tenant, "") if tenant else (1, "", iid)
        groups.setdefault(key, {})[iid] = inc

    prev_idx = _previous_index(previous)
    out: list = []
    for key in sorted(groups):
        group = groups[key]
        tenant, untenanted = key[1], key[0] == 1
        ids = sorted(group)
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
            digest = hashlib.sha256(members[0].encode("utf-8")).hexdigest()[:16]
            campaign_id = f"campaign:{tenant}:{digest}"
            lineage = sorted({p for i in members for p in prev_idx.get(i, ())} - {campaign_id})
            out.append({
                "campaign_id": campaign_id,
                "tenant_id": tenant,
                "untenanted": untenanted,
                "incident_ids": members,
                "entities": entities,
                "member_alert_ids": alerts,
                "tactics": tactics,
                "incident_count": len(members),
                "merged_from": lineage,
            })
    out.sort(key=lambda c: (c["tenant_id"], c["incident_ids"][0]))
    return out
