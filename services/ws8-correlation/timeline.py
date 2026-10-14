"""WS-8 timeline view: an incident's member alerts in time order, by tactic.

WHY THIS EXISTS (owner decision 2026-10-14, option B of
docs/proposals/2026-10-02-ws8-edge-time.md)
    An incident.graph edge is evidenced by ONE alert, so it carries one instant
    and its direction comes from entity types, not from time: the graph cannot
    say "A happened before B". Analysts still need the attack's story in order.
    This module gives that story a named, testable home: it sorts the alerts the
    incident ALREADY contains. It makes no cross-alert inference, adds no edge,
    and changes no promotion, id, topic or mapping (same read-side posture as
    campaigns.py).

WHAT IT DOES NOT CLAIM
    Time order is necessary for causation and nowhere near sufficient. Two
    alerts with the same time are a TIE and are reported as one group, never
    ordered by an arbitrary key. An alert without a usable time is listed under
    ``untimed`` instead of being sorted to the start (``0``) the way a missing
    time would silently sort -- evidence_package._sort_time's default is fine
    for display but would fabricate an order here.

TENANCY
    Alerts whose ``tenant_id`` differs from the incident's are excluded and
    counted (``foreign_tenant_dropped``): a timeline never mixes customers even
    if a caller hands in the wrong alert list.

STDLIB ONLY. Pure and deterministic: input order never changes the result.
"""
from __future__ import annotations

import math
from typing import Iterable, Optional


def _time(alert: dict) -> Optional[int]:
    t = alert.get("time")
    if isinstance(t, bool) or not isinstance(t, (int, float)) or not math.isfinite(t) or t <= 0:
        return None
    return int(t)


def _tactic(alert: dict) -> Optional[str]:
    mitre = alert.get("mitre")
    tactic = mitre.get("tactic") if isinstance(mitre, dict) else None
    return tactic if isinstance(tactic, str) and tactic else None


def _alert_id(alert: dict) -> Optional[str]:
    a = alert.get("alert_id")
    return a if isinstance(a, str) and a else None


def build_timeline(incident: dict, alerts: Iterable[dict]) -> dict:
    """Order ``incident``'s member alerts by time.

    Only alerts listed in ``incident["member_alert_ids"]`` are used (a caller
    cannot smuggle extra alerts into an incident's story), deduplicated by
    ``alert_id`` (the indexer upserts one alert per id; a redelivered copy is
    the same alert). Returns::

        {"incident_id": str, "tenant_id": str,
         "steps": [{"time": int, "alert_ids": [sorted], "rule_ids": [sorted],
                    "tactics": [sorted]}],          # ascending time; ties grouped
         "tactic_order": [tactic, ...],             # first appearance, in time order
         "untimed": [sorted alert ids],
         "missing_alert_ids": [sorted],             # members not found in ``alerts`` at all
         "foreign_tenant_dropped": int}             # member ids seen only under ANOTHER tenant
    """
    members = incident.get("member_alert_ids")
    members = {m for m in members if isinstance(m, str) and m} if isinstance(members, list) else set()
    tenant = incident.get("tenant_id") if isinstance(incident.get("tenant_id"), str) else ""
    by_id: dict = {}
    foreign: set = set()
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        aid = _alert_id(alert)
        if aid is None or aid not in members:
            continue
        if (alert.get("tenant_id") or "") != tenant:
            foreign.add(aid)
            continue
        # duplicates of one alert_id: keep the one with the EARLIEST usable time,
        # then the smallest rule id -- a total order, so input order never matters
        key = (_time(alert) is None, _time(alert) or 0, str(alert.get("rule_id") or ""))
        prev = by_id.get(aid)
        if prev is None or key < prev[0]:
            by_id[aid] = (key, alert)

    groups: dict = {}
    untimed = []
    for aid, (_key, alert) in by_id.items():
        t = _time(alert)
        if t is None:
            untimed.append(aid)
            continue
        g = groups.setdefault(t, {"time": t, "alert_ids": set(), "rule_ids": set(), "tactics": set()})
        g["alert_ids"].add(aid)
        if isinstance(alert.get("rule_id"), str):
            g["rule_ids"].add(alert["rule_id"])
        if _tactic(alert):
            g["tactics"].add(_tactic(alert))

    steps = [{"time": t, "alert_ids": sorted(g["alert_ids"]), "rule_ids": sorted(g["rule_ids"]),
              "tactics": sorted(g["tactics"])} for t, g in sorted(groups.items())]
    tactic_order: list = []
    for step in steps:
        for tactic in step["tactics"]:
            if tactic not in tactic_order:
                tactic_order.append(tactic)
    return {
        "incident_id": incident.get("incident_id"),
        "tenant_id": tenant,
        "steps": steps,
        "tactic_order": tactic_order,
        "untimed": sorted(untimed),
        "missing_alert_ids": sorted(members - set(by_id) - foreign),
        "foreign_tenant_dropped": len(foreign - set(by_id)),
    }
