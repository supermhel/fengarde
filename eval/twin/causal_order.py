"""causal_order -- grade CAUSAL ORDER (event time) on the oracle's relationships.

WHY THIS EXISTS (2026-10-02)
    ``chain_fidelity`` and ``false_correlation_rate`` are provably order-blind.
    Their join predicate asks "is there an edge from an entity on the earlier
    step side to an entity at step t?" and never reads a clock. A time-mirrored
    copy of every registered storyline (every event moved to ``lo + hi - t``, then
    re-sorted so delivery follows the logs) scored IDENTICALLY on chain_fidelity
    (0.6 / 0.5 / 0.5), FCR (1.0), directional_discrimination (0.0), TPR (1.0),
    incident_count and incident_membership_ok. Only the boolean
    ``alert_order_ok`` flipped. This module grades the order the oracle's
    ``allowed_relationships`` imply, as a graded fraction over the oracle's
    relationship DAG (``it_intrusion``'s ``dns_exfil`` has two parents, which a
    linear check cannot express).

WHAT IS MEASURED (and what is NOT)
    Per graded allowed pair (from-step f, to-step t; both steps timed AND
    entity-bearing -- exactly ``chain_fidelity``'s graded set, so the
    denominators are comparable):

      O  ``ordered``        first_event_time(f) <= first_event_time(t), on the
                            time the PARSER put in the OCSF event.
      A  ``edge_available`` some WS-8 v2 edge that passes the SAME join
                            predicate chain_fidelity uses has an attributed
                            provenance (an alert exists whose
                            ``event_ids[0] or alert_id`` equals the edge's
                            ``event_id`` AND whose ``time`` equals the edge's
                            ``ts_ms``) and ``ts_ms <= last_event_time(t)`` --
                            the relation was knowable without hindsight.

    ``order_concordance``     = ordered / graded.      (O alone; edge-free.)
    ``causal_order_fidelity`` = (O and A) / graded.    (None when no edge exists
                                                        or nothing is graded --
                                                        never a fabricated 0.)

HONEST FRAMING (read before quoting any number from here)
    O is a property of the TIMESTAMPS THE PIPELINE INGESTED. On the harness's own
    chains it is 1.0 BY CONSTRUCTION: the storylines are authored in oracle
    order. It is a timestamp invariant and a tripwire -- it guards mutation
    validity, WS-2 time handling, WS-3 chronology and edge-evidence timing. It
    is NOT a score that ranks correlators and it does NOT show that WS-8
    reconstructs causal order: a WS-8 v2 edge is evidenced by ONE alert, so it
    has one instant and its direction comes from entity TYPE (actor->ip,
    actor->device, device->ip), never from time. On ``ai_to_ot`` the union graph
    is a single edge, so A is vacuous there and only O discriminates. Reading
    ``causal_order_fidelity`` as "causal reconstruction quality" would repeat the
    ``chain_fidelity`` mistake; see docs/proposals/2026-10-02-ws8-edge-time.md
    for what product evidence would be needed.

EDGE SELECTION (correctness note)
    The report builds one graph per promoted incident. Two incidents can carry
    different ``ts_ms`` for the same (from, to) pair (an incident-id sort must
    not decide credit), and within one incident the winning edge is chosen by
    kind rank BEFORE time (a typed kind such as ``caused_by`` arriving later
    displaces an earlier field-pair edge, pushing ``ts_ms`` later). Grading
    therefore takes the PER-INCIDENT graphs and, per (from, to) pair, the MINIMUM
    ``ts_ms`` over attributed edges (``collapse_min_ts``) -- independent of
    incident order.

STDLIB ONLY and import-pure: nothing from report.py / ws2 / ws4 is imported, so
this module cannot trigger the ``sys.modules['main']`` collision documented in
report.py. The join predicate is injected (``join_fn``) so the SAME direction
check chain_fidelity uses is reused, and ``ordered`` is a separate tiny function
so tests can mutate it and prove it load-bearing.
"""
from __future__ import annotations

from typing import Callable, Optional

# Label printed next to every reported order_concordance (SSOT / report context).
ORDER_BASIS = ("timestamp invariant, 1.0 by construction on the harness's own chains: it "
               "records that the ingested clock agrees with the oracle's order, NOT that WS-8 "
               "reconstructs causal order")


# ---------------------------------------------------------------------------
# Tiny pure predicates (mutated by the tests to prove they are load-bearing)
# ---------------------------------------------------------------------------
def ordered(t_from, t_to) -> bool:
    """``from`` is no later than ``to``. Ties count as ordered, matching
    report._alert_order_ok; ``tie_pairs`` in the result keeps them visible."""
    return t_from <= t_to


def edge_known_by(ts_ms, t_last) -> bool:
    """The edge's evidence instant is not after the to-step's last event."""
    return ts_ms <= t_last


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------
def _num(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def step_times(parsed_events) -> dict:
    """``{step: (first_ms, last_ms)}`` from each parsed ChainEvent's OCSF
    ``event['time']`` (the PARSER's output, not the raw payload -- so a WS-2
    unit or timezone bug moves it). Steps with no numeric time are absent."""
    out: dict = {}
    for ev in parsed_events:
        event = getattr(ev, "event", None) or {}
        t = event.get("time")
        step = getattr(ev, "step", None)
        if step is None or not _num(t):
            continue
        lo, hi = out.get(step, (t, t))
        out[step] = (min(lo, t), max(hi, t))
    return out


def attribute_edges(edges: list, items: list) -> list:
    """Per edge ``{"step", "attributed", "ambiguous"}``.

    An edge is attributed iff some alert in ``items`` (``[{step, alert}]``) has
    ``(event_ids[0] or alert_id) == edge.event_id`` AND ``alert.time ==
    edge.ts_ms``. A time-fallback digest ts_ms can never equal a real alert time
    and an unknown event_id matches nothing, so both stay unattributed and earn
    no credit. An edge that matches alerts of several different steps is
    ``ambiguous`` and also earns no credit (no step can be named)."""
    index: dict = {}
    for item in items:
        alert = item.get("alert") or {}
        ids = alert.get("event_ids")
        if isinstance(ids, (list, tuple)):
            first = ids[0] if ids else None
        else:
            first = ids
        handle = str(first) if first not in (None, "") else alert.get("alert_id")
        if handle is None or alert.get("time") is None:
            continue
        index.setdefault((str(handle), alert["time"]), set()).add(item.get("step"))
    out = []
    for ed in edges:
        steps = index.get((str(ed.get("event_id")), ed.get("ts_ms")), set())
        out.append({"step": next(iter(steps)) if len(steps) == 1 else None,
                    "attributed": len(steps) == 1,
                    "ambiguous": len(steps) > 1})
    return out


def _edge_list(graph) -> list:
    if isinstance(graph, dict):
        return list(graph.get("edges") or [])
    return list(graph or [])


def collapse_min_ts(graphs: list, items: list) -> tuple:
    """Flatten per-incident graphs into one edge per (from, to) carrying the
    MINIMUM ``ts_ms`` over ATTRIBUTED edges, independent of incident order.

    Returns ``(edges, stats)``. ``edges`` are the collapsed attributed edges
    (copies); ``stats`` counts every input edge, how many were unattributed and
    how many ambiguous, so the denominator of the claim is visible."""
    flat: list = []
    for g in graphs:
        flat.extend(_edge_list(g))
    attr = attribute_edges(flat, items)
    best: dict = {}
    for ed, at in zip(flat, attr):
        if not at["attributed"] or not _num(ed.get("ts_ms")):
            continue
        key = (ed.get("from"), ed.get("to"))
        cur = best.get(key)
        if cur is None or ed["ts_ms"] < cur["ts_ms"]:
            best[key] = dict(ed)
    stats = {"edges_in": len(flat),
             "attributed": sum(1 for a in attr if a["attributed"]),
             "unattributed": sum(1 for a in attr if not a["attributed"] and not a["ambiguous"]),
             "ambiguous": sum(1 for a in attr if a["ambiguous"]),
             "collapsed": len(best)}
    return [best[k] for k in sorted(best, key=lambda k: (str(k[0]), str(k[1])))], stats


# ---------------------------------------------------------------------------
# The grader
# ---------------------------------------------------------------------------
def grade_causal_order(graphs: list, step_entities: dict, rels: list, step_order: list,
                       times: dict, items: list, join_fn: Callable) -> dict:
    """PURE grader. See the module docstring for the definitions.

    ``graphs``  per-incident graphs (dicts with ``edges``, or bare edge lists).
    ``times``   ``step_times(...)`` output.
    ``items``   the ATTACK alerts (``[{step, alert}]``); decoy alerts are
                deliberately not passed, so an edge evidenced only by a decoy
                earns no credit for an attack pair.
    ``join_fn`` the chain_fidelity direction predicate ``(edges, from, to)``."""
    idx = {label: i for i, label in enumerate(step_order)}

    def earlier_side(f: str) -> set:
        side: set = set()
        if f not in idx:
            return side
        for i in range(idx[f] + 1):
            side |= set(step_entities.get(step_order[i], ()))
        return side

    edges, stats = collapse_min_ts(graphs, items)
    have_edges = stats["edges_in"] > 0
    allowed = [r for r in rels if r.get("allowed")]
    forbidden_rels = [r for r in rels if not r.get("allowed")]

    per_pair: list = []
    graded = n_ordered = n_passed = n_strict = n_tie = n_rev = 0
    n_avail_of_ordered = 0
    for rel in allowed:
        f, t = rel.get("from"), rel.get("to")
        from_set = set(step_entities.get(f, ()))
        to_set = set(step_entities.get(t, ()))
        if not from_set or not to_set:
            per_pair.append({"from": f, "to": t, "graded": False,
                             "reason": "step-not-entity-bearing"})
            continue
        if f not in times or t not in times:
            per_pair.append({"from": f, "to": t, "graded": False,
                             "reason": "step-not-timed"})
            continue
        graded += 1
        f_first, t_first, t_last = times[f][0], times[t][0], times[t][1]
        fwd = bool(ordered(f_first, t_first))
        rev = bool(ordered(t_first, f_first))
        strict = fwd and not rev
        side = earlier_side(f)
        joined = bool(join_fn(edges, side, to_set))
        avail = any(join_fn([ed], side, to_set) and edge_known_by(ed["ts_ms"], t_last)
                    for ed in edges)
        passed = fwd and avail
        n_ordered += fwd
        n_strict += strict
        n_tie += (fwd and rev)
        n_rev += rev
        n_avail_of_ordered += (fwd and avail)
        n_passed += passed
        per_pair.append({"from": f, "to": t, "graded": True, "ordered": fwd,
                         "strictly_ordered": strict, "reverse_ordered": rev,
                         "joined_attributed": joined, "edge_available": avail, "passed": passed})

    per_forbidden: list = []
    f_timed = f_realised = 0
    for rel in forbidden_rels:
        f, t = rel.get("from"), rel.get("to")
        if f not in times or t not in times:
            per_forbidden.append({"from": f, "to": t, "graded": False,
                                  "reason": "step-not-timed"})
            continue
        f_timed += 1
        realised = bool(times[f][0] < times[t][0])  # strictly: the clock says f happened first
        f_realised += realised
        per_forbidden.append({"from": f, "to": t, "graded": True, "realised": realised})

    def _r(num, den):
        return round(num / den, 4) if den else None

    return {
        "graded": graded,
        "order_concordance": _r(n_ordered, graded),
        "order_concordance_basis": ORDER_BASIS,
        "causal_order_fidelity": _r(n_passed, graded) if have_edges else None,
        "edge_available_rate": _r(n_avail_of_ordered, n_ordered) if have_edges else None,
        "temporal_discrimination": _r(n_strict, graded),
        "tie_pairs": n_tie,
        "forbidden_order_realised_rate": _r(f_realised, f_timed),
        "forbidden_timed": f_timed,
        "edge_stats": stats,
        "per_pair": per_pair,
        "per_forbidden_pair": per_forbidden,
    }


# ---------------------------------------------------------------------------
# Reporting policy (Stage 3 is OWNER-GATED -- this function never relabels)
# ---------------------------------------------------------------------------
def reporting_policy(directional_discrimination: Optional[float]) -> dict:
    """How the order metrics are reported next to the legacy join metrics.

    CURRENT POLICY (owner decision pending): ``co_reported``. The legacy
    ``chain_fidelity`` / ``false_correlation_rate`` keep their names, values and
    position; the causal-order metrics are reported BESIDE them. Nothing is
    demoted or relabelled by this function.

    ``would_lead_if_ratified`` records what the owner would be choosing between:
    while ``directional_discrimination`` is None or < 0.5 the legacy pair carries
    no order information, so the order metric would lead (with O labelled a
    timestamp invariant); at >= 0.5 the legacy pair would stay a co-headline."""
    weak = directional_discrimination is None or directional_discrimination < 0.5
    return {
        "mode": "co_reported",
        "headline_switch": "owner-gated (Stage 3 of the causal-order plan); not applied",
        "directional_discrimination": directional_discrimination,
        "legacy_pair_discriminates_direction": not weak,
        "would_lead_if_ratified": ("causal_order_fidelity" if weak
                                   else "chain_fidelity and causal_order_fidelity (co-headline)"),
        "reason": ("directional_discrimination is " +
                   ("null" if directional_discrimination is None else str(directional_discrimination)) +
                   ": the legacy join answers 'joined' for a pair and its reverse, so it carries "
                   "no order information" if weak else
                   "directional_discrimination >= 0.5: the legacy join separates a pair from its "
                   "reverse on at least half of the graded pairs"),
    }


# ---------------------------------------------------------------------------
# Product-output order checks
# ---------------------------------------------------------------------------
def story_order_ok(package_order: list, expected_seq: list) -> Optional[bool]:
    """Does the WS-3 evidence package present the attack in the oracle's order?

    ``package_order`` is ``[(step, alert_time_ms), ...]`` in the package's alert
    BLOCK order (WS-3 sorts them chronologically). OK iff package times are
    non-decreasing AND no step that appears later in the package has a lower
    oracle rank than an earlier-appearing step whose first time is strictly
    earlier (simultaneous steps may appear in either rank order). ``None`` with
    fewer than two distinct oracle steps -- no order to read."""
    rank = {s: i for i, s in enumerate(expected_seq)}
    rows = [(s, t) for s, t in package_order if s in rank and _num(t)]
    if not rows:
        return None
    if any(rows[i][1] > rows[i + 1][1] for i in range(len(rows) - 1)):
        return False
    first: dict = {}
    for s, t in rows:
        first.setdefault(s, t)
    if len(first) < 2:
        return None
    appear = list(first)
    for i in range(len(appear)):
        for j in range(i + 1, len(appear)):
            a, b = appear[i], appear[j]
            if rank[a] > rank[b] and first[a] < first[b]:
                return False
    return True


def parser_time_agreement(parsed_events, raw_ts_fn: Callable) -> Optional[float]:
    """Fraction of parsed events whose OCSF ``time`` equals the time the RAW
    payload declared (``raw_ts_fn(chain_event)``). A value below 1.0 flags WS-2
    time-normalisation drift (unit, timezone, fallback to a processing clock).
    ``None`` when no event has both a raw and a parsed time."""
    total = agree = 0
    for ev in parsed_events:
        parsed_t = (getattr(ev, "event", None) or {}).get("time")
        raw_t = raw_ts_fn(ev)
        if not _num(parsed_t) or not _num(raw_t):
            continue
        total += 1
        agree += (parsed_t == raw_t)
    return round(agree / total, 4) if total else None
