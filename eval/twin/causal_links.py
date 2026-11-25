"""causal_links -- grade the emitted ``incident.graph.links[]`` against the oracle's ``causal_links``
(ADR-012 section 3, work package W3a). The key-evidence analogue of ``causal_order`` (ADR-011).

WHAT IS GRADED
    ``emitted``  the ``links[]`` ws8 put on the incident graph: ``{from_event_id, to_event_id, basis,
                 order, from_ts_ms, to_ts_ms, trust}`` (services/ws8-correlation/correlator.py
                 ``_causal_link_candidates``). The pipeline's OUTPUT, never the harness's event list.
    ``truth``    the oracle's ``causal_links``: ``{from, to, basis}`` over STEP labels.
    ``items``    the ATTACK alerts ``[{step, alert}]``. An event id maps to a step through the alert's
                 ``event_ids[0]`` (else ``alert_id``), the handle ws8 itself records on a link
                 (``_provenance_event_id``), paired with the endpoint's event time like
                 ``causal_order.attribute_edges`` pairs ``event_id`` with ``ts_ms`` (see ``index_items``). A
                 key that names alerts of two different steps is ambiguous and maps to nothing.

FOLDED ALERTS (ONE attribution rule, shared with report.py and test_timeline_order). Two steps of one rule on one
group inside one window bucket mint ONE ``alert_id``; the indexer holds one document and ws8 keeps its last version.
The alert belongs to the EARLIEST step that raised it (``owner_items``), exactly as ``report.py`` attributes the
evidence package's alerts and as ``ws8 timeline.build_timeline`` dedupes duplicate ids. A later step folded into it is
NOT alerted: its truth links are non-gradable (``*_unalerted``), never graded and never guessed. The twin storylines
avoid the fold by construction (every step of a flow sits in its own bucket or on a different rule).

DEFINITIONS (all computed at the STEP-PAIR level; several event links on one step pair count once)
    gradable truth link   BOTH endpoint steps raised an alert (appear in ``items``). Only these are
                          counted. Truth links with an unalerted endpoint are NOT dropped: they are listed
                          in ``non_gradable`` with the reason (``from_unalerted`` / ``to_unalerted`` /
                          ``both_unalerted``) so the denominator of the claim stays visible.
    matched               an emitted link whose (step, step, basis) equals a truth link. ``process_tree``
                          is directed (parent -> child) so the pair is ORDERED; ``network_flow`` and
                          ``agent_session`` are symmetric (ADR-012 s.1), so the pair is unordered.
    precision             matched emitted step-pairs / all emitted step-pairs. An emitted link whose
                          endpoint maps to no attack step (a decoy, an unknown event) is a FALSE link and
                          stays in the denominator (``unmapped``). A link between two events of ONE step
                          is not a step-pair claim: counted in ``intra_step`` and left out of both sides.
    recall                matched gradable truth links / gradable truth links.
    direction_accuracy    among matched links, the share whose emitted direction equals the truth direction
                          AND whose ``order`` is not ``conflict`` (ADR-012: a conflict counts against).
    coverage              attack alerts carrying at least one causal key / all attack alerts (the headline
                          honesty number: a high link score cannot hide a low coverage).
    Every rate carries a Wilson 95 % interval and its (k, n).

THE GATE (``gate``; ADR-012 s.3, owner sign-off item 6)
    Below the minimum n the verdict is ``insufficient_n`` with the reasons, never a score and never a pass:
      * >= 40 gradable truth links
      * >= 4 storylines contributing at least one gradable link
      * >= 2 bases each carrying >= 15 gradable links
      * no storyline above 40 % of the gradable links
    On enough data the verdict is ``pass`` only when the ``key_shuffle`` control collapsed precision AND
    recall to <= 0.25 x baseline; a missing or non-collapsing control is ``fail``.

STDLIB ONLY and import-pure (imports ``causal_order`` for ``wilson_interval`` only, which is itself
import-pure). The load-bearing predicates (``pair_key``, ``direction_ok``) are module-level so the tests
can mutate them and prove they matter.
"""
from __future__ import annotations

from typing import Any, Optional

from causal_order import wilson_interval

#: ADR-012 section 3 minimum-n bar (owner to ratify; the numbers are the ADR's, not tuned here).
MIN_GRADABLE_LINKS = 40
MIN_STORYLINES = 4
MIN_BASES = 2
MIN_PER_BASIS = 15
MAX_STORYLINE_SHARE = 0.40
#: ``key_shuffle`` must take precision and recall to at most this fraction of the baseline.
SHUFFLE_COLLAPSE_FRACTION = 0.25

#: Bases whose link has no direction of its own (ADR-012 s.1). Order from ADR-011 only.
SYMMETRIC_BASES = frozenset({"network_flow", "agent_session"})
BASES = ("process_tree", "network_flow", "agent_session")


# ---------------------------------------------------------------------------
# Predicates (mutated by the tests to prove they are load-bearing)
# ---------------------------------------------------------------------------
def pair_key(basis: str, a, b) -> tuple:
    """Identity of a step-pair claim. Directed bases keep (from, to); symmetric bases are unordered."""
    if basis in SYMMETRIC_BASES:
        lo, hi = sorted((str(a), str(b)))
        return (basis, lo, hi)
    return (basis, str(a), str(b))


def direction_ok(emitted_from, emitted_to, truth_from, truth_to, order) -> bool:
    """The emitted link points the way the truth link does and its logged order is not reversed."""
    return (emitted_from == truth_from and emitted_to == truth_to and order != "conflict")


# ---------------------------------------------------------------------------
# Mapping
# ---------------------------------------------------------------------------
def _handle(alert: dict):
    ids = alert.get("event_ids")
    first = None
    if isinstance(ids, (list, tuple)):
        first = ids[0] if ids else None
    elif ids not in (None, ""):
        first = ids
    if first not in (None, ""):
        return str(first)
    aid = alert.get("alert_id")
    return str(aid) if aid not in (None, "") else None


def step_of_alert(items: list) -> dict:
    """``{alert_id: owning step}``: the EARLIEST step (by alert time, then input order) that raised each alert id.

    THE one attribution rule for a folded alert (see the module docstring). ``report.py`` (the evidence package's
    alert order) and ``test_timeline_order`` call this same function, so the grader, the report and the oracle's
    stale_gap declarations cannot drift apart."""
    order = sorted(range(len(items or [])), key=lambda i: (
        (items[i].get("alert") or {}).get("time") if _is_ms((items[i].get("alert") or {}).get("time"))
        else float("inf"), i))
    owner: dict = {}
    for i in order:
        aid = (items[i].get("alert") or {}).get("alert_id")
        if aid not in (None, ""):
            owner.setdefault(aid, items[i].get("step"))
    return owner


def owner_items(items: list) -> list:
    """The items whose step OWNS its alert id (``step_of_alert``).

    A later step whose alert id was already minted by an earlier step is folded into that alert and is dropped
    here, so it is neither alerted nor mapped. Items with no alert id are kept."""
    owner = step_of_alert(items)
    return [it for it in items or []
            if (it.get("alert") or {}).get("alert_id") in (None, "")
            or owner[(it.get("alert") or {}).get("alert_id")] == it.get("step")]


def index_items(items: list) -> dict:
    """``{(handle, time_ms): step, handle: step}`` for every key that names exactly one step.

    The handle alone is NOT unique in real runs: a rule that folds several steps into one upserted alert re-emits
    that alert with a longer ``event_ids`` list whose first element is unchanged (``owner_items`` keeps only the
    earliest step's items, so a folded alert names ONE step here). ws8 records the link endpoint's event time
    (``from_ts_ms`` / ``to_ts_ms``), so a link is mapped through ``(handle, time)`` first, exactly like
    ``causal_order.attribute_edges`` pairs ``event_id`` with ``ts_ms``, and through the bare handle only when
    the link has no time or the time names no item (the later version of a folded alert). Ambiguous keys are absent
    (the link is then unmapped: a false link, counted, never guessed)."""
    seen: dict = {}
    for item in items or []:
        alert = item.get("alert") or {}
        h = _handle(alert)
        if h is None:
            continue
        t = alert.get("time")
        if _is_ms(t):
            seen.setdefault((h, t), set()).add(item.get("step"))
        seen.setdefault(h, set()).add(item.get("step"))
    return {k: next(iter(v)) for k, v in seen.items() if len(v) == 1}


def _is_ms(t) -> bool:
    return isinstance(t, (int, float)) and not isinstance(t, bool)


def endpoint_step(index: dict, handle, ts):
    """Step a link endpoint belongs to: ``(handle, ts)`` when the link carries a time, else the bare handle."""
    if _is_ms(ts):
        got = index.get((str(handle), ts))
        if got is not None:
            return got
    return index.get(str(handle))


def _keyed(alert: dict) -> bool:
    keys = alert.get("causal_keys")
    return isinstance(keys, (list, tuple)) and len(keys) > 0


def _rate(k: int, n: int) -> dict:
    return {"value": round(k / n, 4) if n else None, "k": k, "n": n, "wilson95": wilson_interval(k, n)}


# ---------------------------------------------------------------------------
# One storyline
# ---------------------------------------------------------------------------
def grade_storyline(name: str, emitted: list, truth: list, items: list) -> dict:
    """Grade one storyline. ``emitted`` may be the union of ``links`` over its incident graphs."""
    items = owner_items(items)
    handle_step = index_items(items)
    alerted = {i.get("step") for i in items or [] if i.get("step") is not None}

    gradable: dict = {}      # pair_key -> truth link
    non_gradable: list = []
    for lk in truth or []:
        f, t, basis = lk.get("from"), lk.get("to"), lk.get("basis")
        miss = [x for x, s in (("from", f), ("to", t)) if s not in alerted]
        if miss:
            non_gradable.append({"storyline": name, "from": f, "to": t, "basis": basis,
                                 "reason": ("both_unalerted" if len(miss) == 2 else f"{miss[0]}_unalerted")})
            continue
        gradable[pair_key(basis, f, t)] = {"from": f, "to": t, "basis": basis}

    predicted: dict = {}     # pair_key -> {"from","to","basis","orders"}
    unmapped = intra = 0
    seen_event_pairs: set = set()
    for lk in emitted or []:
        fe, te, basis = lk.get("from_event_id"), lk.get("to_event_id"), lk.get("basis")
        ident = (str(fe), str(te), basis)
        if ident in seen_event_pairs:
            continue  # the same event link repeated across incident graphs counts once
        seen_event_pairs.add(ident)
        fs = endpoint_step(handle_step, fe, lk.get("from_ts_ms"))
        ts = endpoint_step(handle_step, te, lk.get("to_ts_ms"))
        if fs is None or ts is None:
            unmapped += 1
            continue
        if fs == ts:
            intra += 1
            continue
        key = pair_key(basis, fs, ts)
        slot = predicted.setdefault(key, {"from": fs, "to": ts, "basis": basis, "orders": []})
        slot["orders"].append(lk.get("order"))

    matched = [k for k in predicted if k in gradable]
    correct_dir = 0
    order_counts: dict = {}
    for k in matched:
        p, g = predicted[k], gradable[k]
        # a step-pair held by several event links is a direction success only if EVERY one is
        orders = p["orders"] or [None]
        for o in orders:
            order_counts[o] = order_counts.get(o, 0) + 1
        if all(direction_ok(p["from"], p["to"], g["from"], g["to"], o) for o in orders):
            correct_dir += 1

    n_pred = len(predicted) + unmapped
    alerts = [i.get("alert") or {} for i in items or []]
    per_basis: dict = {}
    for k in gradable:
        b = per_basis.setdefault(k[0], {"gradable": 0, "matched": 0, "predicted": 0})
        b["gradable"] += 1
    for k, p in predicted.items():
        b = per_basis.setdefault(k[0], {"gradable": 0, "matched": 0, "predicted": 0})
        b["predicted"] += 1
        b["matched"] += k in gradable
    return {
        "storyline": name,
        "n_truth": len(truth or []),
        "n_gradable": len(gradable),
        "non_gradable": non_gradable,
        "n_emitted_event_links": len(seen_event_pairs),
        "n_predicted": n_pred,
        "unmapped": unmapped,
        "intra_step": intra,
        "matched": len(matched),
        "precision": _rate(len(matched), n_pred),
        "recall": _rate(len(matched), len(gradable)),
        "direction_accuracy": _rate(correct_dir, len(matched)),
        "order_counts": {str(k): v for k, v in sorted(order_counts.items(), key=lambda kv: str(kv[0]))},
        "coverage": _rate(sum(1 for a in alerts if _keyed(a)), len(alerts)),
        "per_basis": per_basis,
    }


# ---------------------------------------------------------------------------
# Pooling and the gate
# ---------------------------------------------------------------------------
def combine(results: list) -> dict:
    """Pool per-storyline results: sum the (k, n) counts and recompute every rate and interval."""
    def tot(path):
        k = n = 0
        for r in results:
            x = r[path]
            k += x["k"]
            n += x["n"]
        return _rate(k, n)

    per_basis: dict = {}
    per_story: dict = {}
    non_gradable: list = []
    for r in results:
        non_gradable += list(r["non_gradable"])
        per_story[r["storyline"]] = r["n_gradable"]
        for b, v in r["per_basis"].items():
            agg = per_basis.setdefault(b, {"gradable": 0, "matched": 0, "predicted": 0})
            for f in agg:
                agg[f] += v[f]
    for b, v in per_basis.items():
        v["recall"] = _rate(v["matched"], v["gradable"])
        v["precision"] = _rate(v["matched"], v["predicted"])
    return {
        "storylines": [r["storyline"] for r in results],
        "n_truth": sum(r["n_truth"] for r in results),
        "n_gradable": sum(r["n_gradable"] for r in results),
        "n_non_gradable": len(non_gradable),
        "non_gradable": non_gradable,
        "n_predicted": sum(r["n_predicted"] for r in results),
        "unmapped": sum(r["unmapped"] for r in results),
        "intra_step": sum(r["intra_step"] for r in results),
        "matched": sum(r["matched"] for r in results),
        "precision": tot("precision"),
        "recall": tot("recall"),
        "direction_accuracy": tot("direction_accuracy"),
        "coverage": tot("coverage"),
        "per_basis": per_basis,
        "per_storyline_gradable": per_story,
    }


def shuffle_collapsed(baseline: dict, shuffled: dict) -> dict:
    """Did ``key_shuffle`` take precision and recall to <= 0.25 x baseline? Pooled results in, verdict out.

    An undefined baseline metric cannot show a collapse (``ok`` False). Undefined shuffled PRECISION with
    zero predicted links is vacuously collapsed (no link, no false link); undefined shuffled recall cannot
    happen with a defined baseline recall."""
    out: dict = {"ok": True, "metrics": {}}
    for m in ("precision", "recall"):
        b, s = baseline[m]["value"], shuffled[m]["value"]
        if b is None:
            ok = False
        elif s is None:
            ok = (m == "precision" and shuffled["n_predicted"] == 0)
        else:
            ok = s <= SHUFFLE_COLLAPSE_FRACTION * b
        out["metrics"][m] = {"baseline": b, "shuffled": s, "ok": ok}
        out["ok"] = out["ok"] and ok
    return out


def gate(results: list, key_shuffle: Optional[list] = None) -> dict:
    """ADR-012 gate over per-storyline ``grade_storyline`` results.

    ``key_shuffle`` is the per-storyline results of the SAME storylines re-run with the ``key_shuffle``
    control (see ``key_controls``). Verdicts: ``insufficient_n`` (reasons listed; never a pass),
    ``pass``, ``fail`` (enough data, but a control is missing or did not collapse)."""
    pooled = combine(results)
    why: list = []
    n = pooled["n_gradable"]
    if n < MIN_GRADABLE_LINKS:
        why.append(f"gradable links {n} < {MIN_GRADABLE_LINKS}")
    contributing = {s: c for s, c in pooled["per_storyline_gradable"].items() if c > 0}
    if len(contributing) < MIN_STORYLINES:
        why.append(f"storylines contributing {len(contributing)} < {MIN_STORYLINES}")
    qualified = sorted(b for b, v in pooled["per_basis"].items() if v["gradable"] >= MIN_PER_BASIS)
    if len(qualified) < MIN_BASES:
        why.append(f"bases with >= {MIN_PER_BASIS} gradable links: {len(qualified)} < {MIN_BASES}")
    share = (max(contributing.values()) / n) if n and contributing else None
    if share is not None and share > MAX_STORYLINE_SHARE:
        why.append(f"largest storyline share {share:.3f} > {MAX_STORYLINE_SHARE}")

    out: dict[str, Any] = {"verdict": None, "reasons": why, "failures": [], "pooled": pooled,
           "max_storyline_share": round(share, 4) if share is not None else None,
           "claimable_bases": qualified,
           "bases_below_min": sorted(b for b, v in pooled["per_basis"].items()
                                     if 0 < v["gradable"] < MIN_PER_BASIS),
           "key_shuffle": None}
    if why:
        out["verdict"] = "insufficient_n"
        return out
    if key_shuffle is None:
        out["failures"].append("key_shuffle control not supplied")
    else:
        shuf = shuffle_collapsed(pooled, combine(key_shuffle))
        out["key_shuffle"] = shuf
        if not shuf["ok"]:
            out["failures"].append("key_shuffle did not collapse precision and recall to <= "
                                   f"{SHUFFLE_COLLAPSE_FRACTION} x baseline")
    out["verdict"] = "fail" if out["failures"] else "pass"
    return out
