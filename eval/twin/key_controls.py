"""key_controls -- the four ADR-012 key controls: ``key_shuffle``, ``key_drop``, ``key_collide``, ``key_forge``.

The ADR-012 analogue of ``eval/adversarial/order_controls.py``. Each control is a METRIC CONTROL for the
instrument (``causal_links``), not a mutation of the product: it perturbs the ``causal_keys`` carried by the
captured ws4 alerts BEFORE ws8 runs, re-runs the REAL ws8 Correlator, and re-grades. A link metric that cannot
say no on perturbed keys is rejected (ADR-012 s.3: "each must collapse the metric it targets").

    control        what it does to the alerts                                       must happen
    -------------  ---------------------------------------------------------------  ------------------------------
    key_shuffle    permute key hashes among key slots inside each (namespace,       precision AND recall <= 0.25 x
                   scope), preserving the multiset of hashes                         baseline (checked pooled by
                                                                                     ``causal_links.gate``)
    key_drop       delete every causal key                                          zero links, recall 0,
                                                                                     coverage 0 (nothing stays
                                                                                     labelled causal)
    key_collide    give two unrelated alerts the SAME weak key value: a bare PID    no link between the two
                   (no start time) on ``proc``, ``0x0`` on ``logon``, ``0`` on      events (the canonicaliser's
                   ``flow``. The key goes through the REAL ``key_hash``             weak-key / null-value rule
                                                                                     leaves them keyless)
    key_forge      a second sender replays a genuine event's scope and key value    no link between the forged and
                   (same scope, same value, different ``sender``), and the          the genuine event; no link
                   ``("a|b","c")`` vs ``("a","b|c")`` scope/value pair              between the two encoded pairs
                                                                                     (sender is in the hash; the
                                                                                     encoding is injective)

Why ``key_collide`` / ``key_forge`` build keys through ``shared.causal_keys.key_hash`` and not by editing ``h``:
at alert level a key is already a hash, so a weak value or a different sender is only visible BEFORE hashing.
Putting the perturbation at the raw-value step exercises the canonicaliser and the sender-in-hash rule, the two
defences the ADR names. ``hash_fn`` is injectable so a test can swap in a deliberately broken hash and watch the
control fail. (The twin BUILDERS must not import ``causal_keys``; this evaluator may, and must.)

ws8 is loaded lazily under a unique module name (the report.py "main.py collision" discipline): importing this
module has no side effect on ``sys.path``.

Everything here is deterministic: a seeded ``random.Random``, fixed ordering, no wall clock.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import random
import sys
from pathlib import Path
from typing import Any, Callable, Optional

ROOT = Path(__file__).resolve().parents[2]
TWIN = Path(__file__).resolve().parent
SERVICES = ROOT / "services"
for _p in (str(TWIN), str(SERVICES)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import causal_links as cl  # noqa: E402
from shared import causal_keys as ck  # noqa: E402

_WS8_PATH = SERVICES / "ws8-correlation" / "correlator.py"
_WS8_MOD_NAME = "ws8_correlator_mod"  # the SAME unique name report.py uses: one load per process

#: (namespace, weak value) variants of key_collide. All three are "none" to the real canonicalisers.
COLLIDE_VARIANTS = (("proc", "1234"), ("logon", "0x0"), ("flow", "0"))
FORGED_SENDER = "203.0.113.250"
HOUR_MS = 3_600_000


def ws8_module():
    """Load the REAL ws8 correlator once (unique module name, lazy)."""
    mod = sys.modules.get(_WS8_MOD_NAME)
    if mod is not None:
        return mod
    spec = importlib.util.spec_from_file_location(_WS8_MOD_NAME, _WS8_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot locate {_WS8_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_WS8_MOD_NAME] = mod
    spec.loader.exec_module(mod)
    return mod


def run_correlation(alerts: list) -> list:
    """Feed ``alerts`` (in the order given) through a fresh REAL Correlator and return the union of
    ``links[]`` over every promoted incident's final graph, de-duplicated and in a stable order."""
    ws8 = ws8_module()
    times = [a.get("time") for a in alerts if isinstance(a.get("time"), int)]
    now_ms = (max(times) if times else 0) + HOUR_MS
    corr = ws8.Correlator(ws8.DequeWindowCounter(), allowlist=ws8.Allowlist([]),
                          now_fn=lambda: now_ms / 1000.0)
    seen_ids: set = set()
    for a in alerts:
        for inc in corr.ingest_alert(copy.deepcopy(a)):
            seen_ids.add(inc["incident_id"])
    out: list = []
    seen: set = set()
    for iid in sorted(seen_ids):
        for lk in (corr.incident_graph(iid) or {}).get("links") or []:
            ident = (lk.get("from_event_id"), lk.get("to_event_id"), lk.get("basis"))
            if ident not in seen:
                seen.add(ident)
                out.append(lk)
    return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def make_keys(tenant: str, specs: list, hash_fn: Callable = ck.key_hash) -> list:
    """Alert-shape ``causal_keys`` from raw key material. A spec is ``{ns, role, scope, value, sender?,
    trust?}``; a value the canonicaliser drops yields NO key (fail closed), exactly like ws4."""
    out: list = []
    for s in specs:
        h = hash_fn(tenant, s["ns"], s.get("sender", ""), s.get("scope", ""), s["value"])
        if h is not None:
            out.append({"ns": s["ns"], "role": s.get("role", "self"), "h": h,
                        "scope_trust": s.get("trust", "observed")})
    return out


def _handle(alert: dict) -> str:
    h = cl._handle(alert)
    return h if h is not None else ""


def _keys(alert: dict) -> list:
    return [k for k in alert.get("causal_keys") or [] if isinstance(k, dict)]


def _hashes(alert: dict) -> set:
    return {(k.get("ns"), k.get("h")) for k in _keys(alert)}


def _track_signature(alert: dict) -> str:
    """Alerts of one ws8 track share an actor / address; the signature groups them."""
    return json.dumps([alert.get("actor"), alert.get("src_endpoint")], sort_keys=True, default=str)


def link_between(links: list, a: str, b: str) -> list:
    """The emitted links joining the two event handles, in either direction."""
    return [lk for lk in links
            if {str(lk.get("from_event_id")), str(lk.get("to_event_id"))} == {str(a), str(b)}]


def _default_scope(alert: dict, _key: dict):
    return alert.get("tenant_id")


# ---------------------------------------------------------------------------
# The controls (alerts in -> perturbed deep copy + info out)
# ---------------------------------------------------------------------------
def key_shuffle(alerts: list, seed: int = 7, scope_fn: Optional[Callable] = None) -> tuple:
    """Permute key hashes among the key slots of each (namespace, scope), keeping the multiset of hashes and
    every slot's role. ``scope_fn(alert, key) -> hashable`` names the scope (default: the tenant; a caller that
    knows the sensor / host passes it). A group is re-drawn until it differs from the original assignment (up
    to 50 tries), so a shuffle is never the identity when it could be anything else."""
    scope_fn = scope_fn or _default_scope
    out = copy.deepcopy(alerts)
    groups: dict = {}
    for ai, a in enumerate(out):
        for ki, k in enumerate(_keys(a)):
            if k.get("h"):
                groups.setdefault((k.get("ns"), repr(scope_fn(a, k))), []).append((ai, ki))
    pairs_before = _co_holders(out)
    rng = random.Random(seed)
    moved = slots = 0
    for gkey in sorted(groups):
        idxs = groups[gkey]
        slots += len(idxs)
        hs = [_keys(out[ai])[ki]["h"] for ai, ki in idxs]
        if len(set(hs)) < 2:
            continue
        perm = list(hs)
        for _ in range(50):
            rng.shuffle(perm)
            if perm != hs:
                break
        for (ai, ki), h in zip(idxs, perm):
            if _keys(out[ai])[ki]["h"] != h:
                moved += 1
            _keys(out[ai])[ki]["h"] = h
    pairs_after = _co_holders(out)
    return out, {"control": "key_shuffle", "slots": slots, "moved": moved,
                 "co_holder_pairs_before": len(pairs_before),
                 "co_holder_pairs_preserved": len(pairs_before & pairs_after)}


def _co_holders(alerts: list) -> set:
    """Unordered alert-index pairs that share a (namespace, hash)."""
    holders: dict = {}
    for ai, a in enumerate(alerts):
        for key in _hashes(a):
            holders.setdefault(key, set()).add(ai)
    pairs: set = set()
    for members in holders.values():
        m = sorted(members)
        pairs |= {(x, y) for i, x in enumerate(m) for y in m[i + 1:]}
    return pairs


def key_drop(alerts: list) -> tuple:
    """Delete every causal key."""
    out = copy.deepcopy(alerts)
    dropped = 0
    for a in out:
        dropped += len(_keys(a))
        a["causal_keys"] = []
    return out, {"control": "key_drop", "keys_dropped": dropped}


def _pick_unrelated_pair(alerts: list) -> Optional[tuple]:
    """First two alerts of one ws8 track, with distinct handles, that share no key."""
    by_track: dict = {}
    for i, a in enumerate(alerts):
        by_track.setdefault(_track_signature(a), []).append(i)
    for sig in sorted(by_track):
        idxs = by_track[sig]
        for x in range(len(idxs)):
            for y in range(x + 1, len(idxs)):
                a, b = alerts[idxs[x]], alerts[idxs[y]]
                if _handle(a) != _handle(b) and not (_hashes(a) & _hashes(b)):
                    return idxs[x], idxs[y]
    return None


def key_collide(alerts: list, ns: str = "proc", value: str = "1234",
                hash_fn: Callable = ck.key_hash, scope: str = "collide-host") -> tuple:
    """Give two unrelated alerts of one track the same WEAK key value through ``hash_fn`` (the real
    canonicaliser by default). Expectation: the value is dropped, the alerts stay keyless on it, and no link
    joins them. The key is prepended so ws8's 6-key bound cannot cut it. ``applied`` is False when the alerts
    hold no such pair (the control then says nothing)."""
    out = copy.deepcopy(alerts)
    pair = _pick_unrelated_pair(out)
    info: dict[str, Any] = {"control": "key_collide", "ns": ns, "value": value, "applied": False,
            "pair": None, "keys_attached": 0}
    if pair is None:
        return out, info
    ia, ib = pair
    roles = ("self", "parent") if ns == "proc" else ("self", "self")
    for idx, role in zip(pair, roles):
        a = out[idx]
        spec = {"ns": ns, "role": role, "scope": scope, "value": value, "sender": ""}
        ks = make_keys(a.get("tenant_id") or "default", [spec], hash_fn)
        info["keys_attached"] += len(ks)
        a["causal_keys"] = ks + _keys(a)
    info["applied"] = True
    info["pair"] = (_handle(out[ia]), _handle(out[ib]))
    return out, info


def key_forge(alerts: list, specs_by_handle: dict, forged_sender: str = FORGED_SENDER,
              hash_fn: Callable = ck.key_hash, limit: int = 3) -> tuple:
    """Two forgeries, both through ``hash_fn``.

    (1) SENDER: for up to ``limit`` genuine alerts whose key material is in ``specs_by_handle``
        (``{event handle: [spec, ...]}``, specs as in ``make_keys``), append a forged copy on the same track
        carrying the SAME scope and value but sent by ``forged_sender``.
    (2) ENCODING: two more alerts on that track carry scope/value ``("a|b","c")`` and ``("a","b|c")`` on one
        ``flow`` key; a delimiter-joined hash would equate them.

    ``info["pairs"]`` are the (genuine, forged) handles and the encoding pair; ``info["forged_handles"]`` every
    forged event. Expectation (``check_forge``): no link between a forged and ANY genuine event (a replayed key
    joins the forger to whichever genuine event holds that key, not necessarily the one it copied) and none
    inside the encoding pair."""
    out = copy.deepcopy(alerts)
    info: dict[str, Any] = {"control": "key_forge", "applied": False, "pairs": [], "forged_handles": [],
            "encoding_pair": None, "forged_sender": forged_sender}
    genuine = [a for a in out if _handle(a) in specs_by_handle][:limit]
    if not genuine:
        return out, info
    base = genuine[0]
    tenant = base.get("tenant_id") or "default"
    t0 = max((a.get("time") for a in out if isinstance(a.get("time"), int)), default=0)
    n = 0
    for g in genuine:
        specs = [dict(s, sender=forged_sender) for s in specs_by_handle[_handle(g)]]
        f = copy.deepcopy(g)
        n += 1
        f["alert_id"] = f"forge-{n}"
        f["event_ids"] = [f"forge-ev-{n}"]
        f["time"] = t0 + n
        f["mitre"] = dict(g.get("mitre") or {})
        f["causal_keys"] = make_keys(g.get("tenant_id") or tenant, specs, hash_fn)
        out.append(f)
        info["pairs"].append((_handle(g), _handle(f)))
        info["forged_handles"].append(_handle(f))
    enc = []
    for scope, value in (("a|b", "c"), ("a", "b|c")):
        e = copy.deepcopy(base)
        n += 1
        e["alert_id"] = f"forge-{n}"
        e["event_ids"] = [f"forge-ev-{n}"]
        e["time"] = t0 + n
        e["causal_keys"] = make_keys(tenant, [{"ns": "flow", "role": "self", "scope": scope,
                                               "value": value, "sender": ""}], hash_fn)
        out.append(e)
        enc.append(_handle(e))
        info["forged_handles"].append(_handle(e))
    info["pairs"].append(tuple(enc))
    info["encoding_pair"] = tuple(enc)
    info["applied"] = True
    return out, info


# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------
def check_key_drop(baseline: dict, dropped: dict) -> dict:
    """After ``key_drop``: zero links, recall 0 (or undefined when nothing was gradable), coverage 0."""
    rec = dropped["recall"]["value"]
    cov = dropped["coverage"]["value"]
    ok = (dropped["n_predicted"] == 0 and rec in (0, 0.0, None) and cov in (0, 0.0, None)
          and baseline["n_predicted"] > 0)
    return {"ok": ok, "links_after": dropped["n_predicted"], "recall_after": rec, "coverage_after": cov,
            "links_before": baseline["n_predicted"]}


def check_forge(links: list, info: dict) -> dict:
    """``key_forge``: (1) no emitted link joins a forged event to a GENUINE one; (2) none joins the two events
    of the encoding pair. Links among the forged events themselves are the forger's own sender scope (ADR-012:
    a holder can always forge inside its own scope) and are not a failure."""
    forged = {str(h) for h in info["forged_handles"]}
    cross = [(lk["from_event_id"], lk["to_event_id"]) for lk in links
             if (str(lk.get("from_event_id")) in forged) != (str(lk.get("to_event_id")) in forged)]
    enc = check_no_link(links, [info["encoding_pair"]]) if info.get("encoding_pair") else {"ok": True}
    return {"ok": not cross and enc["ok"], "forged_events": len(forged), "forged_vs_genuine": cross,
            "encoding_pair_linked": not enc["ok"]}


def check_no_link(links: list, pairs: list) -> dict:
    """``key_collide`` / ``key_forge``: no emitted link between any listed pair of event handles."""
    bad = [p for p in pairs if link_between(links, p[0], p[1])]
    return {"ok": not bad, "pairs": len(pairs), "linked": bad}


# ---------------------------------------------------------------------------
# One storyline, all controls
# ---------------------------------------------------------------------------
def run_controls(case: dict, seed: int = 7, run: Callable = run_correlation,
                 hash_fn: Callable = ck.key_hash) -> dict:
    """Run baseline + the four controls for ONE storyline and re-grade each.

    ``case``: ``{name, alerts, items, truth, key_specs?, scope_fn?}``. ``items`` are the attack alerts
    ``[{step, alert}]`` the grader maps event ids through; the controls perturb ``case["alerts"]`` (what ws8
    consumes). ``key_specs`` is ``{event handle: [spec, ...]}`` for ``key_forge``. The ``baseline`` and
    ``key_shuffle`` / ``key_drop`` entries are ``grade_storyline`` results (pool them with
    ``causal_links.combine`` / ``causal_links.gate``); the collide / forge entries are verdicts."""
    name, alerts, items, truth = case["name"], case["alerts"], case["items"], case["truth"]
    base_links = run(alerts)
    baseline = cl.grade_storyline(name, base_links, truth, items)

    def regrade(perturbed: list, controlled_items: Optional[list] = None) -> dict:
        return cl.grade_storyline(name, run(perturbed), truth, controlled_items if controlled_items is not None
                                  else _items_with_keys(items, perturbed))

    shuf_alerts, shuf_info = key_shuffle(alerts, seed, case.get("scope_fn"))
    shuffled = regrade(shuf_alerts)
    drop_alerts, drop_info = key_drop(alerts)
    dropped = regrade(drop_alerts)

    collide: dict = {}
    for ns, value in COLLIDE_VARIANTS:
        c_alerts, c_info = key_collide(alerts, ns, value, hash_fn)
        if c_info["applied"]:
            c_info["verdict"] = check_no_link(run(c_alerts), [c_info["pair"]])
        collide[f"{ns}:{value}"] = c_info

    forge: dict = {"applied": False}
    if case.get("key_specs"):
        f_alerts, forge = key_forge(alerts, case["key_specs"], hash_fn=hash_fn)
        if forge["applied"]:
            forge["verdict"] = check_forge(run(f_alerts), forge)
    return {"storyline": name, "baseline": baseline,
            "key_shuffle": shuffled, "key_shuffle_info": shuf_info,
            "key_drop": dropped, "key_drop_info": drop_info,
            "key_drop_verdict": check_key_drop(baseline, dropped),
            "key_collide": collide, "key_forge": forge}


def _items_with_keys(items: list, perturbed_alerts: list) -> list:
    """Re-point ``items`` at the perturbed alerts so ``coverage`` reflects the perturbation (match by handle)."""
    by_handle = {_handle(a): a for a in perturbed_alerts}
    out = []
    for it in items:
        al = by_handle.get(_handle(it.get("alert") or {}))
        out.append({"step": it.get("step"), "alert": al if al is not None else it.get("alert")})
    return out
