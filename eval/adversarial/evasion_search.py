"""evasion_search -- find the BOUNDARY of each volume rule, end to end, and
cross-check it against what the rule's own YAML says it should be.

WHY THIS EXISTS (2026-10-01)
    A fixed mutation catalogue samples a few points ("drop 25% of the events",
    "stretch 6x") and reports pass/fail at each. Two things are wrong with that
    as the *baseline* an evaluation rests on:

      1. Where a point lands relative to the boundary decides the verdict. A
         burst only 2 events above its threshold fails "drop 25%"; one 10 above
         it passes. The pass/fail is a property of the catalogue's constants as
         much as of the product.
      2. Nothing says what the answer SHOULD be. "dns_exfil goes dark at 25%
         loss" is either correct (the rule needs 40 distinct names and the burst
         only had 44) or a bug. Without an independent expectation a red row and
         a green row are equally unexplained.

    This module replaces the guess with a measurement and the measurement with
    an expectation. For every burst step of every storyline, along four axes, it
    SEARCHES for the smallest perturbation that makes the step's expected rule
    stop firing through the REAL WS-2 -> WS-4 path:

      loss          events removed (evenly spread)      -> max tolerated loss
      pacing        inter-event gap multiplied          -> max tolerated stretch
      ip spread     burst round-robined over k addresses -> fewest k that evades
      account split burst round-robined over k accounts  -> fewest k that evades

    and then computes what the rule's DECLARED parameters (``siem.threshold``,
    ``window_seconds``, ``group_by`` in ``contracts/rules/*.yml``) predict for
    the same burst. The two are independent: the prediction reads YAML and the
    burst's own timestamps; the measurement runs the pipeline.

      agree     -> the end-to-end system honours the rule as written
      disagree  -> a real finding: the parser mangles a field the rule groups
                   on, enrichment re-keys the window, a boundary is off by one,
                   or the rule has slack/blindness its YAML does not declare.

    The search also states plainly what is NOT evadable: a rule grouped on the
    account is immune to address rotation (and vice versa). That is a result,
    not a skipped row.

DETERMINISTIC. No wall clock, no sampling: integer bisection / linear scan over
a single parameter, pure function of (scenario, seed).
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ADVERSARIAL = Path(__file__).resolve().parent
TWIN = ROOT / "eval" / "twin"
SERVICES = ROOT / "services"
for _p in (str(ADVERSARIAL), str(TWIN), str(SERVICES)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import yaml  # noqa: E402

import mutate_generic as mg  # noqa: E402
import scenario_registry as reg  # noqa: E402

OUT_DIR = ADVERSARIAL / "out"
DEFAULT_OUT = OUT_DIR / "evasion_search.latest.json"
RULES_DIR = ROOT / "contracts" / "rules"

#: Largest pacing multiple searched. A rule that still fires at this multiple
#: is reported "not evaded up to 50x", not "robust".
_STRETCH_CAP_PCT = 5000
#: Measured vs predicted stretch may differ by this fraction (window edge
#: inclusivity is a convention, not a defect).
_STRETCH_TOL = 0.03


# ---------------------------------------------------------------------------
# Declared rule parameters (independent of the engine)
# ---------------------------------------------------------------------------
def _rule_params() -> dict:
    out = {}
    for f in sorted(RULES_DIR.glob("*.yml")):
        d = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        rid, siem = d.get("id"), d.get("siem") or {}
        if rid:
            out[rid] = {
                "name": f.stem,
                "threshold": siem.get("threshold"),
                "window_seconds": siem.get("window_seconds"),
                "group_by": siem.get("group_by"),
                "distinct_field": siem.get("distinct_field"),
                "periodicity": siem.get("periodicity"),
            }
    return out


# ---------------------------------------------------------------------------
# Detection leg only (WS-2 -> WS-4): fast, no WS-8
# ---------------------------------------------------------------------------
def _fired(payloads: list) -> list:
    """Fired-rule dicts for ``payloads``.

    Default: ``probe_session.FastProbe`` (one Detector, a fresh window counter
    per probe; ~0.1 s per probe instead of ~2-4 s). ``FENGARDE_SLOW_PROBE=1``
    restores the original per-probe fresh ``Detector`` via
    ``report._real_detection``. The two are PROVEN to return identical lists
    (``probe_session.verify_parity``; ``test_evasion_axes.py``) and the JSON
    this module writes is byte-identical under either."""
    import probe_session  # noqa: PLC0415
    pairs = [(p["source_type"], p["raw"], p.get("meta"), spec.label) for spec, p in payloads]
    if probe_session.fast_probe_enabled():
        return probe_session.default_probe().detect(pairs)
    import report  # noqa: PLC0415
    return report._real_detection(pairs)


def _step_fires(fired: list, step: str, expected: set) -> bool:
    return any(a.get("step") == step and a.get("rule_id") in expected for a in fired)


def step_dependencies(oracle: dict, step: str) -> tuple:
    """The CONTEXT steps ``step``'s detection needs in the stream (oracle ``step_dependencies``,
    e.g. ``foreign_login: [victim_session]``: impossible travel needs the account's earlier
    login in the other country). Their events are replayed UNPERTURBED beside the step under
    test; without them a single-event step that depends on earlier telemetry is scored on a
    stream in which its rule cannot fire at all."""
    return tuple((oracle.get("step_dependencies") or {}).get(step) or ())


def _detects(payloads, step, expected, deps=()):
    """Does ``step``'s expected rule fire? Scored on the step's OWN events (plus its declared
    context-step ``deps``): the rules searched here are stateful per group key and the other steps
    use different sources, accounts and rules, so replaying the whole 95-event stream per probe
    only costs time. ``verify_subset_equivalence`` proves the two agree on the unperturbed
    stream."""
    keep = {step, *deps}
    sub = [x for x in payloads if x[0].label in keep]
    return _step_fires(_fired(sub), step, expected)


def verify_subset_equivalence(sdef, seed: int = 7) -> list:
    """Steps where the step-subset verdict differs from the full-stream verdict
    on the UNPERTURBED stream (must be empty for the shortcut to be valid)."""
    payloads = sdef.build(seed)[0]
    oracle = reg.load_oracle(sdef)
    full = _fired(payloads)
    bad = []
    for step, pt in (oracle.get("detection_points") or {}).items():
        exp = {r["rule_id"] for r in pt.get("expected_rules") or []}
        deps = step_dependencies(oracle, step)
        if exp and _step_fires(full, step, exp) != _detects(payloads, step, exp, deps):
            bad.append(step)
    return bad


# ---------------------------------------------------------------------------
# Single-step perturbations
# ---------------------------------------------------------------------------
def _idx(payloads, step):
    return [i for i, (s, _p) in enumerate(payloads) if s.label == step]


def _thin_step(payloads, step, r):
    idxs = _idx(payloads, step)
    n = len(idxs)
    if r <= 0:
        return list(payloads)
    drop = {idxs[min(n - 1, int(j * n / r + n / (2 * r)))] for j in range(r)}
    return [x for i, x in enumerate(payloads) if i not in drop]


def _stretch_step(payloads, step, pct):
    import copy  # noqa: PLC0415
    out = copy.deepcopy(payloads)
    idxs = _idx(out, step)
    t0 = min(mg.get_time(out[i][1]) for i in idxs)
    for i in idxs:
        t = mg.get_time(out[i][1])
        mg.set_time(out[i][1], t0 + (t - t0) * pct // 100)
    return out


def _spread_step(payloads, step, k, kind):
    import copy  # noqa: PLC0415
    out = copy.deepcopy(payloads)
    for rank, i in enumerate(_idx(out, step)):
        j = rank % k
        if kind == "ip":
            mg.set_src_ip(out[i][1], f"198.18.77.{j + 10}")
        else:
            base = mg.get_actor(out[i][1])
            if base is not None and j:
                mg.set_actor(out[i][1], f"{base}-{j + 1}")
    return out


# ---------------------------------------------------------------------------
# Searches
# ---------------------------------------------------------------------------
def _first_true(lo, hi, pred):
    """Smallest x in [lo, hi] with pred(x) true, assuming pred is monotone
    (false...false true...true) and pred(hi) is true. Integer bisection."""
    while lo < hi:
        mid = (lo + hi) // 2
        if pred(mid):
            hi = mid
        else:
            lo = mid + 1
    return lo


def _search_loss(payloads, step, expected, n, deps=()):
    """Largest number of events removable with the step still detected.
    Monotone in the number removed (more loss never helps a count rule), so
    bisect: the smallest r at which the step goes dark, minus one."""
    def dark(r):
        return not _detects(_thin_step(payloads, step, r), step, expected, deps)
    if dark(0):
        return None                                   # not detected even untouched
    return _first_true(1, n, dark) - 1


def _search_stretch(payloads, step, expected, deps=()):
    """Largest integer-percent stretch with the step still detected (bisect)."""
    if not _detects(_stretch_step(payloads, step, 100), step, expected, deps):
        return None
    if _detects(_stretch_step(payloads, step, _STRETCH_CAP_PCT), step, expected, deps):
        return _STRETCH_CAP_PCT                       # never evaded within the cap
    lo, hi = 100, _STRETCH_CAP_PCT                    # lo fires, hi does not
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if _detects(_stretch_step(payloads, step, mid), step, expected, deps):
            lo = mid
        else:
            hi = mid
    return lo


def spread_vacuity(payloads, step, kind):
    """Did the spread operator actually TOUCH this step's events, and if not, why?

    ``mutate_generic.set_src_ip`` / ``set_actor`` return False for a source with no adapter, and a
    spread that changed nothing leaves the rule firing -- which reads as "immune on this axis",
    indistinguishable from a rule that really is. Returns

      None               the operator changed events (the axis was genuinely probed);
      "field-absent"     it changed nothing because the PARSED events carry no such field (a port
                         scan has no account), so "immune" is true by construction;
      "adapter-missing"  it changed nothing although the parsed events DO carry the field: the
                         harness has no adapter for this source and every "immune" verdict on this
                         axis is vacuous. A failure of the instrument, reported as one.
    """
    import copy  # noqa: PLC0415
    import probe_session  # noqa: PLC0415
    idxs = _idx(payloads, step)
    before = [copy.deepcopy(payloads[i][1]) for i in idxs]
    after_all = _spread_step(payloads, step, 2, kind)
    if any(before[j] != after_all[i][1] for j, i in enumerate(idxs)):
        return None
    field = "src_endpoint" if kind == "ip" else "actor"
    sub = [x for x in payloads if x[0].label == step]
    pairs = probe_session.payloads_to_pairs(sub)
    for ev in probe_session.default_probe().normalized(pairs):
        if kind == "ip" and ((ev.get(field) or {}).get("ip")):
            return "adapter-missing"
        if kind != "ip" and (((ev.get(field) or {}).get("user") or {}).get("name")):
            return "adapter-missing"
    return "field-absent"


def _search_spread(payloads, step, expected, n, kind, deps=()):
    """Fewest addresses/accounts k at which the step stops being detected.
    Dispersion only grows with k, so test the extreme first: if one key per
    event still fires, the rule is immune on this axis (None)."""
    def dark(k):
        return not _detects(_spread_step(payloads, step, k, kind), step, expected, deps)
    if not dark(n):
        return None
    return _first_true(2, n, dark)


# ---------------------------------------------------------------------------
# Predictions from the rule's DECLARED parameters
# ---------------------------------------------------------------------------
def _predict(params, times_ms, n):
    T, W, gb = params["threshold"], params["window_seconds"], params["group_by"]
    pred = {"loss": None, "stretch_pct": None, "ip_k": "immune", "account_k": "immune"}
    if not T:
        return pred
    pred["loss"] = max(n - T, -1)
    if W and n >= T and T > 1:
        ts = sorted(times_ms)
        span = min(ts[i + T - 1] - ts[i] for i in range(0, n - T + 1))
        pred["stretch_pct"] = (int(W * 1000 * 100 // span) if span > 0 else _STRETCH_CAP_PCT)
    group = {"src_endpoint.ip": "ip_k", "actor.user.name": "account_k"}.get(gb)
    if group:
        # round-robin over k: max per-key count is ceil(n/k); evades once < T
        pred[group] = next((k for k in range(2, n + 1) if math.ceil(n / k) < T), None)
    return pred


def _combine(preds: list) -> dict:
    """Combine per-rule predictions into the prediction for a STEP.

    A step stays detected while ANY of its expected rules fires (the oracle's
    own any-intersection semantics), so:
      * tolerated loss / slowdown = the MOST tolerant rule's;
      * an axis is evaded only when EVERY rule is evaded, so the fewest keys
        that evade the step is the LARGEST of the rules' k -- and if any rule
        is immune on that axis (it is keyed on the other one, or cannot be
        evaded at all), the step is immune there.
    This is what makes a companion rule (e.g. one keyed on the account next to
    one keyed on the address) show up as exactly what it is: a step that can no
    longer be defeated by changing just one thing."""
    def _mx(vals):
        vals = [v for v in vals if v is not None]
        return max(vals) if vals else None

    out = {"loss": _mx([p["loss"] for p in preds]),
           "stretch_pct": _mx([p["stretch_pct"] for p in preds])}
    for key in ("ip_k", "account_k"):
        vs = [p[key] for p in preds]
        if any(v == "immune" or v is None for v in vs):
            out[key] = "immune"
        else:
            out[key] = max(vs)
    return out


def _agree(measured, predicted, key):
    if predicted is None:
        return None
    if key == "stretch_pct":
        if measured is None:
            return False
        if measured >= _STRETCH_CAP_PCT:
            return predicted >= _STRETCH_CAP_PCT
        return abs(measured - predicted) <= max(2, int(predicted * _STRETCH_TOL))
    return measured == predicted


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def search_scenario(sdef, seed: int = 7) -> dict:
    oracle = reg.load_oracle(sdef)
    rules = _rule_params()
    payloads = sdef.build(seed)[0]
    attack = {s.label for s in sdef.steps}
    by_step: dict = {}
    for i, (spec, _p) in enumerate(payloads):
        if spec.label in attack:
            by_step.setdefault(spec.label, []).append(i)

    rows = []
    for step in [s.label for s in sdef.steps]:
        idxs = by_step.get(step, [])
        n = len(idxs)
        exp = [r["rule_id"] for r in ((oracle.get("detection_points") or {}).get(step) or {}).get("expected_rules") or []]
        if n < mg._BURST_MIN or not exp:
            rows.append({"step": step, "events": n, "searched": False,
                         "reason": ("single-event step" if n < mg._BURST_MIN else "no expected rule (oracle gap)")})
            continue
        expected = set(exp)
        if any((rules.get(r) or {}).get("periodicity") for r in exp):
            # A periodic rule (beaconing) fires on the REGULARITY of the schedule, not only its
            # count: thinning evenly spaced beats leaves a double gap and a coefficient of
            # variation above the bound long before the count threshold is reached, so the
            # threshold/window prediction (``n - T``) is wrong BY CONSTRUCTION for the loss axis
            # (measured tolerated loss 0, predicted 2). Marked unsearched rather than reported as
            # a disagreement the model was never able to get right. The periodicity bound itself
            # is exercised by the pacing/jitter_100pct variant in scenario_matrix and by the
            # beacon negative twins.
            rows.append({"step": step, "events": n, "searched": False, "reason": "periodic rule",
                         "note": "thinning or stretching a schedule changes its coefficient of "
                                 "variation; the count/window model does not describe that"})
            continue
        # every expected rule with a declared threshold contributes to the prediction
        decls = [rules[r] for r in exp if r in rules and rules[r]["threshold"]]
        if not decls or len(decls) < len([r for r in exp if r in rules]):
            rows.append({"step": step, "events": n, "searched": False,
                         "reason": "an expected rule is stateless (no threshold to bound)"})
            continue
        times = [mg.get_time(payloads[i][1]) for i in idxs]
        pred = _combine([_predict(d, times, n) for d in decls])
        deps = step_dependencies(oracle, step)
        measured = {
            "loss": _search_loss(payloads, step, expected, n, deps),
            "stretch_pct": _search_stretch(payloads, step, expected, deps),
            "ip_k": _search_spread(payloads, step, expected, n, "ip", deps),
            "account_k": _search_spread(payloads, step, expected, n, "account", deps),
        }
        vacuity = {k: spread_vacuity(payloads, step, kind)
                   for k, kind in (("ip_k", "ip"), ("account_k", "account"))}
        vacuity = {k: v for k, v in vacuity.items() if v}
        # an axis the rule is declared immune to must also be immune in practice -- and the probe
        # must have actually perturbed something, or "immune" only means "untouched"
        verdict = {}
        for key in ("loss", "stretch_pct", "ip_k", "account_k"):
            p = pred[key]
            if vacuity.get(key) == "adapter-missing":
                verdict[key] = False
            elif p == "immune":
                verdict[key] = (measured[key] is None)
            else:
                verdict[key] = _agree(measured[key], p, key)
        rows.append({
            "step": step, "events": n, "searched": True,
            "rule": " + ".join(d["name"] for d in decls),
            "threshold": "/".join(str(d["threshold"]) for d in decls),
            "window_seconds": "/".join(str(d["window_seconds"]) for d in decls),
            "group_by": " | ".join(str(d["group_by"]) for d in decls),
            "measured": measured, "predicted": pred, "agree": verdict,
            "vacuous_axes": dict(sorted(vacuity.items())),
            "all_agree": all(v in (True, None) for v in verdict.values()),
            "margin_over_threshold": n - min(d["threshold"] for d in decls),
        })
    return {"scenario": sdef.name, "seed": seed, "rows": rows}


def search_all(seed: int = 7, scenarios: list | None = None) -> dict:
    sdefs = [reg.get(n) for n in scenarios] if scenarios else list(reg.ALL)
    return {"seed": seed, "basis": "harness-measured",
            "scenarios": {s.name: search_scenario(s, seed) for s in sdefs}}


def _fmt(measured, predicted, key):
    m = "never" if measured is None else (f"{measured / 100:g}x" if key == "stretch_pct" else str(measured))
    if key == "stretch_pct" and measured is not None and measured >= _STRETCH_CAP_PCT:
        m = f">={_STRETCH_CAP_PCT / 100:g}x"
    p = ("immune" if predicted == "immune" else "-" if predicted is None
         else f"{predicted / 100:g}x" if key == "stretch_pct" else str(predicted))
    return f"{m} (declared: {p})"


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(prog="evasion_search")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--seeds", type=str, default=None, help="comma-separated seeds")
    ap.add_argument("--scenario", action="append", default=None)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--warn-only", action="store_true")
    args = ap.parse_args(argv)

    seeds = [int(x) for x in args.seeds.split(",")] if args.seeds else [args.seed]
    all_ok = True
    results = {}
    for seed in seeds:
        res = search_all(seed, args.scenario)
        results[seed] = res
        print(f"== evasion boundary search (seed={seed}) ==")
        for name, sc in res["scenarios"].items():
            print(f"\n[{name}]")
            for r in sc["rows"]:
                if not r["searched"]:
                    print(f"  {r['step']:<22} not searched: {r['reason']}")
                    continue
                m, p = r["measured"], r["predicted"]
                flag = "ok " if r["all_agree"] else "MISMATCH"
                print(f"  {r['step']:<22} {r['events']} events, {r['rule']} T={r['threshold']} "
                      f"W={r['window_seconds']}s by {r['group_by']}  [{flag}]")
                print(f"      tolerates loss of   {_fmt(m['loss'], p['loss'], 'loss')} events")
                print(f"      tolerates slowdown  {_fmt(m['stretch_pct'], p['stretch_pct'], 'stretch_pct')}")
                print(f"      evaded by IPs       {_fmt(m['ip_k'], p['ip_k'], 'ip_k')}")
                print(f"      evaded by accounts  {_fmt(m['account_k'], p['account_k'], 'account_k')}")
                for axis, why in r.get("vacuous_axes", {}).items():
                    print(f"      (axis {axis}: {why} -- "
                          + ("the spread changed nothing because the parsed events carry no such field)"
                             if why == "field-absent" else
                             "NO ADAPTER for this source, so the verdict above is vacuous)"))
                if not r["all_agree"]:
                    all_ok = False
                    bad = [k for k, v in r["agree"].items() if v is False]
                    print(f"      >>> measured != declared on: {', '.join(bad)}")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(results if len(seeds) > 1 else results[seeds[0]], fh, indent=2)

    if not all_ok:
        print("\n[MISMATCH] end-to-end behaviour differs from what a rule's own YAML declares "
              "-- a hidden blind spot, hidden slack, or a boundary bug. See above.")
        return 0 if args.warn_only else 1
    print(f"\n[OK] every searched boundary matches its rule's declared parameters. -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
