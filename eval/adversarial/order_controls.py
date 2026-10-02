"""order_controls -- the reversed-order METRIC CONTROL for the join/order metrics.

WHAT THIS IS
    A control for the INSTRUMENT, not a mutation of the PRODUCT. A metric that
    claims to grade causal order must be able to say no: if the same attack is
    played backwards in time the order metrics must collapse, and -- the half
    that makes the finding -- the legacy join metrics must NOT, because they
    never read a clock (measured 2026-10-02, seed 7, all three storylines:
    chain_fidelity 0.6 / 0.5 / 0.5, false_correlation_rate 1.0,
    directional_discrimination 0.0, tpr 1.0, incident_count 2 / 3 / 1 are
    IDENTICAL on the mirrored chain; only ``alert_order_ok`` flips).

VARIANTS (all pure functions of (payloads, seed); payloads are the
``(spec, payload)`` pairs ``mutate_generic`` uses)
    identity      the true chain, through the same payload-source path.
    mirror        every timed event moved to ``lo + hi - t`` and delivery
                  re-sorted so it follows the logs: the attack happens backwards.
    swap          two adjacent graded steps exchange their start times (each
                  keeps its internal burst offsets): a graded intermediate case,
                  so the metric is a fraction and not a coin flip.
    shift_1h      a pure replay offset (``mutate_generic`` timing/shift_1h): the
                  POSITIVE control -- order metrics must be unchanged.

POLICY (why this is not in ``mutate_generic._STATIC``)
    These variants are metric controls and are reported BESIDE
    ``mutation_robustness``, never pooled into it. ``mutate_generic`` records why:
    an earlier time-rewriting ``swap_first_two_steps`` variant was removed from
    the product catalogue because failing it said nothing about the product -- the
    logs said the steps happened in the other order. The same is true of
    ``mirror`` here, so it must not become a pass/fail row for the product.

VALIDITY (``valid``)
    A mirrored run only counts when the mirror did not simply break the pipeline:
    the mirrored span must be far below the correlator's 24 h horizon and the
    incident count must equal the identity run's. Otherwise the row is reported
    with ``valid=False`` and the reason, and the lane's self-check fails.

STDLIB ONLY (plus the harness modules it drives). Deterministic.
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ADVERSARIAL = Path(__file__).resolve().parent
TWIN = ROOT / "eval" / "twin"
SERVICES = ROOT / "services"
for _p in (str(ADVERSARIAL), str(TWIN), str(SERVICES)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import mutate_generic as mg  # noqa: E402
import scenario_registry as reg  # noqa: E402

#: WS-8's default horizon (services/ws8-correlation/correlator.py DEFAULT_HORIZON_S).
HORIZON_MS = 24 * 3600 * 1000

#: Metrics reported per variant, in print order.
ORDER_KEYS = ("alert_order_ok", "order_concordance", "causal_order_fidelity")
LEGACY_KEYS = ("tpr", "chain_fidelity", "false_correlation_rate", "directional_discrimination",
               "incident_count", "incident_membership_ok")


def _times(payloads: list) -> list:
    return [t for t in (mg.get_time(p) for _s, p in payloads) if t is not None]


def mirror_event_time(payloads: list) -> tuple:
    """Time-mirror a payload list. Returns ``(payloads, changed)``; the input is
    never mutated. Every timed payload moves to ``lo + hi - t`` (envelope clock
    AND the source's own timestamp field, via ``mutate_generic.set_time``) and
    the list is then stably re-sorted by the new time, so delivery order follows
    the logs rather than the original generation order."""
    out = copy.deepcopy(payloads)
    ts = _times(out)
    if not ts:
        return out, 0
    lo, hi = min(ts), max(ts)
    changed = 0
    for _s, p in out:
        t = mg.get_time(p)
        if t is not None and mg.set_time(p, lo + hi - t):
            changed += 1
    out.sort(key=lambda x: (mg.get_time(x[1]) if mg.get_time(x[1]) is not None else 0))
    return out, changed


def swap_adjacent_steps(payloads: list, a: str, b: str) -> tuple:
    """Exchange the start times of step blocks ``a`` and ``b``. Each block keeps
    its internal offsets (a burst stays a burst); delivery is re-sorted by the
    new time. Returns ``(payloads, changed)``; ``(copy, 0)`` if either step has
    no timed payload."""
    out = copy.deepcopy(payloads)
    idx = {a: [], b: []}
    for i, (spec, p) in enumerate(out):
        if spec.label in idx and mg.get_time(p) is not None:
            idx[spec.label].append(i)
    if not idx[a] or not idx[b]:
        return out, 0
    start_a = min(mg.get_time(out[i][1]) for i in idx[a])
    start_b = min(mg.get_time(out[i][1]) for i in idx[b])
    changed = 0
    for i in idx[a]:
        t = mg.get_time(out[i][1])
        changed += bool(mg.set_time(out[i][1], start_b + (t - start_a)))
    for i in idx[b]:
        t = mg.get_time(out[i][1])
        changed += bool(mg.set_time(out[i][1], start_a + (t - start_b)))
    out.sort(key=lambda x: (mg.get_time(x[1]) if mg.get_time(x[1]) is not None else 0))
    return out, changed


def pick_swap_pair(sdef, base_grade: dict):
    """The first adjacent pair of the oracle's ``expected_sequence`` that is a
    GRADED allowed pair in the identity run (so swapping it can move the metric)."""
    graded = {(r["from"], r["to"]) for r in base_grade.get("causal_order", {}).get("per_pair", [])
              if r.get("graded")}
    seq = list(reg.load_oracle(sdef).get("expected_sequence") or [])
    for x, y in zip(seq, seq[1:]):
        if (x, y) in graded:
            return x, y
    return None


def validity_reason(changed: int, span, identity_incidents, mirror_incidents):
    """Why a mirrored run must NOT count (``None`` = it counts). Pure, so the test can
    drive each branch: the mirror must have moved something, the storyline must sit far
    below the correlator's 24 h horizon (a longer one could silently turn mirrored times
    into 'now' fallbacks), and the PIPELINE's incident count must not have moved (else the
    pipeline, not the metric, changed)."""
    if changed == 0:
        return "mirror changed no event"
    if span is None or span >= HORIZON_MS // 4:
        return f"storyline span {span} ms is not far below the 24h correlator horizon"
    if mirror_incidents != identity_incidents:
        return (f"mirror changed incident_count {identity_incidents} -> {mirror_incidents}: "
                "the pipeline, not the metric, moved")
    return None


def _grade(sdef, seed: int, payloads: list) -> dict:
    def _src(_seed, payloads=payloads):
        return payloads, {}, {}, None

    return reg.grade(sdef, seed, payload_source=_src, strict=False)


def _row(name: str, grade: dict, changed: int) -> dict:
    co = grade.get("causal_order") or {}
    row = {"variant": name, "changed_events": changed}
    for k in ORDER_KEYS + LEGACY_KEYS:
        row[k] = grade.get(k)
    row["forbidden_order_realised_rate"] = co.get("forbidden_order_realised_rate")
    row["temporal_discrimination"] = co.get("temporal_discrimination")
    row["story_order_ok"] = co.get("story_order_ok")
    return row


def run_order_controls(sdef, seed: int = 7, swap: tuple | None = None) -> dict:
    """Run identity / mirror / swap / shift_1h over one storyline.

    Returns ``{scenario, rows: {variant: row}, swap_pair, mirror_valid,
    mirror_invalid_reason, legacy_equal_under_mirror}``. ``legacy_equal_under_mirror``
    is the finding: every ``LEGACY_KEYS`` value on the mirrored chain equals the
    identity run's."""
    base_payloads = sdef.build(seed)[0]
    ident = _grade(sdef, seed, copy.deepcopy(base_payloads))
    rows = {"identity": _row("identity", ident, 0)}

    mirrored, m_changed = mirror_event_time(base_payloads)
    m_grade = _grade(sdef, seed, mirrored)
    rows["mirror"] = _row("mirror", m_grade, m_changed)

    pair = swap or pick_swap_pair(sdef, ident)
    if pair:
        swapped, s_changed = swap_adjacent_steps(base_payloads, *pair)
        rows["swap"] = _row("swap", _grade(sdef, seed, swapped), s_changed)

    shifted, sh_changed = mg.apply(base_payloads, "timing", "shift_1h", seed=seed, sdef=sdef)
    rows["shift_1h"] = _row("shift_1h", _grade(sdef, seed, shifted), sh_changed)

    ts = _times(mirrored)
    span = (max(ts) - min(ts)) if ts else None
    reason = validity_reason(m_changed, span, rows["identity"]["incident_count"],
                             rows["mirror"]["incident_count"])
    return {
        "scenario": sdef.name,
        "rows": rows,
        "swap_pair": list(pair) if pair else None,
        "span_ms": span,
        "mirror_valid": reason is None,
        "mirror_invalid_reason": reason,
        "legacy_equal_under_mirror": all(rows["mirror"][k] == rows["identity"][k] for k in LEGACY_KEYS),
    }


def controls_ok(ctl: dict) -> list:
    """Self-check of ONE storyline's control table; returns problems (empty = ok).

    The instrument must be able to say YES (identity concordance 1.0, positive
    shift unchanged) and NO (mirror concordance 0.0, causal_order_fidelity 0.0 or
    None, alert_order_ok False)."""
    name, r = ctl["scenario"], ctl["rows"]
    bad = []
    if not ctl["mirror_valid"]:
        bad.append(f"{name}: mirror control invalid: {ctl['mirror_invalid_reason']}")
    if r["identity"]["order_concordance"] != 1.0:
        bad.append(f"{name}: identity order_concordance={r['identity']['order_concordance']!r}, "
                   "expected 1.0 (the control cannot say yes)")
    if r["mirror"]["order_concordance"] != 0.0:
        bad.append(f"{name}: mirrored order_concordance={r['mirror']['order_concordance']!r}, "
                   "expected 0.0 (the control cannot say no)")
    if r["mirror"]["causal_order_fidelity"] not in (0.0, None):
        bad.append(f"{name}: mirrored causal_order_fidelity={r['mirror']['causal_order_fidelity']!r}")
    if r["mirror"]["alert_order_ok"] is not False:
        bad.append(f"{name}: mirrored alert_order_ok={r['mirror']['alert_order_ok']!r}, expected False")
    for k in ("order_concordance", "causal_order_fidelity", "alert_order_ok"):
        if r["shift_1h"][k] != r["identity"][k]:
            bad.append(f"{name}: positive control shift_1h moved {k}: "
                       f"{r['identity'][k]!r} -> {r['shift_1h'][k]!r}")
    return bad


def main(argv: list | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="order_controls")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args(argv)
    bad: list = []
    cols = ("variant",) + ORDER_KEYS + ("forbidden_order_realised_rate",) + LEGACY_KEYS
    for sdef in reg.ALL:
        ctl = run_order_controls(sdef, args.seed)
        print(f"\n[{ctl['scenario']}] swap pair: {ctl['swap_pair']}  "
              f"legacy join metrics equal under mirror: {ctl['legacy_equal_under_mirror']}")
        print("  " + " | ".join(cols))
        for row in ctl["rows"].values():
            print("  " + " | ".join(str(row.get(c)) for c in cols))
        bad += controls_ok(ctl)
    for b in bad:
        print(f"[FAIL] {b}")
    print("[FAIL] order controls failed" if bad else "[OK] order controls can say yes and no")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
