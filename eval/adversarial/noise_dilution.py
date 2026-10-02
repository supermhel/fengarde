"""noise_dilution -- can benign-looking noise make a stateful rule forget an attack?

WHY THIS EXISTS (2026-10-02)
    The previous harness injected *decoys* (events that trip the same rules from
    other entities) and asked whether the incident stayed clean. It never asked
    the adversary's question: "what can I send, that no analyst would call an
    attack, that makes the detector lose track of the thing I am doing?"

    Probing found one answer end to end. ``DequeWindowCounter._sweep`` evicts
    every idle key using the CURRENT hit's window, not the key's own: noise on a
    60 s rule (one hit in 256) sweeps away the live 300 s / 600 s / 3600 s state
    of every other rule. The Redis backend uses a per-key ``EXPIRE`` so the two
    backends disagree. This module turns that primitive into an end-to-end
    instrument and states the attacker's price.

WHAT IS MEASURED (finding F1, an open BUG)
    For every stateful rule-set whose window is longer than the shortest window in
    the rule base, the reference burst is split by a pause longer than that short
    window, benign noise on disjoint keys is inserted in the pause, and the burst
    is replayed through the FULL stream (never the step-subset shortcut: the sweep
    phase is a function of the global hit count, which a subset replay changes).
    The cost is a vector, never a scalar:

        noise_events        the fewest noise events that make the set go dark (bisection)
        counter_hits        what they cost in the counter's own unit (a companion
                            rule makes one event two hits, so events are not hits)
        min_pause_seconds   the idle time the target key MUST show at the sweep tick

    ``predict_noise_events`` re-derives that number from ``_SWEEP_EVERY``, the
    counter's hit count before the noise and the windows of the hits one noise
    event causes -- an independent model; measured != predicted is a finding.

CONTROLS (each can fail)
    no noise -> detected; noise on a key that is NOT idle long enough -> detected
    (the negative that shows the cause is the sweep, not the noise); N*-1 events ->
    detected; a counter with a per-key sweep (the product fix) -> detected, so the
    instrument turns green when the bug is fixed; slow-path parity on the noise
    stream itself (parity on other streams does not cover this one).

BACKEND: DequeWindowCounter only. The Redis counter expires keys itself and has no
sweep, so this is a single-process (default backend) defect.

ALERT FLOODS (F5, informational)
    ``alert_flood_cost`` reports events per distinct alert id for floods built as
    (groups x window-buckets) cells that each reach the threshold. It does NOT
    assert "a flood collapses to <=2 alert ids": that holds for ONE group in <=2
    buckets only (unit-level property of ``Rule.alert_key``).

NOT DONE HERE (see evasion_findings.yaml / README): the WS-8 member-cap flood and
the disjoint-entity incident/triage metrics -- they need ``reg.grade`` (~10 s/call)
and the new triage_rank / incident_inflation metrics, which do not exist yet.
"""
from __future__ import annotations

import argparse
import copy
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

import evasion_axes as ax  # noqa: E402
import probe_session as ps  # noqa: E402
import rule_probes as rp  # noqa: E402
from shared import window as _window  # noqa: E402
from shared.window import DequeWindowCounter  # noqa: E402

SWEEP_EVERY = _window._SWEEP_EVERY
NOISE_STEP = "noise"
OUT_DIR = ADVERSARIAL / "out"
DEFAULT_OUT = OUT_DIR / "noise_dilution.latest.json"
#: Bisection ceiling (noise events). Two full sweep periods at one hit per event.
_NOISE_CAP = 2 * SWEEP_EVERY + 8
#: Pause (ms) built into the stream: the short window plus slack for the noise train.
_PAUSE_SLACK_MS = 2_000


# ---------------------------------------------------------------------------
# Counters used as instruments
# ---------------------------------------------------------------------------
class RecordingCounter(DequeWindowCounter):
    """Logs the window of every hit, in hit order (calibration of one noise event)."""

    def __init__(self) -> None:
        super().__init__()
        self.log: list = []

    def hit(self, key, now_ms, window_ms, member=None):
        self.log.append(window_ms)
        return super().hit(key, now_ms, window_ms, member)

    def hit_distinct(self, key, now_ms, window_ms, value=None, member=None):
        self.log.append(window_ms)
        return super().hit_distinct(key, now_ms, window_ms, value, member)


class PerKeyWindowCounter(DequeWindowCounter):
    """The product fix for F1: the sweep evicts a key against ITS OWN window.
    Used only as the 'the instrument can turn green' control."""

    def __init__(self) -> None:
        super().__init__()
        self._kw: dict = {}

    def hit(self, key, now_ms, window_ms, member=None):
        self._kw[key] = window_ms
        return super().hit(key, now_ms, window_ms, member)

    def hit_distinct(self, key, now_ms, window_ms, value=None, member=None):
        self._kw[key] = window_ms
        return super().hit_distinct(key, now_ms, window_ms, value, member)

    def _sweep(self, now_ms: int, window_ms: int) -> None:
        self._hits += 1
        if self._hits % SWEEP_EVERY:
            return
        stale = [k for k, ts in self._last.items() if ts < now_ms - self._kw.get(k, window_ms)]
        for k in stale:
            self._w.pop(k, None)
            self._dw.pop(k, None)
            self._live_members.pop(k, None)
            self._last.pop(k, None)
            self._kw.pop(k, None)


# ---------------------------------------------------------------------------
# Noise: benign firewall denies on disjoint keys
# ---------------------------------------------------------------------------
def noise_payload(i: int, t_ms: int) -> tuple:
    """One denied connection from its own source to its own destination port.
    Every key is unique, so no noise rule ever approaches its threshold -- this is
    traffic no analyst would escalate."""
    a, b = divmod(i, 250)
    src = f"198.19.{a % 250}.{b + 1}"
    dst = f"10.9.{a % 250}.{b + 1}"
    raw = (f"%ASA-4-106023: Deny tcp src outside:{src}/{30000 + i} "
           f"dst inside:{dst}/{1000 + i} by access-group acl_out")
    meta = {"received_at": t_ms, "ingest_id": f"ing-noise-{i:05d}", "trace_id": "trace-noise",
            "tenant_id": "acme", "ip": src}
    return rp.ProbeSpec(NOISE_STEP), {"source_type": "cisco_asa", "raw": raw, "meta": meta}


def calibrate_noise(rules_dir=None) -> dict:
    """Hits one noise event causes, and the window of each hit. Measured on a
    recording counter against the real detector -- companions count, so a single
    event is routinely two hits."""
    probe = ps.FastProbe(rules_dir=rules_dir, strict_clock=True, counter_factory=RecordingCounter)
    spec, p = noise_payload(0, rp.BASE_MS)
    fired = probe.detect(ps.payloads_to_pairs([(spec, p)]))
    log = list(probe.last_counter.log)
    return {"hits_per_event": len(log), "windows_ms": log, "alerts": len(fired)}


# ---------------------------------------------------------------------------
# Shortest window, applicability
# ---------------------------------------------------------------------------
def shortest_window_ms(rule_sets: dict) -> int:
    return min(r.window_ms for rs in rule_sets.values() for r in rs.rules)


def applicable(rs: ax.RuleSet, w_short_ms: int) -> bool:
    """The sweep can only hurt a rule whose OWN window is longer than the noise's."""
    return all(r.window_ms > w_short_ms for r in rs.rules)


# ---------------------------------------------------------------------------
# The stream
# ---------------------------------------------------------------------------
def plan_split(rs: ax.RuleSet, burst: ax.Burst) -> tuple:
    """(m, j): use the first ``m`` burst events, ``j`` of them before the pause.

    Before the pause fewer than T events (nothing fires early); after it fewer
    than T again (so a forgotten window really means no detection); together at
    least T (so the no-noise control is detected)."""
    t_min = min(r.threshold for r in rs.rules)
    t_max = max(r.threshold for r in rs.rules)
    m = min(burst.n, 2 * t_min - 2 if t_min > 2 else t_min)
    j = t_min - 1
    if m < t_max or m - j > t_min - 1 or j < 1:
        raise ValueError(f"{rs.key}: burst of {burst.n} cannot be split around a pause (T={t_min}..{t_max})")
    return m, j


def build_stream(lab: ax.Lab, w_short_ms: int, n_noise: int, *, idle_ms: int | None = None,
                 prefix_noise: int = 0) -> dict:
    """The full stream: ``j`` burst events, a pause, ``n_noise`` noise events that
    start ``idle_ms`` after the last pre-pause event (default: one millisecond
    past the short window, the cheapest placement that still sweeps the key),
    then the rest of the burst.

    ``prefix_noise`` events are sent BEFORE the burst (they only move the sweep
    phase -- the control that proves N* is computed from the counter's own state
    and not hard-coded)."""
    rs, burst = lab.rs, lab.burst
    m, j = plan_split(rs, burst)
    gap = w_short_ms + _PAUSE_SLACK_MS
    one_s = 1_000
    if rs.periodic:
        # a periodicity rule must stay regular: every interval is the pause length
        offs = [i * gap for i in range(m)]
    else:
        offs = [i * one_s for i in range(j)] + [(j - 1) * one_s + gap + (i - j) * one_s for i in range(j, m)]
    body = ax.apply_offsets(burst.payloads[:m], offs)
    if not ax.times_follow(lab, burst.payloads[:m], offs):
        raise ValueError(f"{rs.key}: event time does not follow the raw time fields")
    t_last_pre = min(ax.event_times(body)) + offs[j - 1]
    start = idle_ms if idle_ms is not None else w_short_ms + 1
    noise = [noise_payload(prefix_noise + k, t_last_pre + start + k) for k in range(n_noise)]
    t_first = min(ax.event_times(body))
    prefix = [noise_payload(10_000 + k, t_first - 1_000_000 + k) for k in range(prefix_noise)]
    stream = prefix + body[:j] + noise + body[j:]
    return {"payloads": stream, "t_last_pre": t_last_pre, "pre_events": len(prefix) + j,
            "m": m, "j": j, "idle_start_ms": start}


def _phase_before_noise(lab: ax.Lab, built: dict) -> int:
    """The counter's hit count after the events that precede the noise -- read
    from the same detector, never assumed."""
    pre = built["payloads"][: built["pre_events"]]
    trace: list = []
    lab.probe.detect(ps.payloads_to_pairs(pre), hit_trace=trace)
    return trace[-1] if trace else 0


def predict_noise_events(phase: int, windows_per_event: list, idle_start_ms: int, w_short_ms: int,
                         cap: int = _NOISE_CAP):
    """Independent model of N*: walk the counter's hit arithmetic. A sweep runs
    on every ``_SWEEP_EVERY``-th hit and evicts a key whose last hit is older than
    THAT hit's window; the target's last hit is ``idle_start_ms + k - 1`` ms before
    the k-th noise event, so the target is swept when the tick's window is shorter
    than that idle time. Returns the smallest k, or None."""
    hits = phase
    for k in range(1, cap + 1):
        idle = idle_start_ms + (k - 1)
        for w in windows_per_event:
            hits += 1
            if hits % SWEEP_EVERY == 0 and idle > w:
                return k
    return None


def _lost(lab: ax.Lab, w_short_ms: int, n: int, **kw) -> bool:
    built = build_stream(lab, w_short_ms, n, **kw)
    return not lab.detected(built["payloads"])


def state_exhaustion(lab: ax.Lab, w_short_ms: int, *, calib: dict | None = None) -> dict:
    """Measured vs predicted cost of making ``lab.rs`` forget the burst by noise."""
    rs = lab.rs
    if not applicable(rs, w_short_ms):
        return {"applicable": False, "reason": "a rule in this set has the shortest window: the sweep never "
                                               "evicts it early", "agree": True}
    calib = calib or calibrate_noise()
    base = build_stream(lab, w_short_ms, 0)
    d0, q0 = lab.both(base["payloads"])
    if not d0:
        return {"applicable": True, "searched": False, "agree": False,
                "reason": "the split reference burst is not detected without noise (the instrument cannot "
                          "separate cause from baseline)"}
    phase = _phase_before_noise(lab, base)
    pred = predict_noise_events(phase, calib["windows_ms"], base["idle_start_ms"], w_short_ms)
    if not _lost(lab, w_short_ms, _NOISE_CAP):
        measured = None
    else:
        measured = ax._first_true(1, _NOISE_CAP, lambda n: _lost(lab, w_short_ms, n))
    mono = True
    if measured is not None:
        mono = (not _lost(lab, w_short_ms, measured - 1)) and all(
            _lost(lab, w_short_ms, measured + d) for d in (1, 7, SWEEP_EVERY // 2))
    not_idle = None
    if measured is not None:
        # the same noise placed while the target key is NOT yet idle past the short window
        not_idle = not _lost(lab, w_short_ms, measured * 3, idle_ms=w_short_ms // 2)
    h = calib["hits_per_event"]
    return {"applicable": True, "searched": True, "baseline_detected": d0, "baseline_predicted": q0,
            "phase_hits_before_noise": phase, "hits_per_noise_event": h,
            "noise_events": "immune" if measured is None else measured,
            "predicted_noise_events": "immune" if pred is None else pred,
            "counter_hits": None if measured is None else measured * h,
            "min_pause_seconds": None if measured is None else round((w_short_ms + measured) / 1000.0, 3),
            "monotone_checked": mono, "not_idle_control_detected": not_idle,
            "agree": (measured == pred) and mono and (not_idle in (None, True)), "backend": "deque"}


def parity_on_noise_stream(lab: ax.Lab, w_short_ms: int, n: int) -> bool:
    """FastProbe == the slow per-probe-Detector path on THIS noise stream. Parity
    on the unperturbed and thinned streams does not cover it: the sweep fires on
    the global hit count."""
    import report  # noqa: PLC0415
    built = build_stream(lab, w_short_ms, n)
    pairs = ps.payloads_to_pairs(built["payloads"])
    return report._real_detection(pairs) == lab.probe.detect(pairs)


# ---------------------------------------------------------------------------
# F5: alert-id economics of floods (informational)
# ---------------------------------------------------------------------------
def _ssh_fail(ip: str, user: str, t: int, i: int) -> tuple:
    raw = f"Jun 10 13:55:{i % 60:02d} db01 sshd[{2000 + i}]: Failed password for {user} from {ip} port {50000 + i} ssh2"
    meta = {"received_at": t, "ingest_id": f"ing-flood-{i:05d}", "trace_id": "trace-flood", "tenant_id": "acme", "ip": ip}
    return rp.ProbeSpec("flood"), {"source_type": "linux_ssh", "raw": raw, "meta": meta}


def alert_ids(probe: ps.FastProbe, pairs: list) -> list:
    """Distinct alert ids (``Rule.alert_key``) the stream would raise, per rule."""
    events = probe.normalized(pairs)
    probe._fresh_counter()
    ids: dict = {}
    for ev in events:
        _e, matched, _a = probe.detector.process(ev)
        for r in matched:
            ids.setdefault(r.id, set()).add(r.alert_key(ev))
    return ids


def alert_flood_cost(probe: ps.FastProbe | None = None) -> dict:
    """Events needed per distinct alert id on common_bruteforce (T=10, W=60 s).

    Cells = groups x window-buckets, each reaching T events. One group inside one
    bucket yields ONE id however many events it gets (a unit property of the
    deterministic alert key, not a property of floods); distinct (group, bucket)
    cells each cost about T events per id."""
    probe = probe or ps.FastProbe(strict_clock=True)
    bf = next(r for r in ax.load_stateful_rules().values() if r.name == "common_bruteforce")
    t, w = bf.threshold, bf.window_ms
    base = rp.BASE_MS - (rp.BASE_MS % w)            # bucket-aligned
    rows = []
    for groups, buckets, per in ((1, 1, t), (1, 1, 10 * t), (4, 1, t), (1, 3, t), (4, 3, t)):
        pl, i = [], 0
        for g in range(groups):
            for b in range(buckets):
                for e in range(per):
                    pl.append(_ssh_fail(f"198.18.50.{g + 1}", "deploy", base + b * w + 1_000 + e * 10, i))
                    i += 1
        pl.sort(key=lambda x: x[1]["meta"]["received_at"])
        ids = alert_ids(probe, ps.payloads_to_pairs(pl)).get(bf.id, set())
        rows.append({"groups": groups, "buckets": buckets, "events_per_cell": per, "events": len(pl),
                     "alert_ids": len(ids), "events_per_alert": (round(len(pl) / len(ids), 2) if ids else None)})
    return {"rule": bf.name, "threshold": t, "window_seconds": bf.window_seconds, "rows": rows,
            "one_group_one_bucket_is_one_id": rows[0]["alert_ids"] == 1 and rows[1]["alert_ids"] == 1,
            "note": "informational: the flood costs ~T events per distinct (group, bucket) alert id"}


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def measure_all(seed: int = 7, rules_dir=None, *, probe: ps.FastProbe | None = None, only: list | None = None) -> dict:
    sets = ax.build_rule_sets(rules_dir)
    w_short = shortest_window_ms(sets)
    probe = probe or ps.FastProbe(rules_dir=rules_dir, strict_clock=True)
    calib = calibrate_noise(rules_dir)
    out: dict = {}
    for key, rs in sets.items():
        if only and key not in only:
            continue
        burst = ax.reference_burst(key, seed)
        if burst is None:
            continue
        out[key] = state_exhaustion(ax.Lab(probe, rs, burst), w_short, calib=calib)
    return {"seed": seed, "basis": "harness-measured", "backend": "deque", "sweep_every": SWEEP_EVERY,
            "shortest_window_seconds": w_short / 1000.0, "noise": calib, "rule_sets": out}


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(prog="noise_dilution")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--rule-set", action="append", default=None)
    args = ap.parse_args(argv)
    res = measure_all(args.seed, only=args.rule_set)
    res["alert_flood_cost"] = alert_flood_cost()
    print(f"== state exhaustion (F1, deque backend; sweep every {SWEEP_EVERY} hits; shortest window "
          f"{res['shortest_window_seconds']:g}s; one noise event = {res['noise']['hits_per_event']} counter hits) ==")
    ok = True
    for key, r in res["rule_sets"].items():
        if not r.get("applicable"):
            print(f"  {key:<34} n/a: {r['reason']}")
            continue
        if not r.get("searched"):
            print(f"  {key:<34} NOT SEARCHED: {r['reason']}")
            ok = False
            continue
        flag = "ok " if r["agree"] else "MISMATCH"
        print(f"  {key:<34} [{flag}] forgets after {r['noise_events']} noise events "
              f"({r['counter_hits']} hits, predicted {r['predicted_noise_events']}), pause >= {r['min_pause_seconds']}s")
        ok = ok and r["agree"]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=2, sort_keys=True)
    print(f"-> {args.out}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
