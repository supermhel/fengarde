"""noise_dilution -- can benign-looking noise make a stateful rule forget an attack?

WHY THIS EXISTS (2026-10-02)
    The previous harness injected *decoys* (events that trip the same rules from
    other entities) and asked whether the incident stayed clean. It never asked
    the adversary's question: "what can I send, that no analyst would call an
    attack, that makes the detector lose track of the thing I am doing?"

    Probing found one answer end to end (finding F1). ``DequeWindowCounter._sweep``
    evicted every idle key using the TRIGGERING hit's window, not the key's own:
    noise on a 60 s rule (one hit in 256) swept away the live 300 s / 600 s / 3600 s
    state of every other rule, at a price of ~124 noise events and a >60 s pause on
    lateral_movement. The Redis backend uses a per-key ``EXPIRE`` so the two
    backends disagreed.

    F1 IS FIXED (2026-10-03): every key is now evicted by its own deadline
    (``services/shared/window.py``), the finding is deleted from
    ``evasion_findings.yaml``, and this module now asserts the FIXED behaviour: the
    shipped counter is immune (up to the noise cap). The old behaviour survives only
    as ``LegacyGlobalSweepCounter``, a negative control that must still go red.

WHAT IS MEASURED (shipped counter: immune; legacy counter: the historical cost)
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
    event causes (``sweep="global"``), or predicts "immune" from the target's own
    window (``sweep="per_key"``) -- an independent model; measured != predicted is
    a finding.

CONTROLS (each can fail)
    shipped counter -> detected under any noise, and the memory bound still holds (an
    idle key past its own window is reclaimed); legacy counter (the old global sweep
    re-introduced) -> forgets after N* events, so the instrument can still go red;
    no noise -> detected; noise on a key that is NOT idle long enough -> detected (the
    negative that shows the cause is the sweep, not the noise); N*-1 events -> detected;
    slow-path parity on the noise stream itself (parity on other streams does not
    cover this one).

BACKEND: DequeWindowCounter only. The Redis counter expires keys itself and has no
sweep (per-key EXPIRE), so it never had the defect.

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
import json
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
class LegacyGlobalSweepCounter(DequeWindowCounter):
    """The F1 defect, re-introduced on purpose: the idle sweep judges EVERY key against
    the window of the hit that triggered it (the shipped counter, fixed 2026-10-03,
    judges each key by its own deadline). Used only as the NEGATIVE control that proves
    the instruments can still go red when the old behaviour comes back."""

    def __init__(self) -> None:
        super().__init__()
        self._trigger_window = 0

    def hit(self, key, now_ms, window_ms, member=None):
        self._trigger_window = window_ms
        return super().hit(key, now_ms, window_ms, member)

    def hit_distinct(self, key, now_ms, window_ms, value=None, member=None):
        self._trigger_window = window_ms
        return super().hit_distinct(key, now_ms, window_ms, value, member)

    def _sweep(self, now_ms: int) -> None:
        self._hits += 1
        if self._hits % SWEEP_EVERY:
            return
        horizon = now_ms - self._trigger_window
        for k in [k for k, ts in self._last.items() if ts < horizon]:
            self._forget(k)


class _Recording:
    """Mixin: logs the window and key of every hit, in hit order (calibration of one
    noise event)."""

    def __init__(self) -> None:
        super().__init__()
        self.log: list = []
        self.keys: list = []

    def hit(self, key, now_ms, window_ms, member=None):
        self.log.append(window_ms)
        self.keys.append(key)
        return super().hit(key, now_ms, window_ms, member)

    def hit_distinct(self, key, now_ms, window_ms, value=None, member=None):
        self.log.append(window_ms)
        self.keys.append(key)
        return super().hit_distinct(key, now_ms, window_ms, value, member)


class RecordingCounter(_Recording, DequeWindowCounter):
    """Recording wrapper around the shipped counter."""


class RecordingLegacyCounter(_Recording, LegacyGlobalSweepCounter):
    """Recording wrapper around the re-introduced defect."""


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
            "m": m, "j": j, "idle_start_ms": start,
            "post_idle_ms": min(ax.event_times(body[j:])) - t_last_pre}


def _phase_before_noise(lab: ax.Lab, built: dict) -> int:
    """The counter's hit count after the events that precede the noise -- read
    from the same detector, never assumed."""
    pre = built["payloads"][: built["pre_events"]]
    trace: list = []
    lab.probe.detect(ps.payloads_to_pairs(pre), hit_trace=trace)
    return trace[-1] if trace else 0


def post_event_hits(lab: ax.Lab, built: dict, counter_cls=RecordingCounter) -> list:
    """The window of each counter hit the FIRST post-pause burst event causes,
    in order, flagged ``True`` once the event has reached a hit on one of the
    target set's own rules (from there on the target key is refreshed by the
    event itself, so a later tick cannot evict it). Read from a recording
    counter on the same detector, never assumed.

    Why it matters: the sweep tick can land INSIDE that event, on a hit of a
    short-window rule that runs before the target rule's own hit (password
    spray: 4 hits per event) -- one noise event earlier than the noise train
    alone predicts."""
    probe = ps.FastProbe(rules_dir=lab.probe.rules_dir, strict_clock=True, counter_factory=counter_cls)
    trace: list = []
    probe.detect(ps.payloads_to_pairs(built["payloads"]), hit_trace=trace)
    idx = built["pre_events"]                       # first event after the pause
    lo = trace[idx - 1] if idx >= 1 else 0
    hi = trace[idx] if idx < len(trace) else lo
    c = probe.last_counter
    out, reached = [], False
    for w, k in zip(c.log[lo:hi], c.keys[lo:hi]):
        reached = reached or k.split(":", 1)[0] in lab.rs.ids
        out.append((w, reached))
    return out


def predict_noise_events(phase: int, windows_per_event: list, idle_start_ms: int, w_short_ms: int,
                         cap: int = _NOISE_CAP, post_hits: list | None = None, post_idle_ms: int = 0,
                         *, sweep: str = "per_key", target_window_ms: int | None = None):
    """Independent model of N*: walk the counter's hit arithmetic. A sweep runs
    on every ``_SWEEP_EVERY``-th hit; the target's last hit is ``idle_start_ms + k - 1``
    ms before the k-th noise event. Two sweep models:

    ``per_key`` (the shipped counter): a key is evicted only when it is idle longer
    than ITS OWN window, so the target (``target_window_ms``, the shortest window of
    the set's own rules) survives whenever the pause is shorter than that. The noise
    cannot choose the window the sweep judges by -> the answer is None (immune) for
    every ``cap``, unless the idle time itself outgrows the target's window.

    ``global`` (the F1 defect, ``LegacyGlobalSweepCounter``): a key is evicted when it
    is idle longer than the window of the hit that TRIGGERED the sweep, so the target
    is swept when that tick's window is shorter than the idle time. After the k-th
    noise event the first post-pause burst event is walked the same way
    (``post_hits`` / ``post_idle_ms``): a tick on a hit BEFORE the event reaches the
    target's own rule also evicts it.

    Returns the smallest k, or None."""
    hits = phase
    for k in range(1, cap + 1):
        idle = idle_start_ms + (k - 1)
        for w in windows_per_event:
            hits += 1
            limit = w if sweep == "global" else target_window_ms
            if hits % SWEEP_EVERY == 0 and limit is not None and idle > limit:
                return k
        h2 = hits
        for w, reached in post_hits or ():
            if reached:
                break
            h2 += 1
            limit = w if sweep == "global" else target_window_ms
            if h2 % SWEEP_EVERY == 0 and limit is not None and post_idle_ms > limit:
                return k
    return None


def _lost(lab: ax.Lab, w_short_ms: int, n: int, **kw) -> bool:
    built = build_stream(lab, w_short_ms, n, **kw)
    return not lab.detected(built["payloads"])


def state_exhaustion(lab: ax.Lab, w_short_ms: int, *, calib: dict | None = None, sweep: str = "per_key") -> dict:
    """Measured vs predicted cost of making ``lab.rs`` forget the burst by noise.

    ``sweep`` names the sweep model the PREDICTION assumes and must match the counter
    ``lab.probe`` was built with: ``per_key`` (shipped; expected result: immune, the
    noise cannot make the set forget) or ``global`` (``LegacyGlobalSweepCounter``, the
    F1 defect; expected result: an integer N*)."""
    rs = lab.rs
    target_w = min(r.window_ms for r in rs.rules)
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
    rec_cls = RecordingLegacyCounter if sweep == "global" else RecordingCounter
    pred = predict_noise_events(phase, calib["windows_ms"], base["idle_start_ms"], w_short_ms,
                                post_hits=post_event_hits(lab, base, rec_cls), post_idle_ms=base["post_idle_ms"],
                                sweep=sweep, target_window_ms=target_w)
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
            "agree": (measured == pred) and mono and (not_idle in (None, True)), "backend": "deque", "sweep": sweep}


def parity_on_noise_stream(lab: ax.Lab, w_short_ms: int, n: int) -> bool:
    """FastProbe == the slow per-probe-Detector path on THIS noise stream. Parity
    on the unperturbed and thinned streams does not cover it: the sweep fires on
    the global hit count."""
    import report  # noqa: PLC0415
    built = build_stream(lab, w_short_ms, n)
    pairs = ps.payloads_to_pairs(built["payloads"])
    return report._real_detection(pairs) == lab.probe.detect(pairs)


# ---------------------------------------------------------------------------
# The F1 primitive (counter level) -- the cheap, exact reproduction
# ---------------------------------------------------------------------------
def f1_primitive(counter_cls=DequeWindowCounter, *, noise_window_ms: int = 60_000,
                 long_window_ms: int = 300_000, noise_delay_ms: int = 100_000) -> dict:
    """The counter-level repro of F1 (no detector, no parser): record a distinct
    value under a 300 s key, send ``_SWEEP_EVERY - 1`` hits on OTHER keys with a
    60 s window 100 s later (the last of them lands on the sweep tick), then
    record a second value and read the distinct count. 2 is correct; 1 means the
    live state of the long-window key was swept by the short-window tick.

    The phase is computed from the counter's own ``_hits`` (never hard-coded 255):
    the target hit is hit number 1, so the tick is ``SWEEP_EVERY - 1`` hits later."""
    c = counter_cls()
    t0 = 1_000_000
    long_w = long_window_ms
    c.hit_distinct("long", t0, long_w, "h1")
    need = SWEEP_EVERY - c._hits           # hits until (and including) the tick
    for i in range(need):
        c.hit(f"noise-{i}", t0 + noise_delay_ms, noise_window_ms)
    count = c.hit_distinct("long", t0 + noise_delay_ms, long_w, "h2")
    return {"distinct_after": count, "state_lost": count < 2, "noise_hits": need,
            "long_window_ms": long_w, "noise_window_ms": noise_window_ms}


def f1_reproduces() -> bool:
    """True if the SHIPPED counter has the cross-window sweep defect. It was fixed
    2026-10-03 (F1 deleted from evasion_findings.yaml), so this must be False; the
    function stays as the regression probe, and as the thing the negative control
    (``LegacyGlobalSweepCounter``) is compared with."""
    return bool(f1_primitive()["state_lost"])


def noise_predict(lab: ax.Lab, w_short_ms: int, calib: dict, *, prefix_noise: int = 0,
                  sweep: str = "global") -> tuple:
    """(built, phase, predicted N*) for a stream with ``prefix_noise`` events
    BEFORE the burst -- the control that proves N* is computed from the counter's
    own state, not a constant. Defaults to the ``global`` (defect) model because that
    is the only one whose N* depends on the phase."""
    built = build_stream(lab, w_short_ms, 0, prefix_noise=prefix_noise)
    phase = _phase_before_noise(lab, built)
    rec_cls = RecordingLegacyCounter if sweep == "global" else RecordingCounter
    pred = predict_noise_events(phase, calib["windows_ms"], built["idle_start_ms"], w_short_ms,
                                post_hits=post_event_hits(lab, built, rec_cls), post_idle_ms=built["post_idle_ms"],
                                sweep=sweep, target_window_ms=min(r.window_ms for r in lab.rs.rules))
    return built, phase, pred


def run_controls(sets: dict | None = None, *, probe: ps.FastProbe | None = None, key: str = "common_lateral_movement",
                 seed: int = 7) -> list:
    """Every control of the state-exhaustion instrument, as ``(name, ok, detail)``.

    F1 is FIXED (2026-10-03: the sweep judges each key by its own window). The shipped
    counter is therefore asserted to be immune; the old behaviour lives on only as
    ``LegacyGlobalSweepCounter``, the negative control that must still go red, so a
    regression of the product (or a blind instrument) cannot pass silently.
    Each control can fail: the legacy counter reproduces the defect, each negative
    removes one ingredient (the idle time, the window mismatch, the defective sweep)
    and must make the loss disappear."""
    out: list = []

    def add(name, ok, detail=""):
        out.append((name, bool(ok), detail))
    prim = f1_primitive()
    add("N1 F1 fixed: the shipped counter keeps the 300 s state under 60 s noise", not prim["state_lost"], str(prim))
    legacy = f1_primitive(LegacyGlobalSweepCounter)
    add("N1b negative control: re-introducing the global sweep (LegacyGlobalSweepCounter) loses the state again "
        "-- the instrument can still go red", legacy["state_lost"], str(legacy))
    same = f1_primitive(LegacyGlobalSweepCounter, noise_delay_ms=30_000)
    add("N2 negative: even the legacy sweep leaves the state intact while the key is idle for less than the noise window",
        not same["state_lost"], str(same))
    # no-noise control: nothing between the two hits -> 2
    c = DequeWindowCounter()
    c.hit_distinct("long", 1_000_000, 300_000, "h1")
    add("N3 negative: with no noise the second value counts 2", c.hit_distinct("long", 1_100_000, 300_000, "h2") == 2)
    short = DequeWindowCounter()
    short.hit("short", 1_000_000, 60_000, "a")
    for i in range(SWEEP_EVERY):
        short.hit(f"n{i}", 1_100_000, 60_000, f"m{i}")
    add("N4 the fix keeps the memory bound: an idle key past ITS OWN window is still reclaimed",
        "short" not in short._w and "short" not in short._last, "the sweep must not become a no-op")
    sets = sets or ax.build_rule_sets()
    probe = probe or ps.FastProbe(strict_clock=True)
    w = shortest_window_ms(sets)
    burst = ax.reference_burst(key, seed)
    lab = ax.Lab(probe, sets[key], burst)
    calib = calibrate_noise()
    res = state_exhaustion(lab, w, calib=calib)
    add(f"N5 end to end ({key}), shipped counter: no amount of noise (up to the cap) makes the set forget; "
        "measured == predicted (both immune)",
        res.get("searched") and res["agree"] and res["noise_events"] == "immune" and res["predicted_noise_events"] == "immune",
        str(res))
    base = build_stream(lab, w, 0)
    add("N6 negative: with no noise the split burst is detected", lab.detected(base["payloads"]))
    # ---- the negative control: the same stream through the re-introduced defect --------------
    legacy_probe = ps.FastProbe(strict_clock=True, counter_factory=LegacyGlobalSweepCounter)
    legacy_lab = ax.Lab(legacy_probe, sets[key], burst)
    lres = state_exhaustion(legacy_lab, w, calib=calib, sweep="global")
    n = lres.get("noise_events")
    add(f"N5b negative control ({key}), LegacyGlobalSweepCounter: the old defect makes the set forget after N* noise "
        "events; measured == predicted",
        lres.get("searched") and lres["agree"] and isinstance(n, int), str(lres))
    n = n if isinstance(n, int) else _NOISE_CAP
    add("N7 negative: against the legacy counter N*-1 noise events keep it detected (the loss starts exactly at the prediction)",
        not _lost(legacy_lab, w, n - 1) and _lost(legacy_lab, w, n), f"N*={n}")
    add("N8 negative: the same noise while the key is NOT idle past the short window is detected even by the legacy "
        "counter (cause = sweep)", lres.get("not_idle_control_detected") is True)
    add("N9 the shipped counter is green on exactly the stream that blinds the legacy one (N* noise events and the cap)",
        not _lost(lab, w, n) and not _lost(lab, w, _NOISE_CAP))
    # the legacy prediction tracks the counter's phase
    shifts = []
    for pre in (17, 100):
        built, phase, pred = noise_predict(legacy_lab, w, calib, prefix_noise=pre, sweep="global")
        meas = ax._first_true(1, _NOISE_CAP, lambda k, pre=pre: _lost(legacy_lab, w, k, prefix_noise=pre))
        shifts.append((pre, phase, pred, meas))
    add("N10 moving the sweep phase (events before the burst) moves the legacy N* exactly as predicted",
        all(pred == meas for _p, _ph, pred, meas in shifts) and len({x[3] for x in shifts} | {n}) > 1, str(shifts))
    # the shipped counter ignores the phase entirely
    add("N10b ... and the same phase shifts do nothing to the shipped counter",
        all(not _lost(lab, w, n, prefix_noise=pre) for pre in (17, 100)))
    # parity on THIS noise stream
    add("N11 FastProbe == the slow per-probe Detector on the noise stream itself", parity_on_noise_stream(lab, w, n))
    leaky = ps.FastProbe(strict_clock=True, reset_counter=False)
    pairs = ps.payloads_to_pairs(build_stream(lab, w, n)["payloads"])
    first, second = leaky.detect(pairs), leaky.detect(pairs)
    add("N12 negative: a probe that leaks window state between calls FAILS parity on the noise stream",
        first != second)
    # F5 alert-id economics
    fl = alert_flood_cost(probe)
    rows = {(r["groups"], r["buckets"], r["events_per_cell"]): r for r in fl["rows"]}
    add("N13 F5 unit control: one group in one bucket is ONE alert id however many events it gets",
        fl["one_group_one_bucket_is_one_id"])
    add("N14 F5: distinct (group, bucket) cells each cost ~T events per alert id (floods DO create alert floods)",
        all(r["alert_ids"] == r["groups"] * r["buckets"] for r in fl["rows"]) and
        all(r["events_per_alert"] is not None and r["events_per_alert"] <= fl["threshold"] * 10 for r in rows.values()),
        str([(r["groups"], r["buckets"], r["alert_ids"], r["events_per_alert"]) for r in fl["rows"]]))
    return out


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
def measure_all(seed: int = 7, rules_dir=None, *, probe: ps.FastProbe | None = None, only: list | None = None,
                legacy: bool = False) -> dict:
    """``legacy=True`` measures the historical F1 cost on ``LegacyGlobalSweepCounter``
    (informational: what the attacker used to pay); the default measures the product."""
    sets = ax.build_rule_sets(rules_dir)
    w_short = shortest_window_ms(sets)
    sweep = "global" if legacy else "per_key"
    if legacy:
        probe = ps.FastProbe(rules_dir=rules_dir, strict_clock=True, counter_factory=LegacyGlobalSweepCounter)
    probe = probe or ps.FastProbe(rules_dir=rules_dir, strict_clock=True)
    calib = calibrate_noise(rules_dir)
    out: dict = {}
    for key, rs in sets.items():
        if only and key not in only:
            continue
        burst = ax.reference_burst(key, seed)
        if burst is None:
            continue
        out[key] = state_exhaustion(ax.Lab(probe, rs, burst), w_short, calib=calib, sweep=sweep)
    return {"seed": seed, "basis": "harness-measured", "backend": "deque", "sweep_every": SWEEP_EVERY, "sweep": sweep,
            "shortest_window_seconds": w_short / 1000.0, "noise": calib, "rule_sets": out}


#: The two rule-sets the blocking lane measures (one with a companion, one without
#: companion but with 4 hits per event); ``--full`` measures every rule-set.
BLOCKING_SETS = ["common_lateral_movement", "common_password_spray"]


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(prog="noise_dilution")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--rule-set", action="append", default=None)
    ap.add_argument("--blocking-subset", action="store_true",
                    help="the CI lane: every control plus two rule-sets (the full table is --full / default)")
    ap.add_argument("--legacy-global-sweep", action="store_true",
                    help="informational: measure the historical F1 cost on the re-introduced defect")
    args = ap.parse_args(argv)
    if args.blocking_subset:
        failed = 0
        for name, ok, detail in run_controls(seed=args.seed):
            print(f"[{'OK' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
            failed += 0 if ok else 1
        args.rule_set = args.rule_set or BLOCKING_SETS
    res = measure_all(args.seed, only=args.rule_set, legacy=args.legacy_global_sweep)
    res["alert_flood_cost"] = alert_flood_cost()
    print(f"== state exhaustion (F1 {'LEGACY global sweep, historical cost' if args.legacy_global_sweep else 'fixed'}, "
          f"deque backend; sweep every {SWEEP_EVERY} hits; shortest window "
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
        if r["noise_events"] == "immune":
            print(f"  {key:<34} [{flag}] immune: {_NOISE_CAP} noise events do not make it forget "
                  f"(predicted {r['predicted_noise_events']}, sweep={r['sweep']})")
        else:
            print(f"  {key:<34} [{flag}] forgets after {r['noise_events']} noise events "
                  f"({r['counter_hits']} hits, predicted {r['predicted_noise_events']}), pause >= {r['min_pause_seconds']}s "
                  f"(sweep={r['sweep']})")
        ok = ok and r["agree"]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=2, sort_keys=True)
    print(f"-> {args.out}")
    if args.blocking_subset and failed:
        print(f"[FAIL] {failed} noise-dilution control(s) failed")
        return 1
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
