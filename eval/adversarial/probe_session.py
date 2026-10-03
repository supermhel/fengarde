"""probe_session -- a FAST, parity-proven detection probe for the evasion searches.

WHY THIS EXISTS (2026-10-02)
    ``evasion_search`` asks "does the step's expected rule still fire?" thousands
    of times. Every answer went through ``negative_controls.run_pipeline``, which
    builds a brand-new ``Detector`` per probe (YAML load + rule compile + scoring
    config: ~1.2-2.4 s) to analyse a dozen events that normalise and detect in a
    few milliseconds. A full search took minutes, which is why the search could
    only ever look at four axes.

    ``FastProbe`` builds ONE ``Detector`` and, per probe, only swaps in a fresh
    ``DequeWindowCounter`` (the single piece of state that carries between
    events). Everything else is the production path unchanged: the same WS-2
    ``normalize_one``, the same ``ingest_id`` / ``twin_step`` / tenant stamping as
    ``run_pipeline``, the same ``Detector.process``.

SPEED IS ONLY ALLOWED IF IT IS PROVEN NOT TO CHANGE THE ANSWER
    * ``verify_parity`` replays the unperturbed stream and three perturbed ones
      through BOTH ``report._real_detection`` (the slow oracle) and ``FastProbe``
      and demands byte-identical fired lists. Its negative control is a
      ``FastProbe(reset_counter=False)``, which leaks window state from one probe
      into the next and MUST fail parity; ``state_leak_check`` runs A, B, A and
      demands the two A results are identical.
    * Parity on the stream is not parity on a NOISE stream: the cross-window
      sweep (``DequeWindowCounter._sweep``) fires on the counter's global hit
      count, so the answer depends on the exact stream replayed. The noise axis
      therefore only ever uses FULL-stream replays and re-proves parity on its
      own noise stream (``noise_dilution``), never the step-subset shortcut.

NORMALISATION CACHE, AND WHY IT REFUSES WALL-CLOCK TIME
    Normalising is deterministic only when the record carries its own
    timestamp: most parsers fall back to ``int(time.time() * 1000)`` when the
    time is absent or unparseable. Such an event's OCSF ``time`` would differ run
    to run (and a cached copy would go stale), so each new (source_type, raw,
    meta) is normalised under two different faked ``time.time`` values; if the
    result differs the event is wall-clock-derived. It is never cached and, with
    ``strict_clock=True`` (the default for every new instrument), ``FastProbe``
    REFUSES the stream (``WallClockDerivedTime``) instead of returning a verdict
    that is a function of the day it ran.

``FENGARDE_SLOW_PROBE=1`` is the escape hatch: ``fast_probe_enabled()`` returns
False and ``evasion_search`` keeps using ``report._real_detection``.

STDLIB ONLY (plus the repo's own modules). Deterministic.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ADVERSARIAL = Path(__file__).resolve().parent
TWIN = ROOT / "eval" / "twin"
SERVICES = ROOT / "services"
for _p in (str(ADVERSARIAL), str(TWIN), str(SERVICES)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import negative_controls  # noqa: E402
from shared.window import DequeWindowCounter  # noqa: E402

#: Must equal ``report._CHAIN_TENANT`` (asserted by ``verify_parity``): the
#: tenant is part of every stateful window key.
CHAIN_TENANT = "twin-chain"

# Two clearly different fake wall-clock values (seconds). Both are far from any
# fixed-calendar fixture time, so a parser that falls back to "now" cannot
# produce the same event under both.
_CLOCK_A = 1_700_000_000.0
_CLOCK_B = 1_900_000_000.0


class WallClockDerivedTime(RuntimeError):
    """An event's normalised form depends on ``time.time()`` (the record had no
    usable timestamp), so any verdict on it would depend on the day it ran."""


def fast_probe_enabled() -> bool:
    """False when ``FENGARDE_SLOW_PROBE=1`` -- keep the per-probe fresh Detector."""
    return os.environ.get("FENGARDE_SLOW_PROBE", "") not in ("1", "true", "yes")


def _digest(source_type, raw, meta) -> str:
    blob = json.dumps([source_type, raw, meta], sort_keys=True, default=repr, ensure_ascii=True)
    return hashlib.sha256(blob.encode("utf-8", "surrogatepass")).hexdigest()


class _FakeClock:
    """Context manager: ``time.time`` returns a fixed value (restored on exit)."""

    def __init__(self, value: float) -> None:
        self.value = value
        self._orig = None

    def __enter__(self):
        self._orig = time.time
        time.time = lambda: self.value  # type: ignore[assignment]
        return self

    def __exit__(self, *exc):
        time.time = self._orig  # type: ignore[assignment]
        return False


#: Fresh-uuid fields a parser generates when the record carries none. They differ
#: on every call by design and are irrelevant to detection (``FastProbe`` stamps
#: its own deterministic ``ingest_id``; nothing reads ``trace_id``), so they must
#: not be mistaken for wall-clock dependence.
_RANDOM_ID_FIELDS = ("ingest_id", "trace_id")


def _canon_event(ev) -> str:
    if isinstance(ev, dict) and isinstance(ev.get("siem"), dict):
        ev = {**ev, "siem": {k: v for k, v in ev["siem"].items() if k not in _RANDOM_ID_FIELDS}}
    return json.dumps(ev, sort_keys=True, default=repr)


class FastProbe:
    """One Detector, a fresh window counter per probe.

    ``rules_dir``: run against a (mutated) COPY of ``contracts/rules`` in a temp
    directory -- how the controls prove the searches can fail -- without ever
    touching the repo's rule files.
    ``reset_counter=False`` exists ONLY as the parity negative control.
    """

    def __init__(self, rules_dir=None, tenant: str = CHAIN_TENANT, *,
                 strict_clock: bool = True, reset_counter: bool = True,
                 counter_factory=None) -> None:
        self.tenant = tenant
        self.rules_dir = rules_dir
        self.counter_factory = counter_factory or DequeWindowCounter
        self.strict_clock = strict_clock
        self.reset_counter = reset_counter
        self._ws2 = negative_controls._get_ws2()
        self.detector = negative_controls.Detector(
            rules_dir=Path(rules_dir) if rules_dir is not None else None, plugin_rule_dirs=[])
        self._cache: dict = {}
        self.last_counter: DequeWindowCounter | None = None
        self.stats = {"probes": 0, "events": 0, "normalize_calls": 0, "cache_hits": 0,
                      "wall_clock_events": 0, "dead_lettered": 0}

    # ---- rules ---------------------------------------------------------
    @property
    def rules(self) -> list:
        return self.detector.rules

    @property
    def stateful_rules(self) -> list:
        return [r for r in self.detector.rules if r.stateful]

    # ---- normalisation (cached, clock-honest) --------------------------
    def _normalize(self, source_type, raw, meta):
        """(event | None, errors, wall_clock_derived). The returned event is a
        private deep copy: ``Detector.process`` mutates it (score, siem)."""
        key = _digest(source_type, raw, meta)
        hit = self._cache.get(key)
        if hit is not None:
            self.stats["cache_hits"] += 1
            ev, errs = hit
            return copy.deepcopy(ev), errs, False
        envelope = {"source_type": source_type, "raw": copy.deepcopy(raw), "meta": copy.deepcopy(meta)}
        with _FakeClock(_CLOCK_A):
            ev_a, err_a = self._ws2.normalize_one(envelope)
        envelope_b = {"source_type": source_type, "raw": copy.deepcopy(raw), "meta": copy.deepcopy(meta)}
        with _FakeClock(_CLOCK_B):
            ev_b, err_b = self._ws2.normalize_one(envelope_b)
        self.stats["normalize_calls"] += 2
        if _canon_event(ev_a) != _canon_event(ev_b) or err_a != err_b:
            # time-dependent: never cached; re-run on the real clock so the
            # (non-strict) answer is exactly what run_pipeline would return.
            self.stats["wall_clock_events"] += 1
            envelope_c = {"source_type": source_type, "raw": copy.deepcopy(raw), "meta": copy.deepcopy(meta)}
            ev, errs = self._ws2.normalize_one(envelope_c)
            return ev, errs, True
        self._cache[key] = (ev_a, err_a)
        return copy.deepcopy(ev_a), err_a, False

    def normalized(self, pairs: list) -> list:
        """The OCSF events (post-stamping, pre-detection) for ``pairs`` -- the
        stream the detector will see. Dead-lettered events are omitted exactly
        as ``run_pipeline`` omits them."""
        events: list = []
        for entry in pairs:
            source_type, rec = entry[0], entry[1]
            meta = entry[2] if len(entry) > 2 and isinstance(entry[2], dict) else {}
            step = entry[3] if len(entry) > 3 else None
            event, errors, wall = self._normalize(source_type, rec, meta)
            if wall and self.strict_clock:
                raise WallClockDerivedTime(
                    f"{source_type} record normalises to a wall-clock time (no usable timestamp): "
                    "refusing to return a verdict that depends on the day it ran")
            if event is None or errors:
                self.stats["dead_lettered"] += 1
                continue
            (event.setdefault("siem", {})).update(
                {"tenant": self.tenant, "ingest_id": f"neg:{self.tenant}:{len(events)}"})
            if step is not None:
                event.setdefault("siem", {})["twin_step"] = step
            events.append(event)
        return events

    # ---- detection -----------------------------------------------------
    def _fresh_counter(self) -> DequeWindowCounter:
        if self.last_counter is None or self.reset_counter:
            counter = self.counter_factory()
            self.detector._window_counter = counter
            for r in self.detector.rules:
                if r.stateful:
                    r.set_counter(counter)
            self.last_counter = counter
        return self.last_counter

    def detect(self, pairs: list, *, hit_trace: list | None = None) -> list:
        """Drop-in for ``negative_controls.run_pipeline(pairs, tenant)``: the
        same list of fired-rule dicts, in the same order.

        ``hit_trace`` (optional, appended to in place): the counter's global hit
        count AFTER each surviving event -- the clock the cross-window sweep
        runs on. Dead-lettered events do not appear."""
        events = self.normalized(pairs)
        self._fresh_counter()
        self.stats["probes"] += 1
        alerts: list = []
        for event in events:
            self.stats["events"] += 1
            _ev, matched, _action = self.detector.process(event)
            if hit_trace is not None:
                hit_trace.append(self.counter_hits)
            for rule in matched:
                alerts.append({"rule_id": rule.id, "rule_title": rule.title,
                               "score_weight": rule.score_weight, "level": rule.level,
                               "source_type": (event.get("siem") or {}).get("source_type"),
                               "step": (event.get("siem") or {}).get("twin_step"),
                               "time": event.get("time")})
        return alerts

    def detect_payloads(self, payloads: list) -> list:
        """``payloads`` is the scenario shape ``[(ChainStepSpec, {source_type, raw, meta})]``."""
        return self.detect(payloads_to_pairs(payloads))

    @property
    def counter_hits(self) -> int:
        """Global hit count of the LAST probe's counter -- the clock the
        cross-window sweep runs on (every ``_SWEEP_EVERY`` hits)."""
        return self.last_counter._hits if self.last_counter is not None else 0


def payloads_to_pairs(payloads: list) -> list:
    return [(p["source_type"], p["raw"], p.get("meta"), spec.label) for spec, p in payloads]


# ---------------------------------------------------------------------------
# Shared default session (one Detector per process, lazily built)
# ---------------------------------------------------------------------------
_DEFAULT: FastProbe | None = None


def default_probe() -> FastProbe:
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = FastProbe(strict_clock=False)   # evasion_search parity: same answers as run_pipeline
    return _DEFAULT


# ---------------------------------------------------------------------------
# Parity proof
# ---------------------------------------------------------------------------
#: The perturbed streams parity is proven on, besides the baseline: one per
#: perturbation family the existing four axes use (loss, distribution, pacing), plus (2026-10-03)
#: ``jitter_100pct``, which re-orders event TIMES within a burst: the periodic (beacon) rule reads
#: the order of arrivals, so a probe that only matched on evenly spaced streams could still diverge.
PARITY_VARIANTS = (("volume", "thin_25pct"), ("distribution", "ip_rotate_2"), ("pacing", "stretch_6x"),
                   ("pacing", "jitter_100pct"))


def _slow(pairs: list) -> list:
    import report  # noqa: PLC0415
    return report._real_detection(pairs)


def verify_parity(sdef, seed: int = 7, probe: FastProbe | None = None, *, variants=PARITY_VARIANTS) -> list:
    """Streams on which ``probe`` and the slow path disagree (empty == parity).

    Each item: ``{"stream": name, "slow": n_fired, "fast": n_fired}``. The slow
    path is ``report._real_detection`` -- the function ``evasion_search`` used."""
    import mutate_generic as mg  # noqa: PLC0415
    import report  # noqa: PLC0415
    assert report._CHAIN_TENANT == CHAIN_TENANT, "FastProbe tenant drifted from the slow path"
    probe = probe or FastProbe(strict_clock=False)
    base = sdef.build(seed)[0]
    streams = [("baseline", base)]
    for axis, variant in variants:
        mutated, changed = mg.apply(base, axis, variant, seed=seed, sdef=sdef)
        if changed:
            streams.append((f"{axis}/{variant}", mutated))
    bad = []
    for name, payloads in streams:
        pairs = payloads_to_pairs(payloads)
        slow, fast = _slow(pairs), probe.detect(pairs)
        if slow != fast:
            bad.append({"stream": name, "slow": len(slow), "fast": len(fast)})
    return bad


def verify_parity_pairs(pairs: list, probe: FastProbe | None = None) -> bool:
    """Parity on an arbitrary raw stream (the noise axis uses this)."""
    probe = probe or FastProbe(strict_clock=False)
    return _slow(pairs) == probe.detect(pairs)


def state_leak_check(sdef, seed: int = 7, probe: FastProbe | None = None) -> bool:
    """Run stream A, then B, then A again on ONE session: both A answers must be
    identical. False == window state leaks between probes."""
    import mutate_generic as mg  # noqa: PLC0415
    probe = probe or FastProbe(strict_clock=False)
    a = sdef.build(seed)[0]
    b, _ = mg.apply(a, "volume", "thin_25pct", seed=seed, sdef=sdef)
    first = probe.detect(payloads_to_pairs(a))
    probe.detect(payloads_to_pairs(b))
    again = probe.detect(payloads_to_pairs(a))
    return first == again


def main(argv: list | None = None) -> int:
    import argparse  # noqa: PLC0415
    import scenario_registry as reg  # noqa: PLC0415
    ap = argparse.ArgumentParser(prog="probe_session")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args(argv)
    rc = 0
    for sdef in reg.ALL:
        t0 = time.perf_counter()
        bad = verify_parity(sdef, args.seed)
        leak_ok = state_leak_check(sdef, args.seed)
        dt = time.perf_counter() - t0
        ok = not bad and leak_ok
        print(f"[{'OK' if ok else 'FAIL'}] {sdef.name}: parity on baseline+{len(PARITY_VARIANTS)} perturbed streams, "
              f"state-leak A/B/A {'clean' if leak_ok else 'LEAKS'} ({dt:.1f}s) {bad if bad else ''}")
        rc |= 0 if ok else 1
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
