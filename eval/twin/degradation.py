"""degradation -- a standalone telemetry-degradation rig for FENGARDE eval (WP-1-E).

DELAY / DUPLICATE / REORDER / LOSS injection, applied to a SEQUENCE OF EVENTS
(a plain list) as pure, seeded functions. One implementation, two consumers:

  * the eval twin/scenario (WP-1-B) uses these to exercise the pipeline with
    defective telemetry before scoring detection;
  * the Phase-4 degradation harness reuses the SAME functions -- not a copy.

This is a SIMULATION / TELEMETRY-INJECTION RIG, NOT A CONTROL PATH. Nothing here
reads a register, writes a coil, or influences any real (or simulated) PLC
action. It only transforms a list of event objects into a degraded list. It is
the telemetry-side fault injector; whether *detection* degrades gracefully is
measured downstream (oracle / report), never decided here.

ACCEPTANCE-RELEVANT INSIGHT
    With LOSS injected, detection should DEGRADE (fewer events -> lower recall)
    WITHOUT producing a FALSE INCIDENT -- a fabricated alarm spun out of missing
    data is the dangerous failure mode. Accordingly this injector ONLY removes
    events: the degraded event set is always a SUBSET, never a superset, of the
    original set (no new event is ever fabricated by loss alone). Whether the
    downstream detector degrades gracefully or invents an incident is a separate
    question measured by the oracle/report, not by this module.

DETERMINISM (honest, stated AND proven)
    Every injector builds its OWN `random.Random(seed)` and uses no wall-clock
    time. The same seed + the same input list => byte-identical output, and
    because each call's RNG is freshly constructed from the seed, repeated calls
    are independent and reproducible (no hidden shared/global RNG state). Call
    `selfcheck()` or run with `--selfcheck` to see this proven on real output.

STDLIB ONLY. No OS, no sockets, no timestamps, no I/O in the injectors.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
from random import Random
from typing import Any, Callable, Sequence

# Timestamp-ish keys DELAY will shift when an event carries one.
_TIME_KEYS = ("ts", "time", "timestamp")


# ---------------------------------------------------------------------------
# Identity & copy helpers (the injectors never mutate the caller's events).
# ---------------------------------------------------------------------------
def event_id(event: Any) -> Any:
    """Stable identity of one event for set/comparison purposes.

    A dict event yields its ``id`` field when present; any other event yields
    itself. This is what loss-subset checks and the CLI print against.
    """
    if isinstance(event, dict) and "id" in event:
        return event["id"]
    return event


def ids(events: Sequence[Any]) -> list[Any]:
    """Map a sequence of events to its id sequence."""
    return [event_id(e) for e in events]


def _copy_event(event: Any) -> Any:
    """Return a fresh object so injectors are pure (never mutate the input)."""
    return copy.copy(event)


def _annotate(event: Any, degradation: tuple[str, Any]) -> Any:
    """Stamp a non-destructive ``degradation`` marker onto a dict event copy."""
    if isinstance(event, dict):
        event["degradation"] = degradation
    return event


# ---------------------------------------------------------------------------
# The four injectors. Each is a pure, seeded function: list in -> new list out.
# ---------------------------------------------------------------------------
def delay_events(events: Sequence[Any], delay: float, seed: int = 0) -> list[Any]:
    """DELAY: push each event's arrival later by ``delay``.

    A dict event carrying a time key (``ts`` / ``time`` / ``timestamp``) has that
    value shifted by ``delay``; otherwise the injected delay is recorded as a
    ``degradation`` marker. ``seed`` is accepted for interface uniformity with
    the other injectors and is reserved for jitter variants; the base delay is a
    constant of the parameter, so output is identical for any seed -- trivially
    deterministic. Returns a NEW list; the input list is never mutated.
    """
    delay = float(delay)
    out: list[Any] = []
    for event in events:
        e = _annotate(_copy_event(event), ("delay", delay))
        if isinstance(e, dict):
            for key in _TIME_KEYS:
                if key in e:
                    try:
                        e[key] = e[key] + delay
                    except TypeError:
                        pass  # non-numeric time value: leave as-is
                    break
        out.append(e)
    return out


def duplicate_events(events: Sequence[Any], factor: int, seed: int = 0) -> list[Any]:
    """DUPLICATE: emit each event ``factor`` times.

    Factor copies of each event are emitted consecutively (``e0,e0,...`` then
    ``e1,e1,...``). ``factor`` is deterministic of the parameter, so output is
    identical for any ``seed`` -- trivially deterministic. Each copy is a fresh
    shallow copy (no aliasing). Returns a NEW list; never mutates the input.
    """
    factor = int(factor)
    if factor < 1:
        raise ValueError(f"duplicate factor must be >= 1, got {factor!r}")
    out: list[Any] = []
    for event in events:
        for _ in range(factor):
            out.append(_annotate(_copy_event(event), ("duplicate", factor)))
    return out


def reorder_events(events: Sequence[Any], window: int, seed: int = 0) -> list[Any]:
    """REORDER: shuffle each non-overlapping ``window``-sized slice in place.

    Introduces out-of-order arrivals within a telemetry window. The shuffle is
    drawn from ``random.Random(seed)`` -- deterministic per seed. A ``window`` < 2
    degenerates to a pass-through (nothing to reorder). Returns a NEW list of
    copies; never mutates the input.
    """
    window = int(window)
    rng = Random(seed)
    if window < 2:
        return [_annotate(_copy_event(e), ("reorder", window)) for e in events]
    out: list[Any] = []
    for start in range(0, len(events), window):
        chunk = list(events[start : start + window])
        rng.shuffle(chunk)  # deterministically introduces out-of-order
        for e in chunk:
            out.append(_annotate(_copy_event(e), ("reorder", window)))
    return out


def drop_events(events: Sequence[Any], drop_rate: float, seed: int = 0) -> list[Any]:
    """LOSS: drop each event with probability ``drop_rate``.

    Each event is KEPT with probability ``1 - drop_rate``, decided by
    ``random.Random(seed)`` -- deterministic per seed. LOSS only ever REMOVES
    events: the degraded set is a strict-or-equal SUBSET of the original (no
    fabricated events). At ``drop_rate = 0`` nothing is dropped (identity);
    at ``drop_rate = 1`` everything is dropped. Returns a NEW list; never
    mutates the input.
    """
    drop_rate = float(drop_rate)
    if not 0.0 <= drop_rate <= 1.0:
        raise ValueError(f"drop_rate must be in [0.0, 1.0], got {drop_rate!r}")
    rng = Random(seed)
    out: list[Any] = []
    for event in events:
        if rng.random() >= drop_rate:  # kept
            out.append(_annotate(_copy_event(event), ("loss", drop_rate)))
    return out


DEGRADATIONS: dict[str, Callable[..., list[Any]]] = {
    "delay": delay_events,
    "duplicate": duplicate_events,
    "reorder": reorder_events,
    "loss": drop_events,
}


def degrade(events: Sequence[Any], kind: str, **params: Any) -> list[Any]:
    """Dispatch to the named injector. ``kind`` is case-insensitive.

    The mapping between a telemetry fault and the injector that models it:
    ``loss`` == drop_events, ``reorder`` == reorder_events, etc. Unknown kinds
    raise ``ValueError`` (fail fast, never silently pass through).
    """
    key = kind.lower()
    if key not in DEGRADATIONS:
        raise ValueError(f"unknown degradation {kind!r}; choose from {sorted(DEGRADATIONS)}")
    return DEGRADATIONS[key](events, **params)


def is_subset(degraded: Sequence[Any], original: Sequence[Any]) -> bool:
    """True iff every degraded event id is an original event id (no fabrication)."""
    original_ids = set(ids(original))
    return all(eid in original_ids for eid in ids(degraded))


# ---------------------------------------------------------------------------
# Canonicalization + self-check: prove determinism and the loss-subset property
# on real output (used by `--selfcheck` and importable for harness assertions).
# ---------------------------------------------------------------------------
def canonical(events: Sequence[Any]) -> str:
    """Byte-stable string of the id sequence (fixed order, no dict-ordering hazard)."""
    return "\n".join(str(eid) for eid in ids(events))


def _sha(events: Sequence[Any]) -> str:
    return hashlib.sha256(canonical(events).encode("utf-8")).hexdigest()


def _sample_events(n: int = 20) -> list[dict[str, Any]]:
    """Synthesize ``n`` dict events ``e0..eN-1`` with an id and a time field."""
    return [{"id": f"e{i}", "ts": float(i) * 10.0} for i in range(n)]


def selfcheck(seed: int = 7) -> int:
    """Run the built-in proof: determinism per injector + loss degradation.

    Returns 0 on success (all assertions pass), nonzero on failure. Prints the
    evidence so the acceptance can be verified on REAL output.
    """
    events = _sample_events(20)
    ok = True

    print("== FENGARDE telemetry-degradation rig self-check ==")
    print(f"source events: n={len(events)} ids={ids(events)}\n")

    # (a) Determinism: every injector, same seed twice -> byte-identical.
    calls = {
        "delay": dict(delay=5.0),
        "duplicate": dict(factor=3),
        "reorder": dict(window=4),
        "loss": dict(drop_rate=0.4),
    }
    for kind, params in calls.items():
        a = degrade(events, kind, seed=seed, **params)
        b = degrade(events, kind, seed=seed, **params)
        identical = canonical(a) == canonical(b)
        ok = ok and identical
        print(f"determinism[{kind}]: run1 sha={_sha(a)} run2 sha={_sha(b)} identical={identical} (n={len(a)})")

    # (b) LOSS: degraded set shrinks as drop_rate rises AND is always a subset.
    print("\nloss subset/shrink proof (seed=%d):" % seed)
    prev_n = len(events)
    for rate in (0.0, 0.2, 0.4, 0.6, 0.8, 0.95):
        deg = drop_events(events, rate, seed=seed)
        n = len(deg)
        subset = is_subset(deg, events)
        shrinks_or_equal = n <= prev_n
        print(
            f"  drop_rate={rate:<4} kept={n:<2} ({(100 * n / len(events)):.0f}% of "
            f"original) subset={subset} non-increasing={shrinks_or_equal}"
        )
        ok = ok and subset and shrinks_or_equal
        prev_n = n

    # Loss alone never FABRICATES events -> strict-subset at a nonzero rate.
    deg = drop_events(events, 0.5, seed=seed)
    strict = len(deg) < len(events) and is_subset(deg, events)
    print(
        f"\nloss strict-subset at drop_rate=0.5: subset={is_subset(deg, events)} n={len(deg)} < original={len(events)} strict={strict}"
    )
    ok = ok and strict

    # (c) The injector only degrades telemetry; it cannot fabricate an anomaly.
    print(
        "\nnote: loss removes events (lower recall downstream) but never adds one "
        "(no fabricated incident from missing data) -- graceful-degradation "
        "scoring is measured by the downstream oracle, not this rig."
    )
    print(f"\nSELF-CHECK {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# CLI: apply a named degradation to an input list and print the event ids.
# Runs entirely outside the twin -- a standalone entry point.
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="degradation",
        description=(
            "FENGARDE telemetry-degradation rig (WP-1-E): a standalone, seeded "
            "DELAY/DUPLICATE/REORDER/LOSS injector over a list of events. "
            "Simulation rig only -- never a control path."
        ),
    )
    parser.add_argument("--kind", choices=sorted(DEGRADATIONS), help="injector to apply: delay, duplicate, reorder, loss")
    ids_src = parser.add_mutually_exclusive_group()
    ids_src.add_argument("--ids", nargs="+", help="explicit event ids to degrade (prints ids back)")
    ids_src.add_argument("--count", type=int, help="synthesize this many events e0..eN-1")
    parser.add_argument("--seed", type=int, default=0, help="RNG seed (same seed + input => identical output)")
    parser.add_argument("--delay", type=float, default=5.0, help="DELAY value")
    parser.add_argument("--factor", type=int, default=3, help="DUPLICATE factor")
    parser.add_argument("--window", type=int, default=4, help="REORDER window size")
    parser.add_argument("--drop-rate", type=float, default=0.3, help="LOSS rate")
    parser.add_argument("--selfcheck", action="store_true", help="run the built-in determinism + loss-subset proof")
    args = parser.parse_args(argv)

    if args.selfcheck:
        return selfcheck(seed=args.seed)

    if args.ids is None and args.count is None:
        parser.error("one of --ids or --count is required (unless --selfcheck)")

    if args.ids is not None:
        events: list[Any] = list(args.ids)
    else:
        events = _sample_events(args.count)

    params = {
        "delay": dict(delay=args.delay),
        "duplicate": dict(factor=args.factor),
        "reorder": dict(window=args.window),
        "loss": dict(drop_rate=args.drop_rate),
    }[args.kind]

    degraded = degrade(events, args.kind, seed=args.seed, **params)
    print(f"# degradation kind={args.kind} seed={args.seed} n_in={len(events)} n_out={len(degraded)}")
    print("\n".join(str(eid) for eid in ids(degraded)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
