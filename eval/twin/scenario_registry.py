"""scenario_registry -- the one place that lists every attack storyline the
twin / reconciler / mutation harness runs over.

Adding a storyline = define a ``scenario.ScenarioDef`` (steps + deterministic
raw-payload builder + oracle path) and append it to ``ALL``. Every consumer
that iterates this registry -- ``oracle_consistency`` (answer key vs reality)
and ``eval/adversarial/scenario_matrix`` (mutation robustness) -- then covers
it with no further wiring, and a scenario whose oracle disagrees with what its
own builder does fails the gate.
"""
from __future__ import annotations

import sys
from pathlib import Path

TWIN = Path(__file__).resolve().parent
if str(TWIN) not in sys.path:
    sys.path.insert(0, str(TWIN))

import scenario  # noqa: E402
import scenarios_extra  # noqa: E402

ALL: tuple = (
    scenario.AI_TO_OT,
    scenarios_extra.IT_INTRUSION,
    scenarios_extra.INFRA_TAKEOVER,
)

BY_NAME: dict = {s.name: s for s in ALL}


def get(name: str):
    try:
        return BY_NAME[name]
    except KeyError:
        raise KeyError(f"unknown scenario {name!r} (registered: {sorted(BY_NAME)})") from None


def load_oracle(sdef) -> dict:
    """The grading oracle for ``sdef`` (imported lazily: ``report`` pulls in
    the WS-4/WS-8 machinery and nothing that only needs the list should pay)."""
    import report  # noqa: PLC0415
    return report._load_oracle(sdef.oracle_path)


def run(sdef, seed: int = 7, *, payload_source=None, strict: bool = True):
    """Run ``sdef`` through the REAL WS-2 parse path (optionally on a mutated
    payload source) and return the ``ChainResult``."""
    return scenario.run_chain(
        seed, strict=strict, steps=tuple(sdef.steps) + tuple(sdef.decoy_steps),
        payload_source=payload_source if payload_source is not None else sdef.build)


def grade(sdef, seed: int = 7, *, payload_source=None, strict: bool = True) -> dict:
    """Run + grade ``sdef`` with the shared twin grader against ITS OWN oracle."""
    import report  # noqa: PLC0415
    result = run(sdef, seed, payload_source=payload_source, strict=strict)
    return report._grade_chain(result, load_oracle(sdef))
