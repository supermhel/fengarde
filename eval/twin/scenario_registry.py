"""scenario_registry -- the one place that lists every attack storyline the
twin / reconciler / mutation harness runs over.

Adding a storyline = define a ``scenario.ScenarioDef`` (steps + deterministic
raw-payload builder + oracle path) in ``eval/twin/storyline_<name>.py`` exporting ``STORYLINE``;
``_discover`` registers it (no shared file is edited). Every consumer
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

import importlib  # noqa: E402

import scenario  # noqa: E402
import scenarios_extra  # noqa: E402

#: The three storylines that predate auto-discovery, in their historical order. Every
#: published per-scenario number keys on these names, so their order never moves.
BUILTIN: tuple = (
    scenario.AI_TO_OT,
    scenarios_extra.IT_INTRUSION,
    scenarios_extra.INFRA_TAKEOVER,
)


def _discover() -> tuple:
    """Storylines contributed as ``eval/twin/storyline_<name>.py``, each exporting ONE
    ``STORYLINE`` (a ``scenario.ScenarioDef``). Adding a storyline is therefore adding files
    (the module, its ``oracle_<name>.yaml``) and editing nothing shared, so several can land in
    parallel without touching this registry. Order is the sorted module name -- deterministic and
    independent of the filesystem. A module that fails to import, exports no ``STORYLINE`` or
    reuses a name FAILS LOUDLY here: a registry that silently skipped a broken storyline would
    report robustness over fewer attack shapes than it claims."""
    found: list = []
    for path in sorted(TWIN.glob("storyline_*.py")):
        mod = importlib.import_module(path.stem)
        sdef = getattr(mod, "STORYLINE", None)
        if not isinstance(sdef, scenario.ScenarioDef):
            raise RuntimeError(f"{path.name} must export STORYLINE: scenario.ScenarioDef "
                               f"(got {type(sdef).__name__})")
        found.append(sdef)
    return tuple(found)


ALL: tuple = BUILTIN + _discover()

_names = [s.name for s in ALL]
if len(set(_names)) != len(_names):
    raise RuntimeError(f"duplicate storyline names registered: {sorted(_names)}")

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
