"""M1 correctness gate: property-based parser hardening (Hypothesis).

PLAN_C Tier 1.2's ask, run against every registered parser: arbitrary/malformed
input must never crash a parser and must never produce an OCSF-schema-invalid
event. This complements (does not replace) test_parser_hardening.py's specific
adversarial cases (P0 hardening, `9e2745b`) -- those are curated regression
fixtures for known-bad inputs; this file is unguided fuzzing across the
signature every parser shares (`parse(raw: dict) -> Optional[dict]`).

Not wired into the atheris nightly fuzz job (that's bytecode-level, this is
structural/value-level) -- see .github/workflows/fuzz.yml.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
NORMALIZATION = HERE.parent
SERVICES = NORMALIZATION.parent
sys.path.insert(0, str(SERVICES))
sys.path.insert(0, str(NORMALIZATION))

from hypothesis import HealthCheck, given, settings, strategies as st  # noqa: E402

from parsers import known_sources, get_parser  # noqa: E402
from shared.ocsf import validate as ocsf_validate  # noqa: E402

# A recursive JSON-like value strategy -- covers the shapes a hostile/garbled
# raw.events payload could actually carry (not just strings: nested dicts,
# lists, numbers, None, booleans), bounded so generation terminates quickly.
_json_scalar = st.one_of(
    st.none(), st.booleans(), st.integers(), st.floats(allow_nan=True, allow_infinity=True),
    st.text(max_size=200),
)
_json_value = st.recursive(
    _json_scalar,
    lambda children: st.one_of(
        st.lists(children, max_size=5),
        st.dictionaries(st.text(max_size=20), children, max_size=5),
    ),
    max_leaves=20,
)

_raw_payload = st.fixed_dictionaries({
    "source_type": st.one_of(st.text(max_size=50), st.none()),
    "raw": _json_value,
    "meta": st.one_of(st.none(), st.dictionaries(st.text(max_size=20), _json_value, max_size=8)),
})

_SLOW_SETTINGS = settings(
    max_examples=100,
    suppress_health_check=[HealthCheck.too_slow],
    deadline=None,  # regex/normalization work can legitimately take a few ms under CI load
)


def _check_parser(source_type: str, raw: dict) -> None:
    parser = get_parser(source_type)
    assert parser is not None, f"registered source_type {source_type!r} has no parser"
    try:
        event = parser.parse(raw)
    except Exception as exc:  # pragma: no cover - the failure IS the finding
        raise AssertionError(
            f"{source_type} parser crashed on malformed input: {exc!r}\nraw={raw!r}"
        ) from exc
    if event is None:
        return
    errors = ocsf_validate(event)
    assert not errors, (
        f"{source_type} parser emitted a schema-invalid OCSF event: {errors}\nraw={raw!r}"
    )


def _make_test(source_type: str):
    @given(raw=_raw_payload)
    @_SLOW_SETTINGS
    def _test(raw):
        raw = dict(raw)
        raw["source_type"] = source_type
        _check_parser(source_type, raw)
    _test.__name__ = f"test_property_{source_type}_never_crashes_or_emits_invalid_ocsf"
    return _test


# One Hypothesis-driven test function per registered parser, so a failure
# names the offending source_type directly instead of a generic loop failure.
for _st in known_sources():
    globals()[f"test_property_{_st}_never_crashes_or_emits_invalid_ocsf"] = _make_test(_st)
del _st


def main() -> int:
    failures: list[str] = []
    for source_type in known_sources():
        test_fn = globals()[f"test_property_{source_type}_never_crashes_or_emits_invalid_ocsf"]
        try:
            test_fn()
            print(f"[OK] {source_type}: 100 examples, no crash, no invalid OCSF")
        except Exception as exc:  # Hypothesis re-raises the shrunk failing case
            failures.append(f"{source_type}: {exc}")
            print(f"[FAIL] {source_type}: {exc}")
    if failures:
        print(f"\n[FAIL] property hardening: {len(failures)} parser(s) failed")
        return 1
    print("\n[OK] property hardening: all parsers PASS (Hypothesis, 100 examples each)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
