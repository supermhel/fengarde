"""Shared plumbing for the atheris fuzz harnesses (M1 correctness gate,
PLAN_C Tier 1.2's "fuzzing (atheris) in a nightly CI job for the top 3
parsers"). One harness per targeted parser (fuzz_linux_ssh.py,
fuzz_cisco_asa.py, fuzz_windows_eventlog.py) -- separate atheris processes
so a crash in one doesn't hide corpus progress in the others, and so each
gets its own corpus directory (see .github/workflows/fuzz.yml).

A finding here is anything Hypothesis' structural fuzzing
(parsers/test_property_hardening.py) could miss because it doesn't mutate at
the byte level: atheris does coverage-guided *byte* mutation of the raw log
line, so it can discover regex/encoding edge cases neither a human nor
value-level property testing would think to generate.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOLS = HERE.parent
ROOT = TOOLS.parent
SERVICES = ROOT / "services"
sys.path.insert(0, str(SERVICES))
sys.path.insert(0, str(SERVICES / "ws2-normalization"))

# 2026-10-20: the harnesses were BLIND. atheris only gets coverage feedback from modules imported inside
# ``atheris.instrument_imports()``; none of the 19 harnesses did that, so the corpus never grew ("corp: 1/1b" after 3.8M
# runs in a 90 s Docker run) and the nightly job / OSS-Fuzz fuzzed with no guidance. Importing the ``parsers`` package here,
# before any harness imports a parser, instruments every parser module (the registry imports them all). Guarded so
# ``_common`` stays importable where atheris is not installed (only the harness entry points need it).
try:
    import atheris as _atheris
except ImportError:  # pragma: no cover
    _atheris = None
if _atheris is not None:
    with _atheris.instrument_imports():
        import parsers  # noqa: E402,F401
from shared.ocsf import validate as ocsf_validate  # noqa: E402


def make_test_one_input(parser, source_type: str):
    """Build the atheris TestOneInput(data) closure for one parser.

    The only thing that counts as a finding: parser.parse() raising, or
    returning an event that fails Contract A validation. A None return
    (rejected input) is success, not a finding -- that's the parser doing
    its job on adversarial input.
    """

    def test_one_input(data: bytes) -> None:
        # Plain UTF-8 decode of the fuzz bytes (2026-10-20): FuzzedDataProvider.ConsumeUnicode* re-encodes bytes into
        # code points in its own scheme, so a real seed record never round-trips to the same text and seeds are useless.
        line = data.decode("utf-8", errors="replace")
        raw = {
            "source_type": source_type,
            "raw": line,
            "meta": {"received_at": 1700000000, "ingest_id": "fuzz"},
        }
        try:
            event = parser.parse(raw)
        except Exception as exc:  # pragma: no cover - the crash IS the finding
            raise AssertionError(
                f"{source_type} parser crashed on fuzzed input: {exc!r}\nline={line!r}"
            ) from exc
        if event is None:
            return
        errors = ocsf_validate(event)
        if errors:
            raise AssertionError(
                f"{source_type} parser emitted schema-invalid OCSF: {errors}\nline={line!r}"
            )

    return test_one_input


def make_json_test_one_input(parser, source_type: str):
    """Same contract as make_test_one_input, for parsers whose parse()
    requires raw['raw'] to already be a dict (isinstance(rec, dict) check,
    no string-with-json.loads fallback) -- k8s_audit, cloudtrail,
    modbus_anomaly, inventory_diff. Feeding those parsers a bare fuzzed
    string via make_test_one_input would never get past that isinstance
    check, so every input degrades to trivially "not a finding" without
    exercising any real field-handling logic. This decodes the fuzzed bytes
    as JSON first and only calls parse() when that produces a dict --
    atheris' coverage feedback still drives it toward interesting shapes
    over the run, same as the string-based harness does for its parsers.
    """
    import json as _json


    def test_one_input(data: bytes) -> None:
        text = data.decode("utf-8", errors="replace")   # see the note in make_test_one_input
        try:
            rec = _json.loads(text)
        except (ValueError, TypeError):
            return  # not a finding -- the parser's own isinstance(rec, dict) guard exists for this
        if not isinstance(rec, dict):
            return
        raw = {
            "source_type": source_type,
            "raw": rec,
            "meta": {"received_at": 1700000000, "ingest_id": "fuzz"},
        }
        try:
            event = parser.parse(raw)
        except Exception as exc:  # pragma: no cover - the crash IS the finding
            raise AssertionError(
                f"{source_type} parser crashed on fuzzed input: {exc!r}\nrec={rec!r}"
            ) from exc
        if event is None:
            return
        errors = ocsf_validate(event)
        if errors:
            raise AssertionError(
                f"{source_type} parser emitted schema-invalid OCSF: {errors}\nrec={rec!r}"
            )

    return test_one_input


def run(parser, source_type: str) -> None:
    import atheris

    test_one_input = make_test_one_input(parser, source_type)
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


def run_json(parser, source_type: str) -> None:
    import atheris

    test_one_input = make_json_test_one_input(parser, source_type)
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
