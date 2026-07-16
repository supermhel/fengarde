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

from shared.ocsf import validate as ocsf_validate  # noqa: E402


def make_test_one_input(parser, source_type: str):
    """Build the atheris TestOneInput(data) closure for one parser.

    The only thing that counts as a finding: parser.parse() raising, or
    returning an event that fails Contract A validation. A None return
    (rejected input) is success, not a finding -- that's the parser doing
    its job on adversarial input.
    """
    import atheris

    def test_one_input(data: bytes) -> None:
        fdp = atheris.FuzzedDataProvider(data)
        line = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())
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


def run(parser, source_type: str) -> None:
    import atheris

    test_one_input = make_test_one_input(parser, source_type)
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
