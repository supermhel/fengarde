"""Systematic extreme-value sweep over every parser, seeded from the repo's own real fixtures.

Why this exists: the nightly atheris fuzz twice crashed a parser (sysmon, n8n_audit) with
``OverflowError: int too large to convert to float`` from one huge timestamp. Hypothesis' random
dictionaries almost never put a hostile value under the key a parser actually reads, and the fuzzer finds
such keys only by chance. This test does it deterministically: for each fixture in
``tools/check_rule_producers.FIXTURES`` (one real record per parser path), every leaf value of a JSON record
is replaced by each extreme in turn (and every digit run of a text line is replaced by a 400-digit run).
A parser must never raise and must never emit schema-invalid OCSF.

Run: python services/ws2-normalization/parsers/test_extreme_values.py
"""
from __future__ import annotations

import copy
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
NORMALIZATION = HERE.parent
SERVICES = NORMALIZATION.parent
ROOT = SERVICES.parent
sys.path.insert(0, str(SERVICES))
sys.path.insert(0, str(NORMALIZATION))
sys.path.insert(0, str(ROOT / "tools"))

from check_rule_producers import FIXTURES  # noqa: E402
from parsers import get_parser, known_sources  # noqa: E402
from parsers.base import _ingest_id_str  # noqa: E402
from shared.ocsf import validate as ocsf_validate  # noqa: E402

BIG = 10 ** 400
EXTREMES = [BIG, -BIG, 2 ** 64, 2 ** 63, -(2 ** 63), 1e308, -1e308, float("inf"), float("-inf"), float("nan"),
            0, -1, "9" * 400, "-" + "9" * 400, "1" + "0" * 400, "\x00", "A" * 100_000,
            "9" * 5000,  # a 5000-digit STRING (an int that long cannot arrive: json.loads rejects ints over 4300 digits,
            #              so no record from the bus can carry one; only ingest_id is guarded against it, in base.py)
            True, False, None, [], {}, [1], {"a": 1}]  # bool is an int to isinstance(); containers where a scalar is expected
DIGITS = re.compile(r"\d+")


def leaf_paths(node, path=()):
    if isinstance(node, dict):
        for k, v in node.items():
            yield from leaf_paths(v, path + (k,))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from leaf_paths(v, path + (i,))
    else:
        yield path


def set_path(node, path, value):
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value


def variants(raw):
    """Yield (label, mutated raw) for every extreme at every leaf (JSON) or digit run (text)."""
    if isinstance(raw, str):
        runs = list(DIGITS.finditer(raw))
        for n, m in enumerate(runs):
            for repl in ("9" * 400, "0" * 400, "1" + "0" * 30):
                yield f"digits#{n}->{repl[:4]}x{len(repl)}", raw[:m.start()] + repl + raw[m.end():]
        return
    for path in leaf_paths(raw):
        if not path:
            continue
        for ev in EXTREMES:
            mutated = copy.deepcopy(raw)
            set_path(mutated, path, ev)
            shown = f"int({ev.bit_length()} bits)" if isinstance(ev, int) and not isinstance(ev, bool) else repr(ev)[:14]
            yield f"{'.'.join(map(str, path))}={shown}", mutated


def run():
    failures: list[str] = []
    total = 0
    missing = set(known_sources()) - set(FIXTURES)
    if missing:
        failures.append(f"parsers without a fixture (not swept): {sorted(missing)}")
    for source_type, fixtures in sorted(FIXTURES.items()):
        parser = get_parser(source_type)
        for fi, fx in enumerate(fixtures):
            for label, raw in variants(fx.get("raw")):
                total += 1
                payload = {"source_type": source_type, "raw": raw, "meta": dict(fx.get("meta") or {"received_at": 1700000000})}
                try:
                    event = parser.parse(payload)
                except Exception as exc:  # the crash IS the finding
                    failures.append(f"{source_type}[{fi}] {label}: {type(exc).__name__}: {str(exc)[:80]}")
                    continue
                if event is not None:
                    errs = ocsf_validate(event)
                    if errs:
                        failures.append(f"{source_type}[{fi}] {label}: schema-invalid OCSF: {errs[:1]}")
    # ingest_id coercion (base.py): never raises, numeric ids become strings, junk gets a fresh uuid
    for given, want in ((123, "123"), (1.5, "1.5"), ("abc", "abc"), (0, "0")):
        if _ingest_id_str(given) != want:
            failures.append(f"_ingest_id_str({given!r}) -> {_ingest_id_str(given)!r}, want {want!r}")
    for junk in (None, True, False, "", [], {}, 10 ** 5000, float("nan")):
        try:
            out = _ingest_id_str(junk)
        except Exception as exc:
            failures.append(f"_ingest_id_str({str(junk)[:10]!r}) raised {type(exc).__name__}")
            continue
        if junk is float("nan") or (isinstance(junk, float) and junk != junk):
            continue  # nan -> "nan" is a valid string id
        if not isinstance(out, str) or not out:
            failures.append(f"_ingest_id_str(junk) returned {out!r}")
    return total, failures


def main():
    total, failures = run()
    if failures:
        print(f"[FAIL] extreme values: {len(failures)} problem(s) in {total} mutations")
        seen = set()
        for f in failures:
            key = f.split(": ", 1)[1] if ": " in f else f
            if key in seen:
                continue
            seen.add(key)
            print("   -", f)
        sys.exit(1)
    print(f"[OK] extreme values: {total} mutations of {len(FIXTURES)} parsers' real fixtures, none crashed or emitted invalid OCSF")


if __name__ == "__main__":
    main()
