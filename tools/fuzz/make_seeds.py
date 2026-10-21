"""Write a seed corpus for the atheris harnesses from the repo's own REAL parser fixtures.

    python tools/fuzz/make_seeds.py <outdir>      # -> <outdir>/<source_type>/seed_<n>

Why: with coverage feedback on (``_common.py`` instruments the parsers) a harness still plateaus at a few dozen edges when
it must invent valid JSON records from random bytes (measured 2026-10-20: windows_eventlog stuck at cov: 29 for 2.2M runs).
Seeding with one real record per EventID/format lets the mutator start inside the field-handling code.
The fixtures are the same ones tools/check_rule_producers.py already maintains (one representative record per parser path).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from check_rule_producers import FIXTURES  # noqa: E402


def main(argv: list) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    out = Path(argv[1])
    total = 0
    for source_type, fixtures in FIXTURES.items():
        d = out / source_type
        d.mkdir(parents=True, exist_ok=True)
        for i, fx in enumerate(fixtures):
            raw = fx.get("raw")
            data = raw if isinstance(raw, str) else json.dumps(raw, sort_keys=True)
            (d / f"seed_{i}").write_bytes(data.encode("utf-8"))
            total += 1
    print(f"wrote {total} seeds for {len(FIXTURES)} source types into {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
