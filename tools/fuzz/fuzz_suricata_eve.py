"""atheris fuzz harness: services/ws2-normalization/parsers/suricata_eve.py.

parse() accepts raw['raw'] as a JSON line (string) or an already-decoded dict, so this uses the string harness: the
fuzzed text reaches the parser's own json.loads, then every field handler.

Run:  python tools/fuzz/fuzz_suricata_eve.py -atheris_runs=200000
      python tools/fuzz/fuzz_suricata_eve.py -max_total_time=600   # nightly CI (10 min)
Corpus (optional, speeds convergence): pass a directory as the last arg.
"""
from __future__ import annotations

from _common import run
from parsers.suricata_eve import SuricataEveParser

if __name__ == "__main__":
    run(SuricataEveParser(), "suricata_eve")
