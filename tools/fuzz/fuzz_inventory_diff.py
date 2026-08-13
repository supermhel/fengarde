"""atheris fuzz harness: services/ws2-normalization/parsers/inventory_diff.py.

Unlike the text-line parsers, InventoryDiffParser.parse() requires raw['raw']
to already be a dict (no string/json.loads fallback), so this uses run_json
(fuzzed bytes -> JSON decode -> only calls parse() on a dict result).

Run:  python tools/fuzz/fuzz_inventory_diff.py -atheris_runs=200000
      python tools/fuzz/fuzz_inventory_diff.py -max_total_time=600   # nightly CI (10 min)
Corpus (optional, speeds convergence): pass a directory as the last arg.
"""
from __future__ import annotations

from _common import run_json
from parsers.inventory_diff import InventoryDiffParser

if __name__ == "__main__":
    run_json(InventoryDiffParser(), "inventory_diff")
