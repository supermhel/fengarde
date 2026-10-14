"""atheris fuzz harness: services/ws2-normalization/parsers/m365_audit.py (Microsoft 365 unified audit, 2026-10-14).

The parser accepts raw['raw'] as a dict or a JSON string; run_json (fuzzed bytes -> JSON
decode -> parse() on a dict) exercises the structured path, where every field is
attacker-influenced.

Run:  python tools/fuzz/fuzz_m365_audit.py -atheris_runs=200000
      python tools/fuzz/fuzz_m365_audit.py -max_total_time=600   # nightly CI (10 min)
"""
from __future__ import annotations

from _common import run_json
from parsers.m365_audit import M365AuditParser

if __name__ == "__main__":
    run_json(M365AuditParser(), "m365_audit")
