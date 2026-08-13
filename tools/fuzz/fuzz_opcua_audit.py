"""atheris fuzz harness: services/ws2-normalization/parsers/opcua_audit.py.

Run:  python tools/fuzz/fuzz_opcua_audit.py -atheris_runs=200000
      python tools/fuzz/fuzz_opcua_audit.py -max_total_time=600   # nightly CI (10 min)
Corpus (optional, speeds convergence): pass a directory as the last arg.
"""
from __future__ import annotations

from _common import run
from parsers.opcua_audit import OpcUaAuditParser

if __name__ == "__main__":
    run(OpcUaAuditParser(), "opcua_audit")
