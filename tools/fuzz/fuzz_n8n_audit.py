"""atheris fuzz harness: services/ws2-normalization/parsers/n8n_audit.py.

Run:  python tools/fuzz/fuzz_n8n_audit.py -atheris_runs=200000
      python tools/fuzz/fuzz_n8n_audit.py -max_total_time=600   # nightly CI (10 min)
Corpus (optional, speeds convergence): pass a directory as the last arg.
"""
from __future__ import annotations

from _common import run
from parsers.n8n_audit import N8nAuditParser

if __name__ == "__main__":
    run(N8nAuditParser(), "n8n_audit")
