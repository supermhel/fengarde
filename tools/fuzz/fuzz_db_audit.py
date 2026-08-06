"""atheris fuzz harness: services/ws2-normalization/parsers/db_audit.py.

Added in the L8 (2026-08-06) fuzz-matrix expansion. db_audit is a high-value
text parser (GRANT/privilege classification, FIX-3-adjacent) whose JSON-payload
shape is worth byte-level coverage. Mirrors fuzz_linux_ssh.py's harness.

Run:  python tools/fuzz/fuzz_db_audit.py -atheris_runs=200000
      python tools/fuzz/fuzz_db_audit.py -max_total_time=600   # nightly CI (10 min)
Corpus (optional, speeds convergence): pass a directory as the last arg.
"""
from __future__ import annotations

from _common import run
from parsers.db_audit import DbAuditParser

if __name__ == "__main__":
    run(DbAuditParser(), "db_audit")
