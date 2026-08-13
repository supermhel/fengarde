"""atheris fuzz harness: services/ws2-normalization/parsers/generic_syslog.py.

Run:  python tools/fuzz/fuzz_generic_syslog.py -atheris_runs=200000
      python tools/fuzz/fuzz_generic_syslog.py -max_total_time=600   # nightly CI (10 min)
Corpus (optional, speeds convergence): pass a directory as the last arg.
"""
from __future__ import annotations

from _common import run
from parsers.generic_syslog import GenericSyslogParser

if __name__ == "__main__":
    run(GenericSyslogParser(), "generic_syslog")
