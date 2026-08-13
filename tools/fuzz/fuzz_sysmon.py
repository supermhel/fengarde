"""atheris fuzz harness: services/ws2-normalization/parsers/sysmon.py.

Run:  python tools/fuzz/fuzz_sysmon.py -atheris_runs=200000
      python tools/fuzz/fuzz_sysmon.py -max_total_time=600   # nightly CI (10 min)
Corpus (optional, speeds convergence): pass a directory as the last arg.
"""
from __future__ import annotations

from _common import run
from parsers.sysmon import SysmonParser

if __name__ == "__main__":
    run(SysmonParser(), "sysmon")
