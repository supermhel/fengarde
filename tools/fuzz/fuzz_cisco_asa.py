"""atheris fuzz harness: services/ws2-normalization/parsers/cisco_asa.py.

Run:  python tools/fuzz/fuzz_cisco_asa.py -atheris_runs=200000
      python tools/fuzz/fuzz_cisco_asa.py -max_total_time=600   # nightly CI (10 min)
"""
from __future__ import annotations

from _common import run
from parsers.cisco_asa import CiscoAsaParser

if __name__ == "__main__":
    run(CiscoAsaParser(), "cisco_asa")
