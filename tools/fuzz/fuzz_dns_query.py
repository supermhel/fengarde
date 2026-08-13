"""atheris fuzz harness: services/ws2-normalization/parsers/dns_query.py.

Run:  python tools/fuzz/fuzz_dns_query.py -atheris_runs=200000
      python tools/fuzz/fuzz_dns_query.py -max_total_time=600   # nightly CI (10 min)
Corpus (optional, speeds convergence): pass a directory as the last arg.
"""
from __future__ import annotations

from _common import run
from parsers.dns_query import DnsQueryParser

if __name__ == "__main__":
    run(DnsQueryParser(), "dns_query")
