"""atheris fuzz harness: services/ws2-normalization/parsers/mail_gateway.py (mail-gateway message log, 2026-10-14).

The parser accepts raw['raw'] as a dict or a JSON string; run_json (fuzzed bytes -> JSON
decode -> parse() on a dict) exercises the structured path, where every field is
attacker-influenced.

Run:  python tools/fuzz/fuzz_mail_gateway.py -atheris_runs=200000
      python tools/fuzz/fuzz_mail_gateway.py -max_total_time=600   # nightly CI (10 min)
"""
from __future__ import annotations

from _common import run_json
from parsers.mail_gateway import MailGatewayParser

if __name__ == "__main__":
    run_json(MailGatewayParser(), "mail_gateway")
