"""v0.4 new-rule firing test: impossible-travel.

Loads the REAL rule YAML and feeds it events shaped exactly as the REAL
linux_ssh parser emits, run through the REAL A5 enrichment stage (the
distinct_field this rule keys on -- src_endpoint.location.country -- is an
enrichment-added field, not a parser field; skipping enrichment here would
test a shape the pipeline never actually produces). Zero infra.

Run: python services/ws4-detection/test_v04_new_rules.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "services"))
sys.path.insert(0, str(ROOT / "services" / "ws2-normalization"))

from engine import load_rules  # noqa: E402
from parsers.linux_ssh import LinuxSshParser  # noqa: E402
from enrichment import enrich  # noqa: E402

RULES_DIR = ROOT / "contracts" / "rules"
FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def rule_by_id(rules, rid):
    for r in rules:
        if r.id == rid:
            return r
    raise AssertionError(f"rule {rid} not loaded")


IMPOSSIBLE_TRAVEL_ID = "7081a2b3-c405-4de3-be5f-6a7b8c9d0e12"


def _accepted(ip: str, i: int, base: int):
    line = f"Jun 10 13:55:{i:02d} db01 sshd[2160]: Accepted publickey for jdoe from {ip} port 50022 ssh2"
    return {"raw": line, "meta": {"received_at": base + i, "ingest_id": f"travel{i}"}}


def run():
    ssh = LinuxSshParser()
    base = 1_750_000_000

    rules = load_rules(RULES_DIR)
    rule = rule_by_id(rules, IMPOSSIBLE_TRAVEL_ID)
    check(rule.stateful and rule.distinct_field == "src_endpoint.location.country",
          "impossible-travel rule should be stateful distinct on src_endpoint.location.country")

    # Same account, same country (RU, per contracts/enrichment/geoip.yml's
    # 203.0.113.0/24 sample entry) twice -> only ONE distinct country -> no fire.
    ev1 = enrich(ssh.parse(_accepted("203.0.113.5", 0, base)))
    ev2 = enrich(ssh.parse(_accepted("203.0.113.9", 1, base)))
    check(ev1["src_endpoint"]["location"]["country"] == "RU",
          "REAL enrichment must resolve 203.0.113.5 to RU (per geoip.yml sample data)")
    check(rule.evaluate(ev1) is False, "impossible-travel: first login must not fire")
    check(rule.evaluate(ev2) is False,
          "impossible-travel: second login from the SAME country must not fire")

    # Same account, now a DIFFERENT country (CN, 198.51.100.0/24) within the
    # window -> 2 distinct countries -> MUST fire.
    ev3 = enrich(ssh.parse(_accepted("198.51.100.5", 2, base)))
    check(ev3["src_endpoint"]["location"]["country"] == "CN",
          "REAL enrichment must resolve 198.51.100.5 to CN (per geoip.yml sample data)")
    check(rule.evaluate(ev3) is True,
          "impossible-travel: a second DISTINCT country within the window MUST fire")

    # A different account entirely, one login, must not fire (fresh window state).
    rule2 = rule_by_id(load_rules(RULES_DIR), IMPOSSIBLE_TRAVEL_ID)
    other = enrich(ssh.parse({
        "raw": "Jun 10 14:00:00 db01 sshd[2160]: Accepted publickey for other from 203.0.113.20 port 50022 ssh2",
        "meta": {"received_at": base + 200, "ingest_id": "travel-other"}}))
    check(rule2.evaluate(other) is False,
          "impossible-travel: a single login for a different account must not fire")


def main():
    run()
    if FAILS:
        print(f"[FAIL] v0.4 new rules: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] impossible-travel fires correctly on REAL parser + enrichment output")


if __name__ == "__main__":
    main()
