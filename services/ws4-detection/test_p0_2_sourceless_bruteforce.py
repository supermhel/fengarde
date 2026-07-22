"""P0-2 new-rule firing test: common_bruteforce_sourceless.

Loads the REAL rule YAML and feeds it events shaped exactly as the REAL
active_directory parser emits for Windows 4625 (failed logon) with no
IpAddress -- the shape live-proven on real attack data (Splunk attack_data
T1110.003 purplesharp "invalid_users"/"disabled_users" datasets: 50+ distinct
accounts failing against one host, IpAddress="-").

Proves:
  - N distinct accounts failing against ONE host within the window fires.
  - The same event repeated (one account only) does NOT fire (distinct-count
    gate, not raw event count).
  - Two DIFFERENT target hosts each below threshold do NOT pool together into
    one false alert -- grouping is on the real hostname value, not a shared
    None/placeholder bucket.

Run: python services/ws4-detection/test_p0_2_sourceless_bruteforce.py
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
from parsers.active_directory import ActiveDirectoryParser  # noqa: E402

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


RULE_ID = "8c2f5a91-4d16-4e8b-9c3a-1f6b2e7d5a83"


def _sourceless_failed_logon(user: str, computer: str, i: int, base: int):
    """Shaped exactly like the real Splunk purplesharp 4625 records: no
    IpAddress field at all (not even "-"; the AD parser's valid_ip() returns
    None for either shape), a distinct TargetUserName per attempt, one
    Computer (the target host)."""
    return {
        "raw": {
            "EventID": 4625,
            "TimeCreated": base + i,
            "TargetUserName": user,
            "TargetDomainName": "ATTACKRANGE",
            "Computer": computer,
        },
        "meta": {"received_at": base + i, "ingest_id": f"sourceless-{computer}-{i}"},
    }


def run():
    ad = ActiveDirectoryParser()
    base = 1_750_000_000

    rules = load_rules(RULES_DIR)
    rule = rule_by_id(rules, RULE_ID)
    check(rule.stateful and rule.group_by == "src_endpoint.hostname"
          and rule.distinct_field == "actor.user.name",
          "common_bruteforce_sourceless must be stateful, grouped on "
          "src_endpoint.hostname, distinct on actor.user.name")

    host = "win-host-mvelazco-02713-447.attackrange.local"

    # Sanity: the real parser must actually produce this shape (no
    # src_endpoint.ip, but src_endpoint.hostname populated from Computer).
    ev0 = ad.parse(_sourceless_failed_logon("probe_user", host, 0, base))
    check(ev0 is not None, "active_directory parser must accept a sourceless 4625")
    check("ip" not in ev0.get("src_endpoint", {}),
          "sourceless 4625 must NOT carry src_endpoint.ip (that's the whole point)")
    check(ev0.get("src_endpoint", {}).get("hostname") == host,
          "active_directory parser must map Computer -> src_endpoint.hostname "
          "when WorkstationName is absent")

    # 4 distinct accounts against ONE host: below threshold (5) -> no fire yet.
    r1 = rule_by_id(load_rules(RULES_DIR), RULE_ID)
    fired = False
    for i, user in enumerate(["alice", "bob", "carol", "dave"]):
        ev = ad.parse(_sourceless_failed_logon(user, host, i, base))
        fired = r1.evaluate(ev) or fired
    check(not fired, "4 distinct accounts against one host must stay below "
                      "the threshold-5 distinct-count gate")

    # 5th distinct account crosses the threshold -> MUST fire.
    ev5 = ad.parse(_sourceless_failed_logon("erin", host, 4, base))
    check(r1.evaluate(ev5) is True,
          "5th distinct account against the same host within the window MUST fire "
          "(the real live-proven shape: purplesharp sprays 50 distinct accounts "
          "against one host with no source IP)")

    # Same account repeated 5x (not distinct) must NOT fire -- proves this is a
    # distinct-count gate, not a raw event-count gate.
    r2 = rule_by_id(load_rules(RULES_DIR), RULE_ID)
    fired2 = False
    for i in range(6):
        ev = ad.parse(_sourceless_failed_logon("mallory", host, i, base))
        fired2 = r2.evaluate(ev) or fired2
    check(not fired2, "one account repeatedly failing is not this rule's shape "
                       "(common_bruteforce.yml/password_spray.yml own that) -- "
                       "distinct-count must stay at 1 and never fire")

    # Two DIFFERENT target hosts, each under threshold, must NOT pool into one
    # alert (grouping on a real field value, not a shared placeholder bucket).
    r3 = rule_by_id(load_rules(RULES_DIR), RULE_ID)
    fired3 = False
    for i, user in enumerate(["u1", "u2", "u3"]):
        ev = ad.parse(_sourceless_failed_logon(user, "host-a.local", i, base))
        fired3 = r3.evaluate(ev) or fired3
    for i, user in enumerate(["u4", "u5", "u6"]):
        ev = ad.parse(_sourceless_failed_logon(user, "host-b.local", 10 + i, base))
        fired3 = r3.evaluate(ev) or fired3
    check(not fired3,
          "3 distinct accounts against host-a plus 3 against host-b must NOT pool "
          "into one shared bucket -- each host's distinct-count (3) stays below "
          "threshold-5 independently")

    if FAILS:
        print(f"\n[FAIL] common_bruteforce_sourceless: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] common_bruteforce_sourceless (P0-2) firing tests PASS")


if __name__ == "__main__":
    run()
