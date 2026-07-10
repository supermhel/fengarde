"""End-to-end-ish tests for the distinct-count rules (port scan, lateral movement).

Loads the REAL rule YAMLs from contracts/rules/ and feeds synthetic OCSF events
through Rule.evaluate(), asserting each rule fires AT the threshold of distinct
values and does NOT fire below it. Also confirms the brute-force rule (plain count)
is unaffected. Zero infra (default in-process deque counter).

Run: C:/Python313/python.exe services/ws4-detection/test_engine_distinct_rules.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))

from engine import load_rules  # noqa: E402

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


PORT_SCAN_ID = "1d2c3b4a-5e6f-4708-8a91-0b1c2d3e4f05"
LATERAL_ID = "2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061"
BRUTEFORCE_ID = "6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c01"


def net_event(src, port, t, ingest, activity_id=6):
    # activity_id 6 = Deny (what the port-scan rule keys on); 7 = Accept.
    return {
        "class_uid": 4001, "activity_id": activity_id, "time": t,
        "src_endpoint": {"ip": src},
        "dst_endpoint": {"ip": "10.0.0.1", "port": port},
        "siem": {"ingest_id": ingest},
    }


def auth_event(user, dst_host, t, ingest):
    return {
        "class_uid": 3002, "activity_id": 1, "status": "Success", "time": t,
        "actor": {"user": {"name": user}},
        "src_endpoint": {"ip": "192.168.1.50"},
        "dst_endpoint": {"hostname": dst_host},
        "siem": {"ingest_id": ingest},
    }


def run():
    rules = load_rules(RULES_DIR)

    # ---- PORT SCAN: 15 distinct ports fires; 14 does not ----
    ps = rule_by_id(rules, PORT_SCAN_ID)
    check(ps.stateful and ps.distinct_field == "dst_endpoint.port",
          "port-scan rule should be stateful distinct on dst_endpoint.port")
    base = 1_750_000_000_000
    fired = [ps.evaluate(net_event("203.0.113.9", 1000 + i, base + i * 100, f"ps{i}"))
             for i in range(15)]
    check(fired[:14] == [False] * 14, "port scan: first 14 distinct ports must NOT fire")
    check(fired[14] is True, "port scan: 15th distinct port MUST fire")

    # below threshold: a different IP hitting only 14 distinct ports never fires
    fired2 = [ps.evaluate(net_event("203.0.113.10", 2000 + i, base + i * 100, f"q{i}"))
              for i in range(14)]
    check(not any(fired2), "port scan: 14 distinct ports must NOT fire")

    # repeats of the SAME port don't trip it (would under a plain count)
    ps2 = rule_by_id(load_rules(RULES_DIR), PORT_SCAN_ID)
    rep = [ps2.evaluate(net_event("198.51.100.7", 22, base + i * 100, f"r{i}"))
           for i in range(30)]
    check(not any(rep), "port scan: 30 hits on ONE port must NOT fire (distinct, not count)")

    # precision: ACCEPTED connections (activity 7) to 15 distinct ports must NOT fire
    # -- the rule keys on denies only, so a legit multi-port app is not a scan.
    ps3 = rule_by_id(load_rules(RULES_DIR), PORT_SCAN_ID)
    acc = [ps3.evaluate(net_event("203.0.113.11", 3000 + i, base + i * 100, f"a{i}",
                                  activity_id=7))
           for i in range(15)]
    check(not any(acc), "port scan: 15 ACCEPTED distinct ports must NOT fire (denies only)")

    # REGRESSION GUARD: fire on events as the REAL Cisco ASA parser emits them --
    # 15 denied connections from one src to 15 distinct dst ports.
    sys.path.insert(0, str(ROOT / "services"))                    # for `shared`
    sys.path.insert(0, str(ROOT / "services" / "ws2-normalization"))  # for `parsers`
    from parsers.cisco_asa import CiscoAsaParser  # noqa: E402
    asa = CiscoAsaParser()
    ps4 = rule_by_id(load_rules(RULES_DIR), PORT_SCAN_ID)
    asa_fired = []
    for i in range(15):
        line = (f"%ASA-4-106023: Deny tcp src outside:203.0.113.5/51000 "
                f"dst inside:10.0.0.10/{2000 + i} by access-group acl_out")
        ev = asa.parse({"raw": line, "meta": {"received_at": 1_750_000_000 + i,
                                              "ingest_id": f"asa-{i}"}})
        asa_fired.append(ps4.evaluate(ev))
    check(asa_fired[:14] == [False] * 14 and asa_fired[14] is True,
          "port scan (REAL ASA parser): 15 distinct denied ports MUST fire")

    # ...and the bare "from IP/port to IP/port" deny syntax (106001/106006/106015),
    # which older endpoint regexes dropped entirely (src/dst = None -> rule blind).
    ps5 = rule_by_id(load_rules(RULES_DIR), PORT_SCAN_ID)
    ft_fired = []
    for i in range(15):
        line = (f"%ASA-2-106001: Inbound TCP connection denied from 203.0.113.7/40000 "
                f"to 10.0.0.20/{3000 + i} flags SYN on interface outside")
        ev = asa.parse({"raw": line, "meta": {"received_at": 1_750_000_000 + i,
                                              "ingest_id": f"ft-{i}"}})
        ft_fired.append(ps5.evaluate(ev))
    check(ft_fired[:14] == [False] * 14 and ft_fired[14] is True,
          "port scan (REAL ASA parser, from/to deny): 15 distinct denied ports MUST fire")

    # ---- LATERAL MOVEMENT: 5 distinct hosts fires; 4 does not ----
    lm = rule_by_id(rules, LATERAL_ID)
    check(lm.group_by == "actor.user.name" and lm.distinct_field == "dst_endpoint.hostname",
          "lateral rule should group by user, distinct on dst_endpoint.hostname")
    lf = [lm.evaluate(auth_event("alice", f"host-{i}", base + i * 1000, f"lm{i}"))
          for i in range(5)]
    check(lf[:4] == [False] * 4, "lateral: first 4 distinct hosts must NOT fire")
    check(lf[4] is True, "lateral: 5th distinct host MUST fire")

    lm2 = rule_by_id(load_rules(RULES_DIR), LATERAL_ID)
    lf2 = [lm2.evaluate(auth_event("bob", f"other-{i}", base + i * 1000, f"b{i}"))
           for i in range(4)]
    check(not any(lf2), "lateral: 4 distinct hosts must NOT fire")

    # failed logins (activity 4) must NOT match the success-only lateral rule
    lm3 = rule_by_id(load_rules(RULES_DIR), LATERAL_ID)
    bad = auth_event("carol", "srv-5", base, "c0")
    bad["activity_id"] = 4
    bad["status"] = "Failure"
    check(lm3.evaluate(bad) is False, "lateral: failed auth must NOT match")

    # --- REGRESSION GUARD: the rule must fire on events as the REAL Windows parser
    # emits them (this is the gap the synthetic tests missed: the parser must put the
    # target host on dst_endpoint.hostname, not src_endpoint). Feed 5 successful 4624
    # logons by one account to 5 distinct Computers through the actual parser. ---
    sys.path.insert(0, str(ROOT / "services"))                    # for `shared`
    sys.path.insert(0, str(ROOT / "services" / "ws2-normalization"))  # for `parsers`
    from parsers.windows_eventlog import WindowsEventLogParser  # noqa: E402
    wparser = WindowsEventLogParser()
    lm4 = rule_by_id(load_rules(RULES_DIR), LATERAL_ID)
    e2e = []
    for i in range(5):
        raw = {"raw": {"EventID": 4624, "TargetUserName": "dave",
                       "Computer": f"win-host-{i}", "IpAddress": "10.9.9.9",
                       "TimeCreated": base + i * 1000},
               "meta": {"ingest_id": f"w4624-{i}"}}
        ev = wparser.parse(raw)
        e2e.append(lm4.evaluate(ev))
    check(e2e[:4] == [False] * 4 and e2e[4] is True,
          "lateral (REAL parser): 5 distinct Windows logon targets MUST fire")

    # ---- BRUTE FORCE unchanged: plain count of 10 failed auths fires ----
    bf = rule_by_id(rules, BRUTEFORCE_ID)
    check(bf.stateful and bf.distinct_field is None,
          "brute-force must remain a plain-count rule (no distinct_field)")
    bff = []
    for i in range(10):
        e = {"class_uid": 3002, "activity_id": 4, "time": base + i * 1000,
             "src_endpoint": {"ip": "203.0.113.99"},
             "siem": {"ingest_id": f"bf{i}"}}
        bff.append(bf.evaluate(e))
    check(bff[:9] == [False] * 9, "brute force: first 9 must NOT fire")
    check(bff[9] is True, "brute force: 10th failed auth MUST fire (count unchanged)")

    # ---- v0.4 fix: unattributable events must NOT count (None group/distinct) ----
    # (a) events MISSING the group_by field never fire and never pollute a real
    # group's counter -- previously they all pooled under one shared "None" key.
    bf2 = rule_by_id(load_rules(RULES_DIR), BRUTEFORCE_ID)
    for i in range(20):  # 2x threshold -- would fire if pooled under "None"
        e = {"class_uid": 3002, "activity_id": 4, "time": base + i * 1000,
             "siem": {"ingest_id": f"nogroup{i}"}}  # no src_endpoint at all
        check(bf2.evaluate(e) is False,
              "brute force: an event with NO group_by field must never fire")
    # a real group is unaffected by the unattributable stream above
    real = []
    for i in range(10):
        e = {"class_uid": 3002, "activity_id": 4, "time": base + i * 1000,
             "src_endpoint": {"ip": "203.0.113.77"},
             "siem": {"ingest_id": f"real{i}"}}
        real.append(bf2.evaluate(e))
    check(real[9] is True, "brute force: a real group still fires at threshold "
                           "after unattributable events were rejected")

    # (b) a None DISTINCT value must not count as a distinct value -- previously
    # the memory backend counted None as one value and the Redis backend turned
    # EVERY None-valued event into a fresh distinct member (str(now_ms)).
    ps6 = rule_by_id(load_rules(RULES_DIR), PORT_SCAN_ID)
    for i in range(30):  # well past threshold -- would fire on Redis semantics
        e = {"class_uid": 4001, "activity_id": 6, "time": base + i * 100,
             "src_endpoint": {"ip": "198.51.100.9"},
             "dst_endpoint": {"ip": "10.0.0.1"},  # NO port -> distinct value None
             "siem": {"ingest_id": f"noport{i}"}}
        check(ps6.evaluate(e) is False,
              "port scan: events with a None distinct value must never fire")


def main():
    run()
    if FAILS:
        print(f"[FAIL] distinct rules: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] port-scan + lateral-movement rules + brute-force unchanged PASS")


if __name__ == "__main__":
    main()
