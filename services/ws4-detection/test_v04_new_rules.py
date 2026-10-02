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
from parsers import _REGISTRY  # noqa: E402
from parsers.dns_query import parent_domain  # noqa: E402
from parsers.linux_ssh import LinuxSshParser  # noqa: E402
from enrichment import enrich  # noqa: E402
from scoring import Scorer  # noqa: E402

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

    # REGRESSION (2026-10-01, found by the it_intrusion storyline): an internal
    # address resolves to the sentinel country "ZZ" (geoip.yml: RFC1918 ->
    # ZZ, documented as "can never be mistaken for a genuine country in a
    # distinct-country count"). The rule used to COUNT it, so the most ordinary
    # pattern there is -- the same account seen from a public address and then
    # from an internal one (VPN, jump host, a pivot) -- scored as "two
    # countries" and raised a HIGH impossible-travel alert.
    rule_zz = rule_by_id(load_rules(RULES_DIR), IMPOSSIBLE_TRAVEL_ID)
    ext = enrich(ssh.parse(_accepted("203.0.113.5", 10, base)))        # RU
    internal = enrich(ssh.parse(_accepted("10.50.0.46", 11, base)))    # ZZ (RFC1918)
    check(internal["src_endpoint"]["location"]["country"] == "ZZ",
          "REAL enrichment must resolve an RFC1918 address to the ZZ sentinel")
    check(rule_zz.evaluate(ext) is False, "impossible-travel: public login alone must not fire")
    check(rule_zz.evaluate(internal) is False,
          "impossible-travel: public-then-INTERNAL login is not travel; the ZZ sentinel "
          "must not count as a second country")
    # ...and ZZ must not mask a genuine second country either: public RU, internal ZZ,
    # then public CN is still two real countries -> must fire.
    cn = enrich(ssh.parse(_accepted("198.51.100.9", 12, base)))
    check(rule_zz.evaluate(cn) is True,
          "impossible-travel: two REAL countries must still fire when an internal login "
          "sits between them")

    # A different account entirely, one login, must not fire (fresh window state).
    rule2 = rule_by_id(load_rules(RULES_DIR), IMPOSSIBLE_TRAVEL_ID)
    other = enrich(ssh.parse({
        "raw": "Jun 10 14:00:00 db01 sshd[2160]: Accepted publickey for other from 203.0.113.20 port 50022 ssh2",
        "meta": {"received_at": base + 200, "ingest_id": "travel-other"}}))
    check(rule2.evaluate(other) is False,
          "impossible-travel: a single login for a different account must not fire")


# --------------------------------------------------------------------------
# Rule-noise review findings (2026-10-02): three pooled / allowlist-first rules
# that shipped noisier than their sibling signals warranted.
# --------------------------------------------------------------------------
BRUTE_PER_SOURCE = "6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c01"
BRUTE_BY_ACCOUNT = "d83b71c3-93eb-439f-86f9-5985ebcc38cb"
DNS_TUNNEL_BY_DOMAIN = "5f3c9d18-72a4-4e0b-b6d1-8c2e7a4f1b93"
OPCUA_UNAUTHORIZED = "e7a14b6d-3c52-4d90-8f1b-5a9c0d2e6b47"
OT_CONFIG_CHANGE = "6f708192-a314-4cd2-ad4e-5f6a7b8c9d01"
OT_OUTSIDE_MAINT = "4d5e6f70-8192-49b0-8b2c-3d4e5f6a7b8e"
T_NIGHT = 1_751_500_000_000     # Thu 2025-07-03 00:26 UTC (outside 08:00-18:00)
T_HOURS = 1_751_536_800_000     # Thu 2025-07-03 10:00 UTC (inside business hours)


def _scorer() -> Scorer:
    return Scorer(ROOT / "contracts" / "scoring.yaml")


def _ev(source_type, raw, i, t_ms):
    meta = {"received_at": t_ms, "ingest_id": f"noise-{source_type}-{i}", "tenant_id": "acme"}
    ev = _REGISTRY[source_type].parse({"source_type": source_type, "raw": raw, "meta": meta})
    assert ev is not None, (source_type, raw)
    return enrich(ev)


def _fired_ids(events):
    """ids of every rule that fires on ANY event of the stream (fresh rule
    instances, so window state is not shared with another stream)."""
    rules = load_rules(RULES_DIR)
    ids = set()
    for e in events:
        for r in rules:
            if r.evaluate(e):
                ids.add(r.id)
    return ids


def run_bruteforce_by_account_noise():
    """FINDING 2. common_bruteforce_by_account pools every source and host, so
    ambient internet spraying of root/admin crosses 10/60s fleet-wide. It used to
    be level high (severity floor 70 >= llm_min 60), i.e. EVERY ambient burst paid
    an LLM triage call. It must still FIRE (the 2-address evasion it closes is
    asserted end to end by test_companion_rules / evasion_search) but must not
    reach the LLM funnel on its own."""
    sc = _scorer()
    rules = load_rules(RULES_DIR)
    by_acct = rule_by_id(rules, BRUTE_BY_ACCOUNT)
    per_src = rule_by_id(rules, BRUTE_PER_SOURCE)
    # ambient spray: 12 failed root logons from 12 DIFFERENT scanners inside 60 s
    spray = [_ev("linux_ssh",
                 f"Jun 10 13:55:{i:02d} db01 sshd[{3000 + i}]: Failed password for root "
                 f"from 198.51.100.{10 + i} port {41000 + i} ssh2", i, T_NIGHT + i * 4_000)
             for i in range(12)]
    fired = _fired_ids(spray)
    check(BRUTE_BY_ACCOUNT in fired, "ambient spray: the pooled by-account rule still fires (detection kept)")
    check(BRUTE_PER_SOURCE not in fired,
          "ambient spray: each scanner sent 1 attempt, so the per-source rule stays silent (precondition)")
    action = sc.route(sc.routing_score([by_acct]))
    check(action != "llm",
          f"ambient spray alone must not pay an LLM triage call (routed {action!r}, "
          f"score {sc.score([by_acct])})")
    check(action == "classifier",
          "ambient spray alone is still indexed AND classifier-scored, never silently dropped "
          f"(routed {action!r})")

    # a genuine single-source brute force is unchanged: the per-source sibling keeps its
    # LLM routing (main.py drops the companion when the sibling matched the same event).
    check(sc.route(sc.routing_score([per_src])) == "llm",
          "a single-source brute force keeps LLM triage (per-source rule unchanged)")

    # the evasion the companion exists for is still detected: 12 failures, 2 addresses
    ips = ["203.0.113.21", "192.0.2.44"]
    split = [_ev("linux_ssh",
                 f"Jun 10 13:55:{i:02d} db01 sshd[{2000 + i}]: Failed password for deploy "
                 f"from {ips[i % 2]} port {51000 + i} ssh2", i, T_NIGHT + i * 3_000) for i in range(12)]
    fired2 = _fired_ids(split)
    check(BRUTE_BY_ACCOUNT in fired2 and BRUTE_PER_SOURCE not in fired2,
          "2-address split: still invisible to the sibling, still caught by the by-account rule")


def run_dns_tunnel_allowlist():
    """FINDING 3. common_dns_tunnel_by_domain pools every client; a CDN / update /
    SaaS parent legitimately serves 40+ distinct names a minute. Suppression is
    wired through a shipped, documented allowlist; an attacker-registered parent
    is never on it, so the 2-host evasion it closes stays closed."""
    import yaml

    al_path = ROOT / "contracts" / "allowlists" / "dns_high_cardinality_parents.yml"
    check(al_path.exists(), "dns_high_cardinality_parents.yml ships with the repo")
    entries: list = []
    if al_path.exists():
        entries = (yaml.safe_load(al_path.read_text(encoding="utf-8")) or {}).get("entries") or []
    check(len(entries) >= 5, "the allowlist ships a small starter set, not an empty file")
    # An entry the parser can never emit would silently never match: every entry
    # must already be in the exact form dns_query.parent_domain() produces.
    bad = [e for e in entries if not isinstance(e, str) or parent_domain(e) != e]
    check(not bad, f"every allowlist entry must equal parent_domain(entry) (lower-case registered domain): {bad}")
    check("akamaiedge.net" in entries and "cloudfront.net" in entries,
          "the starter set covers the common CDN edge zones")

    clients = ["10.50.0.46", "10.50.0.47"]

    def burst(parent):
        return [_ev("dns_query", f"query[A] e{i:03d}.edge.{parent} from {clients[i % 2]}", i, T_NIGHT + i * 1_000)
                for i in range(48)]

    # the attacker's shape (parent owned by the attacker, invalid TLD) still fires
    check(DNS_TUNNEL_BY_DOMAIN in _fired_ids(burst("exfil.example.invalid")),
          "attacker-registered parent split over 2 clients: still detected (evasion stays closed)")
    # a well-known CDN parent is suppressed ...
    check(DNS_TUNNEL_BY_DOMAIN not in _fired_ids(burst("akamaiedge.net")),
          "48 distinct names under allowlisted CDN parent akamaiedge.net must not raise a tunnel alert")
    # ... and the suppression is exact-parent, not 'anything that resembles it'
    check(DNS_TUNNEL_BY_DOMAIN in _fired_ids(burst("akamaiedge-cdn.invalid")),
          "a look-alike parent is NOT suppressed")
    check(DNS_TUNNEL_BY_DOMAIN in _fired_ids(burst("akamaiedge.net.exfil.invalid")),
          "an allowlisted name used as a SUB-label of an attacker's parent is NOT suppressed")


def run_opcua_overlap():
    """FINDING 4. ot_opcua_write_unauthorized_node carried score_weight 50 on top of
    the two older OT-write rules that match the SAME event, so one config write went
    70 -> 100 purely from the overlap. It must add no weight of its own (its level
    floor still scores it when it fires alone), and its metadata must not claim
    'stable' for a rule that is noise until the allowlist is populated."""
    import yaml

    sc = _scorer()
    raw_cfg = yaml.safe_load((RULES_DIR / "ot_opcua_write_unauthorized_node.yml").read_text(encoding="utf-8"))
    check(raw_cfg.get("status") != "stable",
          "an allowlist-first rule that is noise until the allowlist is populated must not be status: stable")
    check(int(raw_cfg["siem"].get("score_weight", 0)) == 0,
          "ot_opcua_write_unauthorized_node must add no weight of its own (overlaps two older OT-write rules)")

    def write(node, t_ms, i):
        return _ev("opcua_audit", {"eventType": "AuditWriteUpdateEventType", "clientUserId": "ot-engineer",
                                   "clientAddress": "10.20.0.50", "serverId": "opcua-line3",
                                   "nodeId": node, "status": "Success", "time": t_ms}, i, t_ms)

    cases = {
        # in-hours config-marker write: ot_config_change (60 -> floor 70) also matches
        "in-hours config write": (write("ns=2;s=Line3/TankLevelSetpoint", T_HOURS, 0), OT_CONFIG_CHANGE),
        # out-of-hours ordinary write: ot_write_outside_maintenance (65 -> floor 70) also matches
        "out-of-hours write": (write("ns=2;s=Line3/PumpEnable", T_NIGHT, 1), OT_OUTSIDE_MAINT),
    }
    for label, (ev, older) in cases.items():
        matched = [r for r in load_rules(RULES_DIR) if r.evaluate(ev)]
        ids = {r.id for r in matched}
        check(OPCUA_UNAUTHORIZED in ids and older in ids,
              f"{label}: precondition -- the new rule AND the older OT rule both match "
              f"({sorted(i[:8] for i in ids)})")
        without = [r for r in matched if r.id != OPCUA_UNAUTHORIZED]
        check(sc.score(matched) == sc.score(without),
              f"{label}: the overlap must not inflate the score ({sc.score(without)} -> {sc.score(matched)})")
    # alone (the in-hours ordinary write nothing else sees) it still scores its medium floor
    alone = [r for r in load_rules(RULES_DIR) if r.evaluate(write("ns=2;s=Line3/PumpEnable", T_HOURS, 2))]
    check([r.id for r in alone] == [OPCUA_UNAUTHORIZED],
          f"in-hours ordinary write: only the new rule matches ({[r.id[:8] for r in alone]})")
    check(sc.score(alone) == 40 and sc.route(sc.routing_score(alone)) == "classifier",
          f"alone it keeps its medium floor (40) and stays out of the LLM funnel (score {sc.score(alone)})")


def main():
    run()
    run_bruteforce_by_account_noise()
    run_dns_tunnel_allowlist()
    run_opcua_overlap()
    if FAILS:
        print(f"[FAIL] v0.4 new rules: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] impossible-travel fires on REAL parser + enrichment output; rule-noise controls "
          "(by-account routing, DNS parent allowlist, OPC UA overlap) hold")


if __name__ == "__main__":
    main()
