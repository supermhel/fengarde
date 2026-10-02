"""WS-8 campaign view: shared-ALERT linking, and -- as important -- what it must
NOT link.

Run: python services/ws8-correlation/test_campaigns.py
"""
from __future__ import annotations

import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from campaigns import link_campaigns  # noqa: E402

FAILS: list = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def inc(iid, tenant="acme", members=(), etype="ip", evalue="x", tactics=()):
    return {"incident_id": iid, "tenant_id": tenant, "member_alert_ids": list(members),
            "entity_type": etype, "entity_value": evalue, "tactics": list(tactics)}


def run():
    # 1. THE POINT: a pivot is a chain of shared alerts (attacker ip - account - foothold ip)
    pivot = [
        inc("i1", members=["a1", "a2", "a3"], etype="ip", evalue="203.0.113.21", tactics=["TA0007"]),
        inc("i2", members=["a3", "a4", "a5"], etype="actor", evalue="deploy", tactics=["TA0006"]),
        inc("i3", members=["a5", "a6"], etype="ip", evalue="10.50.0.46", tactics=["TA0008"]),
    ]
    out = link_campaigns(pivot)
    check(len(out) == 1 and out[0]["incident_ids"] == ["i1", "i2", "i3"],
          f"a chain of shared alerts is ONE campaign, got {[c['incident_ids'] for c in out]}")
    check(out[0]["tactics"] == ["TA0006", "TA0007", "TA0008"], "campaign carries the union of tactics")
    check(out[0]["incident_count"] == 3 and len(out[0]["member_alert_ids"]) == 6,
          "campaign carries the union of member alerts")

    # 2. THE NAT CASE: two unrelated users whose incidents merely share an address
    #    (an ip TRACK) but share NO ALERT must NOT link. This is the whole reason the
    #    link is "shared alert", not "shared entity".
    apart = [inc("n1", members=["u1a", "u1b"], etype="actor", evalue="alice"),
             inc("n2", members=["u2a", "u2b"], etype="actor", evalue="bob"),
             inc("n3", members=["u3a"], etype="ip", evalue="198.51.100.1")]
    check(len(link_campaigns(apart)) == 3,
          "incidents that merely share an address/entity, with no shared ALERT, stay separate")

    # 3. tenant isolation: the SAME alert id in two tenants must never link them
    tenants = [inc("t1", tenant="acme", members=["same"]), inc("t2", tenant="globex", members=["same"])]
    out = link_campaigns(tenants)
    check(len(out) == 2 and {c["tenant_id"] for c in out} == {"acme", "globex"},
          "a shared alert id across TENANTS must not link them")

    # 4. singletons are returned (one code path for callers)
    out = link_campaigns([inc("s1", members=["x"])])
    check(len(out) == 1 and out[0]["incident_count"] == 1, "a lone incident is a campaign of one")

    # 5. determinism and input-order independence
    rng = random.Random(7)
    shuffled = list(pivot)
    rng.shuffle(shuffled)
    check(link_campaigns(pivot) == link_campaigns(shuffled), "result is independent of input order")
    check(link_campaigns(pivot)[0]["campaign_id"] == link_campaigns(shuffled)[0]["campaign_id"],
          "campaign id is derived from its members, not from arrival order")

    # 6. hostile / malformed input is skipped, never raises, never fabricates an id
    junk = [None, 5, "x", {}, {"incident_id": ""}, {"incident_id": 7},
            {"incident_id": "ok", "tenant_id": "acme", "member_alert_ids": "not-a-list"},
            {"incident_id": "ok2", "tenant_id": "acme", "member_alert_ids": [None, 3, "", "a"]}]
    out = link_campaigns(junk)
    check(sorted(i for c in out for i in c["incident_ids"]) == ["ok", "ok2"],
          f"only well-formed incidents survive, got {out}")

    # 7. two disjoint campaigns in one tenant stay two
    two = [inc("a", members=["1", "2"]), inc("b", members=["2", "3"]), inc("c", members=["9"])]
    out = link_campaigns(two)
    check(sorted(c["incident_ids"] for c in out) == [["a", "b"], ["c"]], "disjoint groups stay disjoint")

    # 8. bounded: many incidents sharing one alert is linear, not pairwise
    many = [inc(f"m{i:05d}", members=["hub", f"own{i}"]) for i in range(5000)]
    out = link_campaigns(many)
    check(len(out) == 1 and out[0]["incident_count"] == 5000, "5000 incidents through one hub alert -> one campaign")


def main():
    run()
    if FAILS:
        print(f"[FAIL] ws8 campaigns: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] ws8 campaigns: shared-alert linking, tenant isolation, no entity-only merge, deterministic")


if __name__ == "__main__":
    main()
