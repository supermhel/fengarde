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

    # 9. FINDING 5: campaign_id must be a stable handle -- unchanged when a pivoting attack
    #    gains an incident (it is derived from the smallest member incident id, the union-find
    #    root, not from the whole member list)
    before = link_campaigns([inc("i1", members=["a1", "a2"]), inc("i2", members=["a2", "a3"])])
    after = link_campaigns([inc("i1", members=["a1", "a2"]), inc("i2", members=["a2", "a3"]),
                            inc("i3", members=["a3", "a4"])])
    check(len(before) == 1 and len(after) == 1 and after[0]["incident_count"] == 3,
          "positive control: the third incident really joined the campaign")
    check(before[0]["campaign_id"] == after[0]["campaign_id"],
          f"campaign_id is unchanged when an incident joins: {before[0]['campaign_id']} vs {after[0]['campaign_id']}")
    check(before[0].get("merged_from") == [] and after[0].get("merged_from") == [],
          "no lineage is reported when nothing merged (and with no `previous` supplied)")
    # negative control: different roots give different ids (the id is not a constant)
    other = link_campaigns([inc("z9", members=["q"])])
    check(other[0]["campaign_id"] != before[0]["campaign_id"], "distinct campaigns have distinct ids")

    # 10. FINDING 5 residual case: two campaigns MERGE. The survivor keeps the smaller root id and the
    #     lineage (the id it replaces) is reported when the caller passes the previous view.
    prev = link_campaigns([inc("a", members=["1"]), inc("b", members=["1"]),
                           inc("m", members=["7"]), inc("n", members=["7"])])
    id_ab = next(c["campaign_id"] for c in prev if c["incident_ids"] == ["a", "b"])
    id_mn = next(c["campaign_id"] for c in prev if c["incident_ids"] == ["m", "n"])
    bridge = [inc("a", members=["1"]), inc("b", members=["1", "7"]), inc("m", members=["7"]),
              inc("n", members=["7"])]
    merged = link_campaigns(bridge, previous=prev)
    check(len(merged) == 1 and merged[0]["incident_ids"] == ["a", "b", "m", "n"],
          "the bridge merges the two campaigns")
    check(merged[0]["campaign_id"] == id_ab, "the survivor keeps the campaign id of the smaller root (a)")
    check(merged[0].get("merged_from") == [id_mn],
          f"lineage names the absorbed campaign, got {merged[0].get('merged_from')}")
    # order independence still holds with a previous view, and previous never changes the id
    rng2 = random.Random(3)
    sh = list(bridge)
    rng2.shuffle(sh)
    check(link_campaigns(sh, previous=list(reversed(prev))) == merged,
          "result (incl. merged_from) is order-independent")
    check(link_campaigns(bridge)[0]["campaign_id"] == merged[0]["campaign_id"],
          "`previous` is lineage only; it never changes the id")
    # the other residual: a joiner whose id sorts LOWER becomes the new root. The id moves, but the
    # old id is reported, so a persisted handle can be re-pointed.
    old_view = link_campaigns([inc("a2", members=["x"]), inc("b2", members=["x"])])
    old = old_view[0]["campaign_id"]
    joiner = link_campaigns([inc("a2", members=["x"]), inc("b2", members=["x"]),
                             inc("a1", members=["x", "y"])], previous=old_view)
    check(len(joiner) == 1 and joiner[0]["campaign_id"] != old and joiner[0].get("merged_from") == [old],
          f"a lower-sorting joiner moves the id but reports the old one, got {joiner}")
    # malformed previous is ignored, not fatal
    junk_prev = [None, 3, {"campaign_id": 5}, {"incident_ids": "x"},
                 {"campaign_id": "c", "incident_ids": [1, None]}]
    check(link_campaigns(bridge, previous=junk_prev)[0].get("merged_from") == [],
          "malformed `previous` entries are ignored")

    # 11. FINDING 6a: never silently truncate. Past the old 50_000 cap, every incident is still linked.
    n = 50_050
    big = [inc(f"b{i:06d}", members=["hub"]) for i in range(n)]
    out = link_campaigns(big)
    check(len(out) == 1 and out[0]["incident_count"] == n and len(out[0]["incident_ids"]) == n,
          f"no incident is dropped past the old cap, got {[c['incident_count'] for c in out]}")

    # 12. FINDING 6b: an incident with no tenant must not be pooled with other tenant-less incidents,
    #     nor linked to a tenanted one, even when they share an alert.
    for bad in (None, "", "   ", 7):
        pair = [inc("u1", tenant=bad, members=["shared"]), inc("u2", tenant=bad, members=["shared"])]
        out = link_campaigns(pair)
        check(len(out) == 2 and all(c["incident_count"] == 1 for c in out),
              f"tenant={bad!r}: tenant-less incidents sharing an alert are NOT linked, "
              f"got {[c['incident_ids'] for c in out]}")
        check(all(c.get("untenanted") is True and c["tenant_id"] == "" for c in out),
              f"tenant={bad!r}: marked untenanted")
    mixed = link_campaigns([inc("u1", tenant=None, members=["shared"]),
                            inc("t1", tenant="acme", members=["shared"])])
    check(len(mixed) == 2, "a tenant-less incident does not link to a tenanted one via a shared alert")
    check([c.get("untenanted") for c in link_campaigns([inc("t1", tenant="acme", members=["x"])])] == [False],
          "negative control: a tenanted incident is not marked untenanted")
    ids = {c["campaign_id"] for c in link_campaigns([inc("u1", tenant=None), inc("u2", tenant=None)])}
    check(len(ids) == 2, "tenant-less singletons still get distinct campaign ids")


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
