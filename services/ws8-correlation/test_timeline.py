"""WS-8 timeline view (owner decision WS-8 option B, 2026-10-14): an incident's
member alerts in time order -- and, as important, what it must NOT claim.

Run: python services/ws8-correlation/test_timeline.py
"""
from __future__ import annotations

import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from timeline import build_timeline  # noqa: E402

FAILS: list = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def inc(members, tenant="acme", iid="acme:actor:deploy:0"):
    return {"incident_id": iid, "tenant_id": tenant, "member_alert_ids": list(members)}


def alert(aid, t, rule="r", tactic=None, tenant="acme"):
    a = {"alert_id": aid, "time": t, "rule_id": rule, "tenant_id": tenant}
    if tactic:
        a["mitre"] = {"tactic": tactic}
    return a


def run():
    # 1. order by time, tactic order by first appearance
    alerts = [alert("a3", 3000, "r3", "TA0010"), alert("a1", 1000, "r1", "TA0007"),
              alert("a2", 2000, "r2", "TA0006")]
    tl = build_timeline(inc(["a1", "a2", "a3"]), alerts)
    check([s["alert_ids"] for s in tl["steps"]] == [["a1"], ["a2"], ["a3"]],
          f"steps must follow alert time, got {tl['steps']}")
    check(tl["tactic_order"] == ["TA0007", "TA0006", "TA0010"], f"tactic order: {tl['tactic_order']}")

    # 2. a TIE is one step, never an arbitrary order
    tl = build_timeline(inc(["x", "y"]), [alert("y", 500, "ry"), alert("x", 500, "rx")])
    check(len(tl["steps"]) == 1 and tl["steps"][0]["alert_ids"] == ["x", "y"],
          f"two alerts at the same instant must be ONE step, got {tl['steps']}")

    # 3. no usable time -> untimed, NOT sorted to the start the way time 0 would be
    bad = [alert("n0", 0), alert("nn", None), alert("nb", True), alert("nf", float("nan")),
           alert("ok", 9000)]
    tl = build_timeline(inc(["n0", "nn", "nb", "nf", "ok"]), bad)
    check(tl["untimed"] == ["n0", "nb", "nf", "nn"] and [s["alert_ids"] for s in tl["steps"]] == [["ok"]],
          f"unusable times must be listed as untimed, got untimed={tl['untimed']} steps={tl['steps']}")

    # 4. only MEMBERS are used: a caller cannot smuggle an alert into the story
    tl = build_timeline(inc(["m1"]), [alert("m1", 10), alert("intruder", 5)])
    check([s["alert_ids"] for s in tl["steps"]] == [["m1"]], "a non-member alert must be ignored")

    # 5. tenant isolation: a member id under ANOTHER tenant is dropped and counted, not missing
    tl = build_timeline(inc(["t1", "t2", "gone"]),
                        [alert("t1", 10), alert("t2", 20, tenant="globex")])
    check([s["alert_ids"] for s in tl["steps"]] == [["t1"]] and tl["foreign_tenant_dropped"] == 1
          and tl["missing_alert_ids"] == ["gone"],
          f"foreign-tenant alert dropped+counted, absent one missing: {tl}")

    # 6. redelivered duplicates of one alert_id: one entry, earliest usable time
    tl = build_timeline(inc(["d"]), [alert("d", 70), alert("d", 40), alert("d", None)])
    check([(s["time"], s["alert_ids"]) for s in tl["steps"]] == [(40, ["d"])] and tl["untimed"] == [],
          f"duplicates collapse to the earliest usable time, got {tl}")

    # 7. determinism: input order never changes the result
    many = [alert(f"a{i}", (i * 7) % 13, f"r{i % 3}", f"TA000{i % 5}") for i in range(40)]
    want = build_timeline(inc([a["alert_id"] for a in many]), many)
    rng = random.Random(7)
    for _ in range(20):
        shuffled = many[:]
        rng.shuffle(shuffled)
        if build_timeline(inc([a["alert_id"] for a in many]), shuffled) != want:
            check(False, "a shuffled input changed the timeline")
            break

    # 8. hostile shapes degrade, never raise
    weird = build_timeline({"member_alert_ids": "nope"}, [None, 3, {"alert_id": 5}])
    check(weird["steps"] == [] and weird["missing_alert_ids"] == [], f"hostile input: {weird}")


def main():
    run()
    if FAILS:
        print(f"[FAIL] timeline: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WS-8 timeline: time order, ties grouped, untimed listed, members only, "
          "tenant-isolated, redelivery-idempotent, input-order independent")


if __name__ == "__main__":
    main()
