#!/usr/bin/env python3
"""Zero-infra test for tools/chaos_test.py's alert query/filter logic.

`make chaos` must be re-runnable against a persistent OpenSearch: alerts left by
an earlier run (same fixed attacker IP, different window bucket) must NOT count
as duplicates, while a real duplicate inside this run must still be reported.
A fake transport evaluates the generated query against in-memory docs.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import redis  # noqa: F401
except ImportError:  # chaos_test imports it at module level; the query logic never uses it
    import types
    sys.modules["redis"] = types.ModuleType("redis")
import chaos_test as ct  # noqa: E402


def make_search(docs):
    """Fake OpenSearch: honours bool.filter term(src_endpoint.ip) + range(time)."""
    def search(body):
        hits = []
        for d in docs:
            ok = True
            for f in body["query"]["bool"]["filter"]:
                if "term" in f:
                    ok = ok and d["src"] == f["term"]["src_endpoint.ip"]
                if "range" in f:
                    r = f["range"]["time"]
                    ok = ok and r["gte"] <= d["time"] < r["lt"]
            if ok:
                hits.append({"_id": d["id"], "_source": {"alert_id": d["alert_id"]}})
        return {"hits": {"hits": hits}}
    return search


IP = "203.0.113.1"
OLD_MIN = 1_760_400_000 // 60 * 60          # an earlier run (2026-10-14-ish)
NEW_MIN = 1_763_500_000 // 60 * 60          # this run
old = {"id": "o1", "src": IP, "time": (OLD_MIN + 9) * 1000, "alert_id": "A-old"}
new = {"id": "n1", "src": IP, "time": (NEW_MIN + 9) * 1000, "alert_id": "A-new"}

fails = 0


def check(name, cond):
    global fails
    print(("ok   " if cond else "FAIL ") + name)
    fails += 0 if cond else 1


check("old-run alert excluded; exactly one doc for this run",
      ct.alert_ids_for(IP, NEW_MIN, make_search([old, new])) == [("n1", "A-new")])

check("unscoped query sees both (regression anchor: the filter is what fixes it)",
      len(ct.alert_ids_for(IP, None, make_search([old, new]))) == 2)

dup = {"id": "n2", "src": IP, "time": (NEW_MIN + 10) * 1000, "alert_id": "A-new"}
check("same-run duplicate still reported (fail-closed)",
      len(ct.alert_ids_for(IP, NEW_MIN, make_search([old, new, dup]))) == 2)

check("old alert does not mask a lost alert",
      ct.alert_ids_for(IP, NEW_MIN, make_search([old])) == [])

adj = {"id": "a1", "src": IP, "time": (NEW_MIN + 60) * 1000 + ct.WINDOW_PAD_MS, "alert_id": "A-adj"}
check("adjacent minute excluded",
      ct.alert_ids_for(IP, NEW_MIN, make_search([adj])) == [])

sc = ct.build_scenarios()
check("scenarios carry window_start_s matching their own events",
      all(s.window_start_s is not None
          and s.window_start_s <= s.events[0]["meta"]["received_at"] < s.window_start_s + 60
          for s in sc))

sys.exit(1 if fails else 0)
