"""WS-8 correlation: regression tests for the 4 verified NEW-hunt findings
(2026-08-27) fixed in correlator.py.

1. NEW-hunt #1 -- metrics() nested `ws8_skipped_alerts_by_reason` is a
   non-numeric leaf, so shared/runner.py::render_prometheus (which only
   emits numeric leaves as gauges) made the skip breakdown invisible to
   /metrics/prom. Each reason must ALSO emit a flat numeric
   `ws8_skipped_reason_<reason>` key (the nested dict stays, as the /metrics
   JSON contract).
2. NEW-hunt #3 -- a skew-future / non-numeric / NaN alert `time` was trusted
   verbatim into the side-table entry, skewing first_seen (and therefore the
   incident_id horizon bucket) and eviction ordering. Must apply the same
   _valid_window_time guard WS-4's engine.py uses; a rejected value falls
   back to now_ms.
3. NEW-hunt #4 -- a fully-anonymous alert's member id used to be a
   per-instance counter (anon-seq:{n}), the ONE non-deterministic member id
   in the correlator: the same anon alert redelivered 3x (at-least-once bus)
   inflated into 3 members. It must be a deterministic hash of the payload.
4. NEW-hunt #6 -- member-cap eviction orders by each member `time` (oldest
   go first), but no test exercised it with DISTINCT timestamps where
   insertion order != time order.

Run: python services/ws8-correlation/test_correlator_new_hunt.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))

from test_contract import _Clock, _alert, _new_correlator  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


# --- NEW-hunt #1: skipped-reason breakdown must be visible to /metrics/prom ---
def test_skipped_reasons_emit_flat_numeric_metrics_keys():
    """The nested ws8_skipped_alerts_by_reason dict is a non-numeric leaf, so
    render_prometheus skips it (numeric-only gauges) and the skip breakdown
    was invisible to /metrics/prom. Each reason must ALSO emit a flat
    `ws8_skipped_reason_<reason>` numeric key. The nested dict stays, since
    test_ws5_shaped_alert_is_skipped_with_reason reads it (JSON contract)."""
    c = _new_correlator()
    c.ingest_alert({
        "alert_id": "skip1", "time": 1, "level": "medium", "score": 5,
    })  # no actor/src_endpoint/device -> no_trackable_entity
    metrics = c.metrics()
    flat = metrics.get("ws8_skipped_reason_no_trackable_entity")
    check(flat == 1 and isinstance(flat, int) and not isinstance(flat, bool),
          f"metrics: no_trackable_entity must emit a flat NUMERIC "
          f"ws8_skipped_reason_no_trackable_entity key, got {flat!r}")
    check(metrics["ws8_skipped_alerts_by_reason"].get("no_trackable_entity") == 1,
          "metrics: the nested ws8_skipped_alerts_by_reason dict must be "
          "preserved (it is the /metrics JSON contract)")

    # exercise a second reason (allowlisted shared infra) to prove the flat
    # keys are emitted per-reason, not just for the first one
    c2 = _new_correlator(allowlist_entries=["203.0.113.5"])
    c2.ingest_alert(_alert("a1", tactic="TA0001", ip="203.0.113.5"))
    m2 = c2.metrics()
    check(m2.get("ws8_skipped_reason_allowlisted_ip") == 1,
          f"metrics: allowlisted_ip reason must emit a flat numeric key, "
          f"got {m2.get('ws8_skipped_reason_allowlisted_ip')!r}")


# --- NEW finding #3: bogus alert `time` must not skew anchors/incident_id ---
def test_bogus_alert_time_is_rejected_falls_back_to_now_ms():
    """A skew-future `time` used to be trusted straight into the side-table
    entry, shifting first_seen and the incident_id horizon bucket (a 2x-future
    stamp would land the incident in a DIFFERENT bucket = forked incident).
    Non-finite/NaN is equally poisonous (would poison min/max/eviction sort).
    Both must be rejected and fall back to now_ms."""
    # horizon_s=1 -> 1000ms buckets. now_ms=1,000,000 -> bucket 1000.
    # A tampered time of 2,000,000 -> bucket 2000 (a different incident_id).
    clock = _Clock(t=1000.0)
    c = _new_correlator(horizon_s=1, now_fn=clock)
    c.ingest_alert(_alert("t1", tactic="TA0001", actor="time-user", time_ms=2_000_000))
    incs = c.ingest_alert(_alert("t2", tactic="TA0002", actor="time-user", time_ms=1_000_100))
    key = c._track_key("default", "actor", "time-user")
    side = c._sides[key]
    # the far-future alert's stored time must be now_ms, NOT 2,000,000
    check(side["t1"]["time"] == 1_000_000,
          f"time: tampered future t1 time must be rejected and fall back to "
          f"now_ms (got {side['t1']['time']})")
    check(len(incs) == 1, "time: the two-tactic track must still promote")
    if incs:
        check(incs[0]["first_seen"] == 1_000_000,
              f"time: first_seen must anchor to now_ms, not the tampered "
              f"2,000,000 (got {incs[0]['first_seen']})")
        expected_id = "default:actor:time-user:1000"
        check(incs[0]["incident_id"] == expected_id,
              f"time: incident_id must bucket on the SANITIZED first_seen "
              f"(expected {expected_id!r}, got {incs[0]['incident_id']!r} -- a "
              "future time would fork it into bucket 2000)")

    # NaN time must also be rejected -> falls back to now_ms
    c.ingest_alert({"alert_id": "t3", "tactic": "TA0001", "time": float("nan"),
                    "score": 5, "mitre": {"tactic": "TA0003"},
                    "actor": {"user": {"name": "time-user"}}})
    check(side["t3"]["time"] == 1_000_000,
          "time: NaN time must be rejected and fall back to now_ms (got side['t3']['time'])")


# --- NEW finding #4: fully-anonymous member id must be deterministic ---------
def test_fully_anonymous_alert_redelivery_is_deterministic():
    """A fully-anonymous alert (no alert_id/time/rule_id/event_ids) used to
    get a per-instance counter id (anon-seq:{n}) -- the one non-deterministic
    member id in the correlator: the same anon alert redelivered 3x inflated
    into 3 members. Member id must be a deterministic hash of the payload."""
    c = _new_correlator()
    anon_t1 = {"score": 5, "mitre": {"tactic": "TA0001"}, "tenant_id": "default",
               "actor": {"user": {"name": "anon-actor"}}}
    for _ in range(3):
        c.ingest_alert(anon_t1)
    key = c._track_key("default", "actor", "anon-actor")
    members = c._sides[key]
    check(len(members) == 1,
          f"anon: the same anon alert redelivered 3x must dedupe to ONE member, "
          f"got {len(members)} side entries {sorted(members)}")
    the_member = next(iter(members))
    check(the_member.startswith("anon:") and "anon-seq" not in the_member,
          f"anon: member id must be a deterministic 'anon:' hash, not a "
          f"per-instance counter, got {the_member!r}")

    # a DISTINCT anon alert (different tactic) + its own redelivery must be a
    # separate member, and member_count must reflect 2 distinct alerts only
    anon_t2 = {"score": 5, "mitre": {"tactic": "TA0002"}, "tenant_id": "default",
               "actor": {"user": {"name": "anon-actor"}}}
    incs = c.ingest_alert(anon_t2)
    incs += c.ingest_alert(anon_t2)
    if incs:
        check(incs[-1]["member_count"] == 2,
              f"anon: distinct anon alerts A+B must give member_count 2, got "
              f"{incs[-1]['member_count']} -- redelivery inflating it to 4/5 "
              "is the bug being prevented")
        check(len(set(incs[-1]["member_alert_ids"])) == 2,
              "anon: the two member ids must be distinct deterministic hashes")


# NEW finding #6: member-cap eviction orders by TIME, not insertion order -----
def test_member_cap_evicts_oldest_by_distinct_time():
    """Member-cap eviction sorts by each member's `time` (oldest first), but
    no test exercised it with DISTINCT timestamps where insertion order !=
    time order -- the old cap test's times were monotonically increasing, so a
    bug that evicted in insertion order would pass. Inserting OUT of time
    order must evict the lowest-TIME member, not the first-inserted one."""
    clock = _Clock()
    c = _new_correlator(member_cap=2, now_fn=clock)
    c.ingest_alert(_alert("tm1", tactic="TA0001", actor="evict-user", time_ms=500))
    c.ingest_alert(_alert("tm2", tactic="TA0001", actor="evict-user", time_ms=100))
    c.ingest_alert(_alert("tm3", tactic="TA0001", actor="evict-user", time_ms=300))
    key = c._track_key("default", "actor", "evict-user")
    side = c._sides[key]
    check(set(side) == {"tm1", "tm3"},
          f"cap-time: the OLDEST-by-time member tm2 (t=100) must be evicted, "
          f"newest-by-time tm1/tm3 kept -- got {sorted(side)}; eviction must "
          "sort by member time, not insertion order")
    check(len(side) == 2, "cap-time: side table must stay bounded at member_cap=2")
    check(side["tm1"]["time"] == 500 and side["tm3"]["time"] == 300,
          "cap-time: the surviving members must be the two highest-time ones")


def run_all():
    test_skipped_reasons_emit_flat_numeric_metrics_keys()
    test_bogus_alert_time_is_rejected_falls_back_to_now_ms()
    test_fully_anonymous_alert_redelivery_is_deterministic()
    test_member_cap_evicts_oldest_by_distinct_time()


if __name__ == "__main__":
    run_all()
    if FAILS:
        print(f"[FAIL] WS-8 correlation NEW-hunt regression: {len(FAILS)} problem(s)")
        for f in FAILS:
            print(f"  - {f}")
        sys.exit(1)
    print("[OK] WS-8 correlation NEW-hunt regression PASS (flat prometheus "
          "skip keys + skew-future/NaN time rejected + fully-anonymous "
          "deterministic member id + oldest-by-time member-cap eviction)")