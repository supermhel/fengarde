"""PR #153 review: 4625 (failed logon) edge cases in the active_directory
parser and the Winlogbeat adapter.

Run: python services/ws2-normalization/parsers/test_ad_4625_edges.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
WS2 = HERE.parent
sys.path.insert(0, str(WS2.parent))
sys.path.insert(0, str(WS2))

from parsers.active_directory import ActiveDirectoryParser  # noqa: E402
from adapters import winlogbeat  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


P = ActiveDirectoryParser()
BASE = {"EventID": 4625, "TimeCreated": 1750000000000, "Computer": "WIN11-LAB",
        "SubjectUserName": "WIN11-LAB$", "SubjectDomainName": "WORKGROUP",
        "IpAddress": "10.0.0.5", "WorkstationName": "ATTACKER",
        "Status": "0xC000006D", "SubStatus": "0xC000006A"}


def parse(**over):
    rec = dict(BASE, **over)
    for k, v in list(rec.items()):
        if v is None:
            del rec[k]
    return P.parse({"raw": rec, "meta": {}})


def user(ev):
    return ((ev or {}).get("actor") or {}).get("user", {}).get("name")


def main():
    ev = parse(TargetUserName="jdoe")
    check(user(ev) == "jdoe", f"named target: {user(ev)!r}")
    check((ev.get("unmapped") or {}).get("logon_status") == {"status": "0xC000006D", "sub_status": "0xC000006A"},
          f"status codes: {ev.get('unmapped')}")

    for empty in ("", "-", " - ", None):
        ev = parse(TargetUserName=empty)
        check(ev is not None, f"TargetUserName={empty!r}: event must still parse (IP present)")
        check(user(ev) is None,
              f"TargetUserName={empty!r} must not become user {user(ev)!r} (machine account / '-')")

    # a non-failure event may still fall back to the subject
    ev = P.parse({"raw": {"EventID": 4634, "TimeCreated": 1, "SubjectUserName": "alice"}, "meta": {}})
    check(user(ev) == "alice", f"4634 subject fallback: {user(ev)!r}")

    # hollow 4625: no named event data at all -> dropped, not a sourceless event
    for hollow in ({"EventID": 4625, "TimeCreated": 1, "Computer": "WIN11-LAB"},
                   {"EventID": 4625, "TimeCreated": 1, "Computer": "WIN11-LAB",
                    "StringInserts": ["S-1-0-0", "-", "jdoe"]},
                   {"EventID": 4625, "TimeCreated": 1, "Computer": "WIN11-LAB", "EventData": ["a", "b"]}):
        check(P.parse({"raw": hollow, "meta": {}}) is None, f"hollow 4625 must be dropped: {hollow}")

    for eid in (4625.0, "4625.0", " 4625 "):
        ev = parse(EventID=eid, TargetUserName="jdoe")
        check(ev is not None and ev["activity_id"] == 4, f"EventID {eid!r} must parse as 4625")
    check(parse(EventID=4625.5, TargetUserName="jdoe") is None, "non-integral EventID must not parse")

    # Winlogbeat: no winlog.time_created -> @timestamp, not receive time
    out = winlogbeat.adapt({"raw": {"@timestamp": "2023-01-17T12:50:59.303Z",
                                    "winlog": {"event_id": 4625, "channel": "Security",
                                               "computer_name": "WIN11-LAB",
                                               "event_data": {"TargetUserName": "jdoe"}}},
                            "meta": {}})
    check(out["raw"].get("TimeCreated") == 1673959859303,
          f"winlogbeat @timestamp fallback: {out['raw'].get('TimeCreated')!r}")

    # null / empty SIDs are not an identity (real lab data: TargetUserSid S-1-0-0)
    for null_sid in ("S-1-0-0", "-", "", " S-1-0-0 "):
        ev = parse(TargetUserName="jdoe", TargetUserSid=null_sid)
        check("uid" not in ev["actor"]["user"], f"null SID {null_sid!r} must not become actor.user.uid: {ev['actor']['user']}")
    ev = parse(TargetUserName="jdoe", TargetUserSid="S-1-5-21-1-2-3-1001")
    check(ev["actor"]["user"].get("uid") == "S-1-5-21-1-2-3-1001", "a real SID must be kept")

    # positional-only 4625 (Fluent Bit without event_data_as_map): Microsoft template order
    ins = ["S-1-5-18", "WIN11-LAB$", "WORKGROUP", "0x3e7", "S-1-0-0", "labuser", "WIN11-LAB", "0xc000006d",
           "%%2313", "0xc000006a", "3", "NtLmSsp", "NTLM", "ATTACKBOX", "-", "-", "0", "0x0", "-",
           "203.0.113.45", "49822"]
    ev = P.parse({"raw": {"EventID": 4625, "TimeCreated": 1, "Computer": "WIN11-LAB", "StringInserts": ins}, "meta": {}})
    check(ev is not None, "positional 4625 must parse")
    if ev is not None:
        check(user(ev) == "labuser", f"positional user: {user(ev)!r}")
        check(ev["actor"]["user"].get("domain") == "WIN11-LAB", f"positional domain: {ev['actor']['user']}")
        check("uid" not in ev["actor"]["user"], "positional null SID dropped")
        check(ev.get("src_endpoint", {}).get("ip") == "203.0.113.45", f"positional ip: {ev.get('src_endpoint')}")
        check(ev.get("src_endpoint", {}).get("hostname") == "ATTACKBOX", f"positional host: {ev.get('src_endpoint')}")
        check((ev.get("unmapped") or {}).get("logon_status") == {"status": "0xc000006d", "sub_status": "0xc000006a",
                                                                  "failure_reason": "%%2313"},
              f"positional status codes: {ev.get('unmapped')}")
    # named keys win: StringInserts is ignored when any named data exists
    ev = P.parse({"raw": {"EventID": 4625, "TimeCreated": 1, "IpAddress": "10.0.0.9", "StringInserts": ins}, "meta": {}})
    check(user(ev) is None, f"named data present -> inserts ignored: {user(ev)!r}")
    # too-short inserts are still dropped
    check(P.parse({"raw": {"EventID": 4625, "TimeCreated": 1, "StringInserts": ins[:5]}, "meta": {}}) is None,
          "short StringInserts must be dropped")
    # through the Fluent Bit adapter
    from adapters import fluentbit_winevtlog  # noqa: E402
    out = fluentbit_winevtlog.adapt({"raw": {"ProviderName": "Microsoft-Windows-Security-Auditing", "EventID": 4625,
                                             "TimeCreated": "2026-11-13 10:15:30 +0100", "Computer": "WIN11-LAB",
                                             "StringInserts": ins}, "meta": {}})
    check(out["source_type"] == "active_directory", f"adapter route: {out['source_type']}")
    ev = P.parse(out)
    check(user(ev) == "labuser", f"adapter+positional user: {user(ev)!r}")

    if FAILS:
        print(f"[FAIL] AD 4625 edges: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] AD 4625 edges: no subject/'-' misattribution, hollow events dropped, "
          "integral float EventIDs, status codes kept, Winlogbeat @timestamp fallback")


if __name__ == "__main__":
    main()
