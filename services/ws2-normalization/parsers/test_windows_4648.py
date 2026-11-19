"""Windows Security 4648 (logon with explicit credentials) -> OCSF Authentication 3002 / Logon.

Run: python services/ws2-normalization/parsers/test_windows_4648.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
WS2 = HERE.parent
sys.path.insert(0, str(WS2.parent))
sys.path.insert(0, str(WS2))

from shared.ocsf import validate  # noqa: E402
from parsers.windows_eventlog import WindowsEventLogParser  # noqa: E402
from adapters import fluentbit_winevtlog, winlogbeat  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


P = WindowsEventLogParser()
REC = {"EventID": 4648, "TimeCreated": 1750000000000, "Computer": "WIN11-LAB",
       "SubjectUserSid": "S-1-5-21-1-2-3-1001", "SubjectUserName": "alice", "SubjectDomainName": "CORP",
       "TargetUserName": "svc-backup", "TargetDomainName": "CORP", "TargetServerName": "fileserver01",
       "IpAddress": "10.0.0.5", "ProcessName": "C:\\Windows\\System32\\runas.exe"}


def main():
    ev = P.parse({"source_type": "windows_eventlog", "raw": dict(REC), "meta": {}})
    check(ev is not None, "4648 must parse")
    if ev is not None:
        check(ev["class_uid"] == 3002 and ev["activity_id"] == 1, f"class/activity: {ev['class_uid']}/{ev['activity_id']}")
        check(ev["type_uid"] == 300201, f"type_uid derived: {ev['type_uid']}")
        au = ev["actor"]["user"]
        check(au["name"] == "alice" and au.get("domain") == "CORP" and au.get("uid") == "S-1-5-21-1-2-3-1001",
              f"actor is the Subject account: {au}")
        check((ev.get("unmapped") or {}).get("target_user") == {"name": "svc-backup", "domain": "CORP"},
              f"explicit target account: {ev.get('unmapped')}")
        check(ev.get("dst_endpoint") == {"hostname": "fileserver01"}, f"dst from TargetServerName: {ev.get('dst_endpoint')}")
        check(ev.get("src_endpoint", {}).get("ip") == "10.0.0.5", f"src ip: {ev.get('src_endpoint')}")
        errs = validate(ev)
        check(not errs, f"schema validation: {errs}")

    # TargetServerName '-' / absent -> falls back to the logging host
    for tsn in ("-", None):
        r = dict(REC)
        if tsn is None:
            del r["TargetServerName"]
        else:
            r["TargetServerName"] = tsn
        ev = P.parse({"source_type": "windows_eventlog", "raw": r, "meta": {}})
        check(ev is not None and ev.get("dst_endpoint") == {"hostname": "WIN11-LAB"}, f"TargetServerName={tsn!r} fallback")

    # routing: Fluent Bit and Winlogbeat both reach windows_eventlog (4648 is not AD-only)
    out = fluentbit_winevtlog.adapt({"raw": {"ProviderName": "Microsoft-Windows-Security-Auditing", "EventID": 4648,
                                             "TimeCreated": "2026-11-13 10:15:30 +0100", "Computer": "WIN11-LAB",
                                             "EventData": {k: v for k, v in REC.items()
                                                           if k.startswith(("Subject", "Target")) or k == "IpAddress"}},
                                     "meta": {}})
    check(out["source_type"] == "windows_eventlog", f"fluent-bit route: {out['source_type']}")
    ev = P.parse(out)
    check(ev is not None and ev["actor"]["user"]["name"] == "alice", "fluent-bit 4648 end to end")
    out = winlogbeat.adapt({"raw": {"@timestamp": "2026-11-13T10:15:30Z",
                                    "winlog": {"event_id": 4648, "channel": "Security", "computer_name": "WIN11-LAB",
                                               "provider_name": "Microsoft-Windows-Security-Auditing",
                                               "event_data": {"SubjectUserName": "alice", "SubjectDomainName": "CORP",
                                                              "TargetUserName": "svc-backup",
                                                              "TargetServerName": "fileserver01"}}},
                            "meta": {}})
    check(out["source_type"] == "windows_eventlog", f"winlogbeat route: {out['source_type']}")
    ev = P.parse(out)
    check(ev is not None and ev.get("dst_endpoint", {}).get("hostname") == "fileserver01", "winlogbeat 4648 end to end")

    if FAILS:
        print(f"[FAIL] Windows 4648: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] Windows 4648: Authentication 3002/Logon, Subject actor, explicit target in unmapped, dst from TargetServerName")


if __name__ == "__main__":
    main()
