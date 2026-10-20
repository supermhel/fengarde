r"""2026-10-20 recall work: Windows service install (7045/4697), audit-log cleared (1102/104) and
Sysmon ProcessAccess (10) parse to class 1002, and the three new rules fire / stay quiet correctly.

Run: python services/ws2-normalization/parsers/test_recall_events.py
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent
sys.path[:0] = [str(ROOT / "services"), str(ROOT / "services" / "ws2-normalization"),
                str(ROOT / "services" / "ws4-detection")]

from engine import load_rules  # noqa: E402
from parsers import _REGISTRY  # noqa: E402

FAILS: list = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def parse(src, rec):
    return _REGISTRY[src].parse({"source_type": src, "raw": rec, "meta": {"ingest_id": "t-" + str(rec["EventID"])}})


def rule(rid):
    return next(r for r in load_rules(ROOT / "contracts" / "rules") if r.title == rid)


T = 1750000000000
svc_tmp = parse("windows_eventlog", {"EventID": 7045, "TimeCreated": T, "Computer": "wks1", "SubjectUserName": "jdoe",
                                     "ServiceName": "Upd", "ImagePath": r"C:\Users\jdoe\AppData\Local\Temp\u.exe"})
svc_ok = parse("windows_eventlog", {"EventID": 7045, "TimeCreated": T, "Computer": "wks1",
                                    "ServiceName": "Spooler", "ImagePath": r"C:\Windows\System32\spoolsv.exe"})
svc_4697 = parse("windows_eventlog", {"EventID": 4697, "TimeCreated": T, "Computer": "dc1", "SubjectUserName": "adm",
                                      "ServiceName": "x", "ServiceFileName": "%COMSPEC% /c calc"})
clr_sec = parse("windows_eventlog", {"EventID": 1102, "TimeCreated": T, "Computer": "dc1", "SubjectUserName": "adm"})
clr_sys = parse("windows_eventlog", {"EventID": 104, "TimeCreated": T, "Computer": "dc1", "SubjectUserName": "adm"})
for ev, act in ((svc_tmp, 3), (svc_ok, 3), (svc_4697, 3), (clr_sec, 4), (clr_sys, 4)):
    got = ev and (ev["class_uid"], ev["activity_id"])
    check(got == (1002, act), f"class/activity wrong: {got}")
check(svc_tmp["unmapped"]["service"]["suspicious_path"] is True, "temp-path service must be suspicious")
check(svc_ok["unmapped"]["service"]["suspicious_path"] is False, "System32 service must not be suspicious")
check(svc_4697["unmapped"]["service"]["suspicious_path"] is True, "%COMSPEC% service must be suspicious")

sysmon10 = {"EventID": 10, "TimeCreated": T, "Computer": "wks1", "SourceProcessId": "99",
            "TargetImage": r"C:\Windows\System32\lsass.exe", "GrantedAccess": "0x1010"}
bad = parse("sysmon", dict(sysmon10, SourceImage=r"C:\Users\jdoe\Downloads\dump.exe"))
trusted = parse("sysmon", dict(sysmon10, SourceImage=r"C:\Windows\System32\wininit.exe"))
other_target = parse("sysmon", dict(sysmon10, SourceImage=r"C:\x\a.exe", TargetImage=r"C:\Windows\explorer.exe"))
benign_mask = parse("sysmon", dict(sysmon10, SourceImage=r"C:\x\a.exe", GrantedAccess="0x1000"))
check(bad["class_uid"] == 1002 and bad["activity_id"] == 5, "sysmon 10 must be class 1002 activity 5")
check(bad["unmapped"]["lsass_access_suspicious"] is True, "dump.exe -> lsass 0x1010 must be suspicious")
check(trusted["unmapped"]["lsass_access_suspicious"] is False, "wininit -> lsass must be trusted")
check(other_target["unmapped"]["lsass_access_suspicious"] is False, "non-lsass target must not be suspicious")
check(benign_mask["unmapped"]["lsass_access_suspicious"] is False, "benign mask must not be suspicious")

R_CLR, R_SVC, R_LSA = (rule("Windows audit log cleared"), rule("Service installed from a suspicious path"),
                       rule("Suspicious process access to lsass.exe"))
check(R_CLR.evaluate(clr_sec) and R_CLR.evaluate(clr_sys), "log-cleared rule must fire on 1102 and 104")
check(not R_CLR.evaluate(svc_tmp), "log-cleared rule must not fire on a service install")
check(R_SVC.evaluate(svc_tmp) and R_SVC.evaluate(svc_4697), "service rule must fire on suspicious paths")
check(not R_SVC.evaluate(svc_ok), "service rule must not fire on System32")
check(R_LSA.evaluate(bad), "lsass rule must fire on a dump-style access")
check(not R_LSA.evaluate(trusted) and not R_LSA.evaluate(benign_mask) and not R_LSA.evaluate(other_target),
      "lsass rule must stay quiet on trusted caller / benign mask / other target")

if FAILS:
    for f in FAILS:
        print("[FAIL]", f)
    sys.exit(1)
print("[OK] service-install, log-cleared and lsass-access events parse to class 1002 and their rules fire/stay quiet correctly")
