"""Flow-record rules: common_ids_high_severity_alert, ot_write_unlisted_source, common_large_outbound_flow.

Loads the REAL rule YAML and feeds it events produced by the REAL suricata_eve / zeek_json parsers. Base records are the
real capture records in parsers/test_fixtures/*_real.json; where the capture lacks the value a rule keys on (severity 1,
a 1 GiB flow, a DNP3 write) the record is that real record with only the named field changed (derived, same layout).
Each rule fires on its positive and stays silent on near-misses. Zero infra.

Run: python services/ws4-detection/test_flow_record_rules.py
"""
from __future__ import annotations

import copy
import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "services"))
sys.path.insert(0, str(ROOT / "services" / "ws2-normalization"))

from engine import load_rules  # noqa: E402
from parsers.suricata_eve import SuricataEveParser  # noqa: E402
from parsers.zeek_json import ZeekJsonParser  # noqa: E402

RULES_DIR = ROOT / "contracts" / "rules"
FIX = ROOT / "services" / "ws2-normalization" / "parsers" / "test_fixtures"
IDS_ID = "0331c311-7985-47c8-b554-682781ef1069"
OT_ID = "1256b853-33fb-425a-b954-f19add35285f"
BIG_ID = "8bde66cd-c1e9-45e5-83d7-fd091eb80f1d"
GIB = 1_073_741_824
FAILS: list[str] = []
SUR, ZEEK = SuricataEveParser(), ZeekJsonParser()


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def records(name):
    return json.loads((FIX / name).read_text(encoding="utf-8"))["records"]


def pick(name, pred):
    return copy.deepcopy(next(i["record"] for i in records(name) if pred(i)))


def sur(rec, n=0):
    ev = SUR.parse({"source_type": "suricata_eve", "raw": rec, "meta": {"ingest_id": f"s-{n}"}})
    assert ev is not None
    return ev


def zeek(rec, n=0):
    ev = ZEEK.parse({"source_type": "zeek_json", "raw": rec, "meta": {"ingest_id": f"z-{n}"}})
    assert ev is not None
    return ev


def rule(rid, allow_dir=None):
    for r in load_rules(RULES_DIR, allowlists_dir=allow_dir) if allow_dir else load_rules(RULES_DIR):
        if r.id == rid:
            return r
    raise AssertionError(f"rule {rid} not loaded")


def alert_rec(sev, flow_id=None, **kw):
    r = pick("suricata_eve_real.json", lambda i: i["record"].get("event_type") == "alert")
    r["alert"]["severity"] = sev
    if flow_id is not None:
        r["flow_id"] = flow_id
    r.update(kw)
    return r


def test_ids():
    r = rule(IDS_ID)
    check(r.stateful and r.group_by == "unmapped.ids.flow_id", "ids rule: stateful, grouped by flow_id")
    check(r.evaluate(sur(alert_rec(1, 111), 1)) is True, "severity 1 alert MUST fire")
    for sev in (2, 3):
        check(not rule(IDS_ID).evaluate(sur(alert_rec(sev, 222), 2)), f"severity {sev} must stay silent")
    # near-miss: a non-alert Suricata record (real dns record) never fires
    dns = pick("suricata_eve_real.json", lambda i: i["record"].get("event_type") == "dns")
    check(not rule(IDS_ID).evaluate(sur(dns, 3)), "a dns record must stay silent")
    # dedupe: same flow, different ingest ids -> same alert id; other flow -> different id
    a, b = sur(alert_rec(1, 333), 4), sur(alert_rec(1, 333), 5)
    c = sur(alert_rec(1, 444), 6)
    rr = rule(IDS_ID)
    check(rr.alert_key(a) == rr.alert_key(b), "same flow must share one alert_id")
    check(rr.alert_key(a) != rr.alert_key(c), "a different flow must get its own alert_id")
    check(rr.evaluate(a) and rr.evaluate(b), "every high-severity hit still fires (dedupe is on the id)")
    # IPS-blocked still alerts
    blk = alert_rec(1, 555)
    blk["alert"]["action"] = "blocked"
    check(rule(IDS_ID).evaluate(sur(blk, 7)), "an IPS-blocked severity 1 alert still fires")


def write_modbus_suricata(code):
    r = pick("suricata_eve_real.json", lambda i: i["record"].get("event_type") == "modbus"
             and (i["record"]["modbus"].get("request") or {}).get("function_raw") == 5)
    r["modbus"]["request"]["function_raw"] = code
    r["modbus"]["response"]["function_raw"] = code
    return r


def dnp3(code):
    r = pick("suricata_eve_real.json", lambda i: i["record"].get("event_type") == "dnp3")
    r["dnp3"]["application"]["function_code"] = code
    return r


def zeek_modbus(func, pdu="REQ"):
    r = pick("zeek_json_real.json", lambda i: i["log"] == "modbus.log" and i["record"].get("func") == "WRITE_SINGLE_COIL")
    r["func"], r["pdu_type"] = func, pdu
    return r


def test_ot():
    with tempfile.TemporaryDirectory() as td:
        allow = Path(td)
        (allow / "ot_authorized_writers.yml").write_text('entries: ["10.0.0.9", "10.20.1.0/28"]\n', encoding="utf-8")
        for f in (ROOT / "contracts" / "allowlists").glob("*.yml"):
            if f.name != "ot_authorized_writers.yml":
                (allow / f.name).write_text(f.read_text(encoding="utf-8"), encoding="utf-8")
        R = lambda: rule(OT_ID, allow)  # noqa: E731

        # FIRES: real Suricata modbus WrSingleCoil from 10.0.0.9 is the listed writer -> silent; others fire.
        real = pick("suricata_eve_real.json", lambda i: i["record"].get("event_type") == "modbus"
                    and (i["record"]["modbus"].get("request") or {}).get("function_raw") == 5)
        check(not R().evaluate(sur(real)), "listed writer 10.0.0.9: real WrSingleCoil must be silent")
        for code in (5, 6, 15, 16, 21, 22, 23):
            rec = write_modbus_suricata(code)
            rec["src_ip"] = "10.9.9.9"
            check(R().evaluate(sur(rec)), f"suricata modbus function {code} from unlisted source MUST fire")
        rec = write_modbus_suricata(5)
        rec["src_ip"] = "10.20.1.5"
        check(not R().evaluate(sur(rec)), "source inside a listed CIDR must be silent")
        for code in (2, 4, 5, 6):
            rec = dnp3(code)
            check(R().evaluate(sur(rec)), f"dnp3 function {code} from unlisted source MUST fire")
        # real Zeek write request row from an unlisted source
        z = zeek_modbus("WRITE_SINGLE_COIL")
        z["id.orig_h"] = "10.9.9.9"
        check(R().evaluate(zeek(z)), "zeek modbus.log WRITE REQ from unlisted source MUST fire")
        z = zeek_modbus("WRITE_SINGLE_COIL")
        check(not R().evaluate(zeek(z)), "zeek write from listed 10.0.0.9 must be silent")

        # NEAR-MISSES
        for code in (1, 3, 4, 8):
            rec = write_modbus_suricata(code)
            rec["src_ip"] = "10.9.9.9"
            check(not R().evaluate(sur(rec)), f"modbus function {code} (read/diagnostic) must be silent")
        for code in (1, 3, 21, 129):
            rec = dnp3(code)
            check(not R().evaluate(sur(rec)), f"dnp3 function {code} (read/select/other/response) must be silent")
        z = zeek_modbus("WRITE_SINGLE_COIL_EXCEPTION", "RESP")
        z["id.orig_h"] = "10.9.9.9"
        check(not R().evaluate(zeek(z)), "zeek RESP row must be silent (request already counted)")
        z = zeek_modbus("READ_HOLDING_REGISTERS")
        z["id.orig_h"] = "10.9.9.9"
        check(not R().evaluate(zeek(z)), "zeek read must be silent")
    # default-off flag and shipped-empty allowlist
    r = rule(OT_ID)
    check(r.raw["siem"].get("default_enabled") is False, "ot rule must ship default-off")
    check(not (ROOT / "contracts" / "allowlists" / "ot_authorized_writers.yml").read_text().count("\n  - "),
          "shipped ot_authorized_writers must be empty")


def test_large():
    big_s = pick("suricata_eve_real.json", lambda i: i["record"].get("event_type") == "flow"
                 and i["record"].get("app_proto") == "modbus")
    big_s["dest_ip"] = "198.51.100.20"
    big_s["flow"]["bytes_toserver"] = GIB
    check(rule(BIG_ID).evaluate(sur(big_s)), "suricata flow of exactly 1 GiB to a public dst MUST fire")
    z = pick("zeek_json_real.json", lambda i: i["log"] == "conn.log" and i["record"].get("service") == "modbus")
    z["id.resp_h"], z["orig_bytes"] = "198.51.100.20", GIB
    check(rule(BIG_ID).evaluate(zeek(z)), "zeek conn of 1 GiB originated to a public dst MUST fire")

    s2 = copy.deepcopy(big_s)
    s2["flow"]["bytes_toserver"] = GIB - 1
    check(not rule(BIG_ID).evaluate(sur(s2)), "one byte under 1 GiB must be silent")
    s3 = copy.deepcopy(big_s)
    s3["dest_ip"] = "10.0.0.8"
    check(not rule(BIG_ID).evaluate(sur(s3)), "1 GiB to a private destination must be silent")
    s4 = copy.deepcopy(big_s)
    s4["flow"]["bytes_toserver"], s4["flow"]["bytes_toclient"] = 1000, 5 * GIB
    check(not rule(BIG_ID).evaluate(sur(s4)), "a large DOWNLOAD (bytes_toclient) must be silent")
    z2 = copy.deepcopy(z)
    z2["orig_bytes"], z2["resp_bytes"] = 1000, 5 * GIB
    check(not rule(BIG_ID).evaluate(zeek(z2)), "zeek large resp_bytes only must be silent")
    z3 = copy.deepcopy(z)
    z3["id.resp_h"] = "192.168.1.5"
    check(not rule(BIG_ID).evaluate(zeek(z3)), "zeek 1 GiB to a private destination must be silent")
    with tempfile.TemporaryDirectory() as td:
        allow = Path(td)
        for f in (ROOT / "contracts" / "allowlists").glob("*.yml"):
            (allow / f.name).write_text(f.read_text(encoding="utf-8"), encoding="utf-8")
        (allow / "large_transfer_destinations.yml").write_text('entries: ["198.51.100.20"]\n', encoding="utf-8")
        check(not rule(BIG_ID, allow).evaluate(zeek(z)), "an allowlisted backup destination must be silent")


def main():
    test_ids()
    test_ot()
    test_large()
    if FAILS:
        print(f"[FAIL] flow-record rules: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] flow-record rules fire on REAL suricata_eve/zeek_json output and stay silent on near-misses")


if __name__ == "__main__":
    main()
