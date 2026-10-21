"""Regression tests for bugs found by the REPAIRED atheris harnesses (2026-10-20).

The harnesses had no coverage feedback until tools/fuzz/_common.py started instrumenting the parsers (and decoded the
fuzz bytes directly); the first Docker runs then found five real parser bugs within seconds:
  * windows_eventlog: a non-string NewProcessName produced `actor.process.name: expected string, got int`
  * cef / cisco_asa / linux_ssh: a logged port above 65535 produced `src_endpoint.port: 71000 > maximum 65535`
  * opcua_audit: a dict/list eventType raised `TypeError: unhashable type: 'dict'`

Run: python services/ws2-normalization/parsers/test_fuzz_findings.py
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent.parent), str(HERE.parent)]

from parsers import _REGISTRY  # noqa: E402
from shared.ocsf import validate  # noqa: E402
from shared.ip_utils import valid_port  # noqa: E402

FAILS: list = []


def check(c, m):
    if not c:
        FAILS.append(m)


def parse(src, raw):
    return _REGISTRY[src].parse({"source_type": src, "raw": raw, "meta": {"received_at": 1700000000, "ingest_id": "f"}})


# helper
check(valid_port(443) == 443 and valid_port(0) == 0 and valid_port(65535) == 65535, "valid ports must pass")
check(valid_port(65536) is None and valid_port(-1) is None and valid_port(True) is None and valid_port("80") is None,
      "out-of-range / bool / str ports must be rejected")

# windows_eventlog 4688 with a numeric NewProcessName
ev = parse("windows_eventlog", {"EventID": 4688, "TimeCreated": 1750000000000, "NewProcessName": 12345,
                                "SubjectUserName": "u", "Computer": "h"})
check(ev is None or validate(ev) == [], f"windows 4688 with int NewProcessName must stay schema-valid: {ev and validate(ev)}")

# out-of-range ports must be dropped, the event kept and valid
ev = parse("linux_ssh", "Jun 10 13:55:36 db01 sshd[1]: Failed password for root from 203.0.113.5 port 520022 ssh2")
check(ev is not None and validate(ev) == [], f"ssh with port 520022 must stay valid: {ev and validate(ev)}")
check(ev is None or "port" not in (ev.get("src_endpoint") or {}), "ssh: an out-of-range port must be omitted, not copied")

ev = parse("cisco_asa", "%ASA-4-106023: Deny tcp src outside:203.0.113.5/110010 dst inside:10.0.0.10/22 by access-group acl_out")
check(ev is not None and validate(ev) == [], f"asa with src port 110010 must stay valid: {ev and validate(ev)}")
ev = parse("cisco_asa", "%ASA-4-106023: Deny tcp src outside:203.0.113.5/5000 dst inside:10.0.0.10/22 by access-group acl_out")
check(ev is not None and ev["src_endpoint"].get("port") == 5000 and ev["dst_endpoint"].get("port") == 22,
      "asa: in-range ports must still be carried")

ev = parse("cef", "CEF:0|V|P|1|100|name|5|src=203.0.113.5 spt=71000 dst=10.0.0.1 dpt=443")
check(ev is not None and validate(ev) == [], f"cef with spt=71000 must stay valid: {ev and validate(ev)}")
check(ev is None or ev["dst_endpoint"].get("port") == 443, "cef: the in-range dpt must still be carried")

# opcua_audit: unhashable eventType
for bad in ({"a": 1}, ["x"], 5):
    try:
        out = parse("opcua_audit", {"eventType": bad, "sessionId": "s"})
    except Exception as exc:  # noqa: BLE001
        FAILS.append(f"opcua_audit raised on eventType={bad!r}: {exc!r}")
    else:
        check(out is None, f"opcua_audit must reject a non-string eventType {bad!r}")

# n8n_audit: unhashable eventType (second fuzz run)
for bad in ({"a": 1}, ["x"], 5):
    try:
        out = parse("n8n_audit", {"eventType": bad, "user": "u"})
    except Exception as exc:  # noqa: BLE001
        FAILS.append(f"n8n_audit raised on eventType={bad!r}: {exc!r}")
    else:
        check(out is None, f"n8n_audit must reject a non-string eventType {bad!r}")

# valid_ip: an IPv6 zone id with arbitrary text after '%' produced a schema-invalid endpoint (nightly fuzz, db_audit)
from shared.ip_utils import valid_ip  # noqa: E402
check(valid_ip("fe80::1%eth0") == "fe80::1", "zone id must be dropped, address kept")
check(valid_ip("::%" + chr(0x8a) * 8) == "::", "garbage zone id must not survive")
check(valid_ip("%eth0") is None and valid_ip("1.2.3.4%x") == "1.2.3.4", "bare zone rejected; IPv4 zone-like suffix dropped")
ev = parse("db_audit", {"ip": "::%" + chr(0x8a) * 8, "operation": "SELECT", "object": "t", "user": "u", "host": "h"})
check(ev is None or validate(ev) == [], f"db_audit with a zone-id ip must stay schema-valid: {ev and validate(ev)}")

if FAILS:
    for f in FAILS:
        print("[FAIL]", f)
    sys.exit(1)
print("[OK] fuzz findings: non-string process name, out-of-range ports (cef/asa/ssh), non-string OPC UA eventType all handled")
