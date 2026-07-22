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

from parsers import _REGISTRY  # noqa: E402
from enrichment import enrich  # noqa: E402  -- v0.4: mirror the real parse->enrich pipeline

RULES_DIR = ROOT / "contracts" / "rules"

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


def collect_producible() -> tuple[set[str], set[tuple[str, object]]]:
    """(all field paths ever populated, all (path, value) pairs ever observed).

    Distinguishing the two matters: an EQUALITY selection like `class_uid: 6005`
    is only satisfiable if some parser emits class_uid=6005 specifically -- the
    path existing (class_uid is on every event) is not enough. group_by/
    distinct_field only need the path to exist (any value groups/counts fine).
    """
    all_paths: set[str] = set()
    all_pairs: set[tuple[str, object]] = set()
    for source_type, raws in FIXTURES.items():
        parser = _REGISTRY.get(source_type)
        if parser is None:
            print(f"WARNING: fixture defined for unregistered source_type "
                  f"{source_type!r}", file=sys.stderr)
            continue
        for raw in raws:
            payload = {"source_type": source_type, **raw}
            event = parser.parse(payload)
            if event is not None:
                # v0.4: real events go through WS-2's parse -> enrich pipeline
                # before a rule ever sees them (services/ws2-normalization/
                # main.py::normalize_one). Fields enrichment adds (e.g.
                # src_endpoint.location.country) are as "real" as parser
                # fields for satisfiability purposes -- skipping this step
                # would make common_impossible_travel look dormant when it
                # isn't.
                event = enrich(event)
                flat = flatten(event)
                all_paths |= set(flat)
                all_pairs |= {(k, v) for k, v in flat.items()
                             if isinstance(v, (str, int, float, bool)) or v is None}
    missing = set(_REGISTRY) - set(FIXTURES)
    if missing:
        print(f"NOTE: no fixture for registered parser(s) {sorted(missing)} -- "
              f"their fields are NOT checked. Add a fixture when convenient.",
              file=sys.stderr)
    return all_paths, all_pairs


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


def collect_events() -> list[dict[str, object]]:
    """One flattened dotted-path map per REAL event a parser produces (post-enrich).

    Per-event (not a global union) so we can check that a rule matches and has its
    group_by/distinct_field on the SAME event -- see main()."""
    events: list[dict[str, object]] = []
    for source_type, raws in FIXTURES.items():
        parser = _REGISTRY.get(source_type)
        if parser is None:
            continue
        for raw in raws:
            event = parser.parse({"source_type": source_type, **raw})
            if event is not None:
                events.append(flatten(enrich(event)))
    return events


def _event_matches(event: dict, equality: set) -> bool:
    """True if the event satisfies every equality (path,value) the rule requires."""
    return all(event.get(k) == v for k, v in equality)


def main() -> int:
    events = collect_events()
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
        equality, path_only = rule_referenced(rule)

        # P2.7: satisfiability is PER EVENT. A rule fires on events matching its
        # equality selection; for a stateful rule it must ALSO have group_by/
        # distinct_field present on those same events, or it can never count. The
        # old global-union check missed this: it passed a rule whose group/distinct
        # field is only ever produced by a DIFFERENT class than the rule matches.
        matching = [e for e in events if _event_matches(e, equality)]
        satisfied = any(all(f in e for f in path_only) for e in matching)
        if satisfied:
            continue

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

    print(f"[OK] all {len(list(RULES_DIR.glob('*.yml')))} rules are satisfiable by a "
          f"real event that both matches them and carries their group/distinct "
          f"fields ({len(events)} events, {len(all_paths)} paths, "
          f"{len(all_pairs)} (path,value) pairs checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
