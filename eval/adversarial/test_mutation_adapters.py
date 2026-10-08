"""Acceptance test for the mutation FIELD ADAPTERS and the wave-2 variants (2026-10-03).

Standalone (NOT pytest), same style as test_scenario_harness.py: ``[OK]``/``[FAIL]`` lines, exit 0
only when every check passes. Run:

    python eval/adversarial/test_mutation_adapters.py

WHY (the failure this prevents). An operator's adapter edits a RAW key. If the parser reads a
different key, ``changed`` is still > 0 -- the variant reports "applicable" -- and the rule
simply never sees the difference: a silent no-op that is counted as a pass. Every adapter is
therefore proven the only way that matters: normalise the payload through the REAL WS-2 parser
before and after, and require the PARSED field to move to exactly the requested value.

  (a) every adapter moves the PARSED field          for every source a storyline can emit
  (b) NEGATIVE: an adapter that edits a key the parser ignores is caught by the same check
  (c) NEGATIVE: a source/field with no adapter returns False and changes nothing (-> N/A)
  (d) timing/to_business_hours | to_night           pure shifts; the time-of-day predicate flips
                                                     a real rule in BOTH directions
  (e) pacing/jitter_100pct                           deterministic, bounded by the period, bursts
                                                     only; defeats the periodic rule; the
                                                     un-jittered stream still fires it
  (f) distribution/hostname_rotate_all               bypasses a workstation-keyed rule, as that
                                                     rule's own YAML says it can
"""
from __future__ import annotations

import copy
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ADVERSARIAL = Path(__file__).resolve().parent
TWIN = ROOT / "eval" / "twin"
SERVICES = ROOT / "services"
for _p in (str(ADVERSARIAL), str(TWIN), str(SERVICES)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import mutate_generic as mg  # noqa: E402
import negative_controls  # noqa: E402
import probe_session  # noqa: E402
from scenario import ChainStepSpec  # noqa: E402

T0 = 1751500000000          # Wed 2025-07-02 23:46:40 UTC (night)
T1 = T0 + 3_600_000
_FAILURES: list = []


def _check(name: str, ok: bool, detail: str = "") -> None:
    print(f"[{'OK' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))
    if not ok:
        _FAILURES.append(name)


def _meta(ts: int, ip: str | None = None, idx: int = 0) -> dict:
    m = {"received_at": ts, "ingest_id": f"ing-adapt-{idx:04d}", "trace_id": "t-adapt", "tenant_id": "acme"}
    if ip:
        m["ip"] = ip
    return m


def _iso(ms: int, frac: bool = False) -> str:
    return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ" if frac else "%Y-%m-%dT%H:%M:%SZ")


def _payload(source_type: str, raw, ip: str | None = None, idx: int = 0) -> dict:
    return {"source_type": source_type, "raw": raw, "meta": _meta(T0, ip, idx)}


# (label, payload, which adapters the source supports)
def _fixtures() -> list:
    return [
        ("cisco_asa", _payload("cisco_asa",
                               "%ASA-4-106023: Deny tcp src outside:203.0.113.5/40000 "
                               "dst inside:10.0.0.10/22 by access-group acl_out", "203.0.113.5"),
         {"ip", "time"}),
        ("linux_ssh", _payload("linux_ssh",
                               "Jun 10 13:55:00 db01 sshd[2000]: Failed password for deploy "
                               "from 203.0.113.5 port 51000 ssh2", "203.0.113.5"),
         {"ip", "actor", "time"}),
        ("dns_query", _payload("dns_query", "query[A] a.example.invalid from 10.50.0.5", "10.50.0.5"),
         {"ip", "time"}),
        ("cef", _payload("cef", "CEF:0|Vendor|Product|1.0|100|Login failed|5|"
                                "src=192.0.2.5 dst=10.0.0.9 suser=bob outcome=failure", "192.0.2.5"),
         {"ip", "actor", "time"}),
        ("windows_eventlog", _payload("windows_eventlog",
                                      {"EventID": 4624, "TargetUserName": "alice", "Computer": "fs01",
                                       "IpAddress": "10.50.0.21", "WorkstationName": "db01",
                                       "TimeCreated": T0}, "10.50.0.21"),
         {"ip", "actor", "time", "host"}),
        ("active_directory", _payload("active_directory",
                                      {"EventID": 4625, "TargetUserName": "alice", "Computer": "dc01",
                                       "IpAddress": "10.50.0.22", "WorkstationName": "wks-1",
                                       "TimeCreated": T0}, "10.50.0.22"),
         {"ip", "actor", "time", "host"}),
        ("cloudtrail", _payload("cloudtrail",
                                {"eventTime": _iso(T0), "eventSource": "signin.amazonaws.com",
                                 "eventName": "ConsoleLogin", "sourceIPAddress": "203.0.113.9",
                                 "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::1:user/alice"},
                                 "responseElements": {"ConsoleLogin": "Success"}}, "203.0.113.9"),
         {"ip", "actor", "time"}),
        ("vmware_vsphere", _payload("vmware_vsphere",
                                    {"operation": "VM.Delete", "vm": "vm1", "userName": "svc_x",
                                     "host": "vcenter-01", "ipAddress": "203.0.113.9", "createdTime": T0},
                                    "203.0.113.9"),
         {"ip", "actor", "time"}),
        ("mcp_agent", _payload("mcp_agent",
                               {"ts": T0, "session_id": "s1", "agent": "bot", "server": "srv", "tool": "read_file",
                                "arguments": {"path": "/tmp/x"}, "outcome": "success", "client_ip": "10.1.1.1"},
                               "10.1.1.1"),
         {"ip", "actor", "time"}),
        ("n8n_audit", _payload("n8n_audit",
                               {"eventType": "webhook.created", "user": "ops", "ip": "10.1.1.2",
                                "workflowId": "wf", "path": "/p", "ts": T0}, "10.1.1.2"),
         {"ip", "actor", "time"}),
        ("modbus_anomaly", _payload("modbus_anomaly",
                                    {"unitId": 1, "functionCode": 6, "address": 41999, "value": 5,
                                     "sourceIp": "10.20.0.50", "destIp": "10.20.0.5", "time": T0},
                                    "10.20.0.50"),
         {"ip", "time"}),
        ("k8s_audit", _payload("k8s_audit",
                               {"auditID": "a1", "verb": "create", "user": {"username": "alice"},
                                "sourceIPs": ["203.0.113.9"],
                                "objectRef": {"resource": "pods", "namespace": "kube-system", "name": "p"},
                                "requestReceivedTimestamp": _iso(T0, True),
                                "responseStatus": {"code": 201}}, "203.0.113.9"),
         {"ip", "actor", "time"}),
        ("db_audit", _payload("db_audit",
                              {"operation": "SELECT", "object": "cardholder_data", "user": "insider",
                               "host": "db-prod-01", "ipAddress": "10.4.4.9", "timestamp": T0}, "10.4.4.9"),
         {"ip", "actor", "time"}),
        ("opcua_audit", _payload("opcua_audit",
                                 {"eventType": "AuditWriteUpdateEventType", "sourceName": "Write",
                                  "clientUserId": "engineer01", "clientAddress": "10.20.0.15",
                                  "serverId": "plc-line3", "nodeId": "ns=2;s=Line3.PumpEnable",
                                  "status": True, "time": T0}, "10.20.0.15"),
         {"ip", "actor", "time"}),
        ("sysmon:network", _payload("sysmon",
                                    {"EventID": 3, "TimeCreated": T0, "Computer": "wks-1", "Image": "C:\\x.exe",
                                     "User": "m.rossi", "SourceIp": "10.9.0.5", "SourceHostname": "wks-1",
                                     "DestinationIp": "203.0.113.9", "DestinationPort": "443"}, "10.9.0.5"),
         {"ip", "actor", "time", "host"}),
        ("sysmon:process", _payload("sysmon",
                                    {"EventID": 1, "TimeCreated": T0, "Computer": "wks-1", "Image": "C:\\x.exe",
                                     "CommandLine": "x", "User": "m.rossi"}),
         {"actor", "time", "host"}),
        ("inventory_diff", _payload("inventory_diff",
                                    {"mac": "AA:BB:CC:DD:EE:FF", "ip": "10.20.0.77", "hostname": "plc-line4",
                                     "device_type": "plc", "sector": "ot", "seen_at": T0}, "10.20.0.77"),
         {"ip", "time", "host"}),
    ]


_PATHS = {"ip": "src_endpoint.ip", "actor": "actor.user.name", "time": "time", "host": "src_endpoint.hostname"}
_NEW = {"ip": "198.18.7.7", "actor": "zz-renamed", "time": T1, "host": "rot-host-9"}


def _dot(d, dotted):
    cur = d
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _parse(payload):
    ev, errs = negative_controls._get_ws2().normalize_one(copy.deepcopy(payload))
    return ev, errs


def _setter(field):
    return {"ip": mg.set_src_ip, "actor": mg.set_actor, "time": mg.set_time, "host": mg.set_hostname}[field]


def _getter(field):
    return {"ip": mg.get_src_ip, "actor": mg.get_actor, "time": mg.get_time, "host": mg.get_hostname}[field]


def parsed_field_moves(payload, field, setter=None):
    """(moved, before, after): does ``setter(payload, NEW)`` move the PARSED field to NEW? The
    check every adapter is held to; (b) runs it on a deliberately broken one."""
    setter = setter or _setter(field)
    before_ev, errs = _parse(payload)
    if before_ev is None or errs:
        return False, None, f"fixture does not parse: {errs}"
    work = copy.deepcopy(payload)
    ok = setter(work, _NEW[field])
    after_ev, errs = _parse(work)
    after = _dot(after_ev, _PATHS[field]) if after_ev else None
    return bool(ok) and after == _NEW[field], _dot(before_ev, _PATHS[field]), after


# --------------------------------------------------------------------------
def test_adapters_move_the_parsed_field() -> None:
    for label, payload, supports in _fixtures():
        for field in ("ip", "actor", "time", "host"):
            if field not in supports:
                continue
            moved, before, after = parsed_field_moves(payload, field)
            _check(f"(a) {label}: set_{'src_ip' if field == 'ip' else field} moves the PARSED "
                   f"{_PATHS[field]}", moved, f"{before!r} -> {after!r}")
            if field != "time":
                # the getter agrees with what the parser reads (so the 'old' value is not invented)
                got = _getter(field)(payload)
                _check(f"(a) {label}: get_{'src_ip' if field == 'ip' else field} reads what the parser "
                       "reads", got is not None and got == _dot(_parse(payload)[0], _PATHS[field]),
                       f"adapter={got!r} parsed={_dot(_parse(payload)[0], _PATHS[field])!r}")


def test_broken_adapter_is_caught() -> None:
    label, payload, _ = next(f for f in _fixtures() if f[0] == "db_audit")

    def bad_set_ip(p, ip):             # edits a key the db_audit parser never reads, claims success
        p["raw"]["ip_typo"] = ip
        return True

    moved, before, after = parsed_field_moves(payload, "ip", setter=bad_set_ip)
    _check("(b) NEGATIVE control: an adapter that edits a key the parser ignores is caught by the "
           "parsed-field check (changed>0 would still have said 'applicable')", moved is False,
           f"{before!r} -> {after!r}")
    # and the real adapter, on the very same payload, passes (the check can say yes)
    moved, *_ = parsed_field_moves(payload, "ip")
    _check("(b) ...while the real db_audit adapter passes the same check", moved is True)


def test_missing_adapters_are_na() -> None:
    by = {name: p for name, p, _ in _fixtures()}
    for label, field, setter in (("modbus_anomaly", "actor", mg.set_actor), ("cisco_asa", "actor", mg.set_actor),
                                 ("cef", "host", mg.set_hostname), ("sysmon:process", "ip", mg.set_src_ip),
                                 ("db_audit", "host", mg.set_hostname)):
        work = copy.deepcopy(by[label])
        ok = setter(work, "x-y")
        _check(f"(c) {label}: no {field} to rewrite -> returns False and leaves the payload untouched "
               "(the variant is N/A, never a silent pass)", ok is False and work == by[label])
    p = copy.deepcopy(by["windows_eventlog"])
    p["raw"]["WorkstationName"] = "-"
    _check("(c) a Windows '-' workstation is ABSENCE, not a name to rewrite",
           mg.get_hostname(p) is None and mg.set_hostname(p, "x") is False)


# --------------------------------------------------------------------------
def _spec(label: str) -> ChainStepSpec:
    return ChainStepSpec(label, "x", True, label)


def _burst(label, source_type, raws, t0, gap_ms, ip=None) -> list:
    return [(_spec(label), {"source_type": source_type, "raw": r,
                            "meta": _meta(t0 + i * gap_ms, ip, i)}) for i, r in enumerate(raws)]


class _Sd:
    """The two attributes ``mutate_generic.apply`` reads from a ScenarioDef."""
    def __init__(self, labels):
        self.steps = tuple(_spec(x) for x in labels)
        self.decoy = None


def _fires(probe, payloads, rule_title_part: str, step: str) -> bool:
    alerts = probe.detect(probe_session.payloads_to_pairs(payloads))
    return any(rule_title_part in a["rule_title"] and a.get("step") == step for a in alerts)


def test_time_of_day_variants(probe) -> None:
    admin = [(_spec("admin"), {"source_type": "windows_eventlog",
                               "raw": {"EventID": 4672, "SubjectUserName": "adm", "Computer": "dc01",
                                       "TimeCreated": T0},
                               "meta": _meta(T0)})]
    sd = _Sd(["admin"])
    night, ch_n = mg.apply(admin, "timing", "to_night", seed=7, sdef=sd)
    day, ch_d = mg.apply(admin, "timing", "to_business_hours", seed=7, sdef=sd)
    _check("(d) the base stream (Wed 23:46 UTC) trips the after-hours admin rule",
           _fires(probe, admin, "outside business hours", "admin"))
    t_day = mg.get_time(day[0][1])
    dt = datetime.fromtimestamp(t_day / 1000.0, tz=timezone.utc)
    _check("(d) to_business_hours lands on the next WEEKDAY at 10:30 UTC", ch_d == 1 and dt.weekday() < 5
           and (dt.hour, dt.minute, dt.second) == (10, 30, 0), f"{dt.isoformat()}")
    _check("(d) POSITIVE+NEGATIVE: the SAME rule goes silent once the stream is moved into business "
           "hours, and fires again when moved to 03:00 (the predicate is exercised both ways)",
           not _fires(probe, day, "outside business hours", "admin")
           and _fires(probe, night, "outside business hours", "admin") and ch_n == 1)
    dt_n = datetime.fromtimestamp(mg.get_time(night[0][1]) / 1000.0, tz=timezone.utc)
    _check("(d) to_night lands at 03:00 UTC on the next day", (dt_n.hour, dt_n.minute) == (3, 0)
           and dt_n.date() > datetime.fromtimestamp(T0 / 1000.0, tz=timezone.utc).date(), dt_n.isoformat())
    # a pure shift: spacing and order preserved
    stream = _burst("b", "dns_query", [f"query[A] n{i}.example.invalid from 10.1.1.1" for i in range(5)],
                    T0, 7_000, "10.1.1.1")
    out, ch = mg.apply(stream, "timing", "to_business_hours", seed=7, sdef=_Sd(["b"]))
    ts_in = [mg.get_time(p) for _s, p in stream]
    ts_out = [mg.get_time(p) for _s, p in out]
    _check("(d) both are PURE shifts: every inter-event gap is preserved",
           ch == 5 and [b - a for a, b in zip(ts_in, ts_in[1:])] == [b - a for a, b in zip(ts_out, ts_out[1:])])
    # a Friday-night stream goes to MONDAY, not to a weekend day
    fri = int(datetime(2025, 7, 4, 23, 0, tzinfo=timezone.utc).timestamp() * 1000)
    fp = [(_spec("a"), {"source_type": "dns_query", "raw": "query[A] a.example.invalid from 10.1.1.1",
                        "meta": _meta(fri)})]
    out, _ = mg.apply(fp, "timing", "to_business_hours", seed=7, sdef=_Sd(["a"]))
    dt = datetime.fromtimestamp(mg.get_time(out[0][1]) / 1000.0, tz=timezone.utc)
    _check("(d) a Friday-night stream skips the weekend (next weekday is Monday)", dt.weekday() == 0,
           dt.isoformat())
    # the target is always the NEXT day's clock time, so a stream is never already "at" it: the
    # variant is N/A only when there is nothing to move
    _check("(d) an empty stream: changed=0 (N/A), never a claimed change",
           mg.apply([], "timing", "to_night", seed=7, sdef=_Sd([]))[1] == 0
           and mg.apply([], "timing", "to_business_hours", seed=7, sdef=_Sd([]))[1] == 0)


def test_jitter_period(probe) -> None:
    beats = [{"EventID": 3, "TimeCreated": T0 + i * 60_000, "Computer": "wks-1", "Image": "C:\\beacon.exe",
              "User": "m.rossi", "SourceIp": "10.9.0.5", "SourceHostname": "wks-1",
              "DestinationIp": "203.0.113.9", "DestinationPort": "443"} for i in range(8)]
    stream = _burst("beacon", "sysmon", beats, T0, 60_000, "10.9.0.5")
    stream += [(_spec("single"), {"source_type": "sysmon",
                                  "raw": {"EventID": 1, "TimeCreated": T0, "Computer": "wks-1",
                                          "Image": "C:\\w.exe", "User": "m.rossi"},
                                  "meta": _meta(T0)})]
    sd = _Sd(["beacon", "single"])
    _check("(e) NEGATIVE control: the un-jittered 8-beat, 60 s schedule FIRES the periodic rule "
           "(so a jittered stream going silent means something)", _fires(probe, stream, "beaconing", "beacon"))
    a, ch = mg.apply(stream, "pacing", "jitter_100pct", seed=7, sdef=sd)
    b, _ = mg.apply(stream, "pacing", "jitter_100pct", seed=7, sdef=sd)
    _check("(e) jitter_100pct is deterministic for a fixed seed", a == b)
    deltas = [abs(mg.get_time(pa) - mg.get_time(pb)) for (_s, pa), (_t, pb) in zip(a, stream)]
    _check("(e) every event moves by at most one PERIOD (60 s) -- never more; the single-event step "
           "is untouched", max(deltas) <= 60_000 and deltas[-1] == 0 and 0 < ch <= len(beats), f"max={max(deltas)}")
    _check("(e) the operator never mutates its input", stream[0][1]["raw"]["TimeCreated"] == T0)
    # across seeds: the rule is evaded in most draws (about 2% residual per the critic's simulation);
    # the claim is MEASURED here, not assumed, and at least one draw must evade
    evaded = []
    for seed in (7, 11, 13, 17, 19, 23, 29, 31):
        out, _ = mg.apply(stream, "pacing", "jitter_100pct", seed=seed, sdef=sd)
        evaded.append(not _fires(probe, out, "beaconing", "beacon"))
    _check("(e) POSITIVE control: +/-100%-of-period jitter evades the periodic rule (measured over 8 seeds)",
           any(evaded), f"evaded in {sum(evaded)}/8 seeds {evaded}")
    # a stream with no burst is untouched => N/A
    solo = [stream[-1]]
    out, ch = mg.apply(solo, "pacing", "jitter_100pct", seed=7, sdef=sd)
    _check("(e) a storyline with no burst step: changed=0 -> N/A, never a free pass", ch == 0 and out == solo)


def test_hostname_rotate(probe) -> None:
    users = [f"user{i}" for i in range(6)]
    raws = [{"EventID": 4625, "TargetUserName": u, "Computer": "dc01", "IpAddress": "-",
             "WorkstationName": "wks-attacker", "TimeCreated": T0 + i * 5_000} for i, u in enumerate(users)]
    stream = _burst("spray", "active_directory", raws, T0, 5_000)
    sd = _Sd(["spray"])
    _check("(f) NEGATIVE control: 6 distinct accounts failing from ONE workstation FIRE the "
           "workstation-keyed rule", _fires(probe, stream, "source IP not recorded", "spray"))
    out, ch = mg.apply(stream, "distribution", "hostname_rotate_all", seed=7, sdef=sd)
    hosts = {mg.get_hostname(p) for _s, p in out}
    _check("(f) hostname_rotate_all gives every event its own workstation name", ch == 6 and len(hosts) == 6,
           f"{len(hosts)} names")
    _check("(f) FINDING (measured; the rule's own group_by predicts it): a client that simply lies about "
           "its workstation name bypasses common_bruteforce_sourceless",
           not _fires(probe, out, "source IP not recorded", "spray"))
    # N/A on a source with no workstation name
    dns = _burst("d", "dns_query", [f"query[A] n{i}.example.invalid from 10.1.1.1" for i in range(4)],
                 T0, 1_000, "10.1.1.1")
    out, ch = mg.apply(dns, "distribution", "hostname_rotate_all", seed=7, sdef=_Sd(["d"]))
    _check("(f) a source that records no workstation name -> changed=0 (N/A)", ch == 0)


def main() -> int:
    probe = probe_session.FastProbe(strict_clock=False)
    test_adapters_move_the_parsed_field()
    test_broken_adapter_is_caught()
    test_missing_adapters_are_na()
    test_time_of_day_variants(probe)
    test_jitter_period(probe)
    test_hostname_rotate(probe)
    if _FAILURES:
        print(f"\n[FAIL] {len(_FAILURES)} check(s) failed:")
        for f in _FAILURES:
            print(f"   - {f}")
        return 1
    print("\n[OK] mutation adapters: every adapter moves the parsed field and every wave-2 variant passed "
          "its positive AND negative control.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
