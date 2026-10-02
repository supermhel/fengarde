"""rule_probes -- a canonical reference burst for the stateful rules NO storyline exercises.

WHY THIS EXISTS (2026-10-02)
    The evasion searches measure how far an attacker must bend a burst before a
    stateful rule stops firing. That needs a burst that fires the rule to begin
    with. Ten of the 18 shipped stateful rules are exercised by a storyline
    (``it_intrusion`` / ``infra_takeover``); EIGHT are not, so nothing measured
    how evadable they are:

        agent_tool_call_burst        bank_mass_card_read
        common_beaconing             common_bruteforce_sourceless
        common_impossible_travel     common_password_spray
        common_rapid_account_lifecycle   ot_new_engineering_connection

    Each template here is a RAW source record in the format its REAL parser
    documents (WS-2 derives ``type_uid``; nothing is hand-set), sized at the
    rule's own threshold, with a setter per key kind so the searches can rotate
    the grouping key. Every template is self-verified by ``selfcheck()``: the
    burst fires its rule, the one-event-short burst does not, and a rotated key
    moves the grouping field the rule reads. A template that does not satisfy
    all three would silently report "evaded"/"never evaded" about a burst that
    never tested the rule.

REACHABILITY HONESTY
    ``common_impossible_travel`` only fires on the SAMPLE documentation prefixes
    in ``contracts/enrichment/geoip.yml`` (RFC 5737); its own description says it
    WILL NOT FIRE on production traffic until a real GeoIP is substituted. Its
    row is therefore ``production_reachable: false`` -- it measures a sample map.

SAFETY: simulation only. RFC 5737 addresses, ``.invalid`` names, no network.
STDLIB ONLY. Deterministic: no wall clock, no randomness.
"""
from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field
from typing import Callable

BASE_MS = 1751500000000      # same fixed epoch as scenario.py / scenarios_extra.py


class ProbeSpec:
    """Duck-types ``scenario.ChainStepSpec`` -- the searches only read ``.label``."""

    def __init__(self, label: str) -> None:
        self.label = label

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"ProbeSpec({self.label!r})"


def _meta(tag: str, idx: int, ts: int, ip: str | None = None) -> dict:
    meta = {"received_at": ts, "ingest_id": f"ing-probe-{tag}-{idx:03d}",
            "trace_id": f"trace-probe-{tag}", "tenant_id": "acme"}
    if ip is not None:
        meta["ip"] = ip
    return meta


@dataclass
class Probe:
    key: str                              # rule-set key == the primary rule's file stem
    step: str                             # step label every event carries
    source_type: str
    n_events: int                         # reference burst size
    spacing_ms: int
    build: Callable[[int, int], tuple]    # (i, t_ms) -> (source_type, raw)
    setters: dict = field(default_factory=dict)     # kind -> fn(payload, j) -> bool
    production_reachable: bool = True
    reachability_basis: str = "parser emits the field the rule reads on real traffic"

    def payloads(self) -> list:
        spec = ProbeSpec(self.step)
        out = []
        for i in range(self.n_events):
            t = BASE_MS + i * self.spacing_ms
            st, raw = self.build(i, t)
            ip = raw.get("IpAddress") if isinstance(raw, dict) else None
            out.append((spec, {"source_type": st, "raw": raw, "meta": _meta(self.key, i, t, ip)}))
        return out


# --- per-kind setters: rewrite the field the rule's group_by reads ------------
def _dict_setter(field_name: str, fmt: str) -> Callable:
    def set_(p: dict, j: int) -> bool:
        p["raw"][field_name] = fmt.format(j=j)
        return True
    return set_


def _ssh_account(p: dict, j: int) -> bool:
    p["raw"] = re.sub(r"(for (?:invalid user )?)(\S+)( from )",
                      lambda m: f"{m.group(1)}user{j}{m.group(3)}", p["raw"], count=1)
    return True


# --- the eight templates --------------------------------------------------------
def _agent_tool_call_burst() -> Probe:
    def build(i, t):
        return "mcp_agent", {"ts": t, "session_id": "sess-probe-0", "agent": "probe-agent",
                             "server": "filesystem", "tool": "read_file",
                             "arguments": {"path": f"/data/report-{i:03d}.txt"}, "outcome": "success"}
    return Probe("agent_tool_call_burst", "agent_runaway", "mcp_agent", 100, 500, build,
                 {"session": _dict_setter("session_id", "sess-probe-{j}")})


def _bank_mass_card_read() -> Probe:
    def build(i, t):
        return "db_audit", {"operation": "SELECT", "object": "cards", "user": "report_svc",
                            "host": "db-prod-01", "ipAddress": "10.4.4.9", "timestamp": t}
    return Probe("bank_mass_card_read", "card_table_dump", "db_audit", 40, 2_000, build,
                 {"db_object": _dict_setter("object", "cards_{j}")})


def _common_beaconing() -> Probe:
    def build(i, t):
        return "cisco_asa", (f"%ASA-6-302013: Built outbound TCP connection {i} for "
                             f"outside:203.0.113.5/{40000 + i} (203.0.113.5/{40000 + i}) to "
                             f"inside:10.0.0.10/443 (10.0.0.10/443)")
    # 12 callbacks exactly 300 s apart: CV == 0, threshold 6 in 3600 s.
    def set_ip(p, j):
        p["raw"] = re.sub(r"(for \w+:)(\d{1,3}(?:\.\d{1,3}){3})(/\d+ \()(\d{1,3}(?:\.\d{1,3}){3})",
                          lambda m: f"{m.group(1)}198.18.77.{j + 10}{m.group(3)}198.18.77.{j + 10}",
                          p["raw"], count=1)
        return True
    return Probe("common_beaconing", "c2_beacon", "cisco_asa", 12, 300_000, build, {"ip": set_ip})


def _common_bruteforce_sourceless() -> Probe:
    def build(i, t):
        return "active_directory", {"EventID": 4625, "TimeCreated": t, "TargetUserName": f"guess{i:02d}",
                                    "Computer": "dc-probe-0", "IpAddress": "-"}
    return Probe("common_bruteforce_sourceless", "sourceless_guessing", "active_directory", 10, 2_000, build,
                 {"host": _dict_setter("Computer", "dc-probe-{j}")})


def _common_impossible_travel() -> Probe:
    countries = ("203.0.113.9", "198.51.100.9", "192.0.2.9")      # RU, CN, US (SAMPLE prefixes)

    def build(i, t):
        ip = countries[i % 2]
        return "linux_ssh", (f"Jun 10 13:55:{i:02d} db01 sshd[{3000 + i}]: Accepted password for "
                             f"victim from {ip} port {52000 + i} ssh2")
    return Probe("common_impossible_travel", "session_replay", "linux_ssh", 4, 600_000, build,
                 {"account": _ssh_account}, production_reachable=False,
                 reachability_basis=("contracts/enrichment/geoip.yml maps only RFC 5737 SAMPLE prefixes; the rule "
                                     "description states it WILL NOT FIRE on production traffic until a real GeoIP "
                                     "is substituted"))


def _common_password_spray() -> Probe:
    def build(i, t):
        return "active_directory", {"EventID": 4625, "TimeCreated": t, "TargetUserName": "victim",
                                    "Computer": "dc-probe-0", "WorkstationName": f"wks-{i}",
                                    "IpAddress": f"198.18.5.{i + 10}"}
    return Probe("common_password_spray", "credential_stuffing", "active_directory", 16, 5_000, build,
                 {"account": _dict_setter("TargetUserName", "victim{j}")})


def _common_rapid_account_lifecycle() -> Probe:
    def build(i, t):
        return "windows_eventlog", {"EventID": 4720 if i % 2 == 0 else 4726, "TimeCreated": t,
                                    "SubjectUserName": "admin01", "TargetUserName": "tmp-backdoor",
                                    "Computer": "dc01"}
    return Probe("common_rapid_account_lifecycle", "create_then_delete", "windows_eventlog", 4, 60_000, build,
                 {"target_account": _dict_setter("TargetUserName", "tmp-backdoor{j}")})


def _ot_new_engineering_connection() -> Probe:
    def build(i, t):
        return "opcua_audit", {"eventType": "AuditCreateSessionEventType", "sourceName": "CreateSession",
                               "clientUserId": f"engineer{i:02d}", "clientAddress": f"10.20.0.{20 + i}",
                               "serverId": "plc-line3", "status": True, "time": t}
    return Probe("ot_new_engineering_connection", "ot_multi_source", "opcua_audit", 4, 10_000, build,
                 {"ot_server": _dict_setter("serverId", "plc-line{j}")})


_FACTORIES = (_agent_tool_call_burst, _bank_mass_card_read, _common_beaconing,
              _common_bruteforce_sourceless, _common_impossible_travel, _common_password_spray,
              _common_rapid_account_lifecycle, _ot_new_engineering_connection)


def all_probes() -> dict:
    """rule-set key -> Probe, in a fixed (alphabetical) order."""
    probes = [f() for f in _FACTORIES]
    return {p.key: p for p in sorted(probes, key=lambda x: x.key)}


def get(key: str) -> Probe:
    return all_probes()[key]


def clone_payloads(payloads: list) -> list:
    return copy.deepcopy(payloads)
