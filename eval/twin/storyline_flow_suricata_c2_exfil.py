"""storyline_flow_suricata_c2_exfil -- a long-lived C2 channel on a workstation that a Suricata sensor watches,
internal credential brute force from it, DNS tunnelling, RDP lateral movement to a file server, a privileged-group
add and an exfil upload.

Registered by ``scenario_registry._discover`` (module name ``storyline_*``, exports ``STORYLINE``).

    c2_checkin -> ad_bruteforce -> c2_tasking -> dns_tunnel -> lateral_logons -> rdp_lateral_alert -> priv_grant
        -> c2_staging -> exfil_alert -> c2_exfil_ack -> rdp_close -> exfil_close -> c2_close

WHY IT EXISTS (ADR-012 WP 7, basis ``network_flow``). Several steps are linked by ONE Suricata ``flow_id`` on ONE
sensor (``perimeter-ids``): the C2 channel is a single TLS flow that lives ~2.8 hours, so the IDS raises an alert
on it at four different moments and writes its flow record when it finally ends; the RDP session and the exfil
upload are each one flow with an alert at the start and a flow record at the end. The builder mints those
``flow_id`` values itself (``flow_kit``) and the oracle's ``causal_links`` are DERIVED from them
(``derive_causal_links``), never typed and never read from the parser's output.

WHAT IS HONEST ABOUT THE DETECTION SIDE. No shipped rule reads a Suricata alert or flow record, so the nine
Suricata alert / flow-close steps are declared gaps (``no_rule_exists``); the incident forms from the four steps
that DO fire (AD brute force, DNS tunnelling, Windows lateral logons, a privileged-group add), all keyed on the
workstation's address. The links on the gap steps are therefore ``unalerted`` endpoints in ADR-012's vocabulary,
not gradable links, until a rule reads them.

SCOPE. ``bystander_other_sensor`` is a benign alert from a SECOND sensor (``dmz-ids``) whose ``flow_id`` is
numerically IDENTICAL to the C2 flow's: a value comparison across sensors would link it, a scoped one must not
(ADR-012 "scope bugs"). It shares no address with the attack.

TELEMETRY. Real parsers: ``active_directory`` (4625), ``windows_eventlog`` (4624, 4728), ``suricata_eve`` (alert /
flow / dns). Native raw shapes. Simulation only: RFC 5737 documentation addresses outside, private addresses
inside, ``example`` domains, a fixed calendar epoch.
"""
from __future__ import annotations

import sys
from pathlib import Path
from random import Random

TWIN = Path(__file__).resolve().parent
if str(TWIN) not in sys.path:
    sys.path.insert(0, str(TWIN))

import flow_kit  # noqa: E402
from flow_kit import FlowBook, Sensor  # noqa: E402
from scenario import ChainStepSpec, NegativeTwin, ScenarioDef  # noqa: E402
from scenario_kit import epoch_ms  # noqa: E402

START_MS = epoch_ms(2025, 7, 15, 2, 0)       # Tue 2025-07-15 02:00 UTC
_MIN = 60_000

IDS = Sensor("perimeter-ids", "suricata", "10.0.0.250")
IDS_B = Sensor("dmz-ids", "suricata", "10.0.1.250")

STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("c2_checkin", "suricata_eve", True, 
                  "IDS alert on the workstation's long TLS flow to an outside address (first alert)"),
    ChainStepSpec("ad_bruteforce", "active_directory", True, "the workstation fails logon 11-13 times in under a minute"),
    ChainStepSpec("c2_tasking", "suricata_eve", True, "second IDS alert on the SAME TLS flow (tasking response)"),
    ChainStepSpec("dns_tunnel", "suricata_eve", True, "the workstation resolves 42-45 distinct names under one parent in ~53 s"),
    ChainStepSpec("lateral_logons", "windows_eventlog", True, "the guessed account logs on to six file servers from the workstation"),
    ChainStepSpec("rdp_lateral_alert", "suricata_eve", True, "IDS alert on one RDP flow from the workstation to a file server"),
    ChainStepSpec("priv_grant", "windows_eventlog", True, "the account adds a backdoor service account to a privileged group on the DC"),  # noqa: E501
    ChainStepSpec("c2_staging", "suricata_eve", True, "third IDS alert on the SAME TLS flow (large download staged)"),
    ChainStepSpec("exfil_alert", "suricata_eve", True, "IDS alert on one outbound TLS upload flow from the file server"),
    ChainStepSpec("c2_exfil_ack", "suricata_eve", True, "fourth IDS alert on the SAME TLS flow (exfil acknowledgement)"),
    ChainStepSpec("rdp_close", "suricata_eve", True, "the RDP flow record, written when that flow ends"),
    ChainStepSpec("exfil_close", "suricata_eve", True, "the upload flow record, written when that flow ends"),
    ChainStepSpec("c2_close", "suricata_eve", True, "the long TLS flow record, written when it finally ends"),
)
STEP_ORDER = [s.label for s in STEPS]

BYSTANDER = ChainStepSpec("bystander_other_sensor", "suricata_eve", True,
                          "a benign alert from a SECOND sensor whose flow_id equals the C2 flow's (BENIGN, other scope)")
DECOY_STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("decoy_resolver_burst", "suricata_eve", True,
                  "a CDN-heavy laptop resolves 42 distinct names under one vendor parent (BENIGN, noisy: fires the volume rule, disjoint host)"),  # noqa: E501
)

_ATTACKERS = ("203.0.113.21", "203.0.113.77", "203.0.113.130", "203.0.113.201")
_VICTIMS = ("svc_backup", "m.costa", "t.hale", "j.wong")


def _rule_id(stem: str) -> str:
    import yaml  # noqa: PLC0415
    path = TWIN.parents[1] / "contracts" / "rules" / f"{stem}.yml"
    return str(yaml.safe_load(path.read_text(encoding="utf-8"))["id"])


def _make(seed: int, *, n_names: int | None = None):
    rng = Random(seed * 15485863 + 211)
    attacker = rng.choice(_ATTACKERS)
    victim = rng.choice(_VICTIMS)
    ws = f"10.30.4.{20 + seed % 9}"
    fs = "10.30.9.5"
    resolver = "10.30.0.53"
    n_fail = 11 + seed % 3                       # rule threshold: 10 failures / 60 s
    n_names = (42 + seed % 4) if n_names is None else n_names    # rule threshold: 40 distinct names / 60 s
    book = FlowBook(seed, "fsc", STEPS + (BYSTANDER,) + DECOY_STEPS)
    f_c2, f_rdp, f_ex = book.flow_id(), book.flow_id(), book.flow_id()
    c2_src, c2_dst = (ws, 49822), (attacker, 443)

    t_checkin = START_MS
    book.eve_alert("c2_checkin", IDS, t_checkin, f_c2, c2_src, c2_dst, signature="ET MALWARE Cobalt Strike Beacon Observed",
                   sid=2033120, category="A Network Trojan was detected", severity=1, app_proto="tls")

    for i in range(n_fail):                                              # 4 s apart: 12 failures span 44 s
        ts = START_MS + 6 * _MIN + i * 4_000
        book.raw("ad_bruteforce", "active_directory",
                 {"EventID": 4625, "TimeCreated": ts, "TargetUserName": victim, "TargetDomainName": "CORP",
                  "IpAddress": ws}, ts, ws)

    book.eve_alert("c2_tasking", IDS, START_MS + 20 * _MIN, f_c2, c2_src, c2_dst,
                   signature="ET MALWARE Cobalt Strike Malleable C2 Response", sid=2033121,
                   category="A Network Trojan was detected", severity=1, app_proto="tls")

    parent = "upd-sync.example"
    names = [f"{rng.getrandbits(48):012x}.{parent}" for _ in range(n_names)]
    for i, name in enumerate(names):                                     # 1.2 s apart: ~53 s for 44 names
        ts = START_MS + 34 * _MIN + i * 1_200
        book.eve_dns("dns_tunnel", IDS, ts, book.flow_id(), (ws, 42000 + i), (resolver, 53), name, rrtype="TXT")

    for i in range(6):                                                   # 25 s apart: six hosts inside 300 s
        ts = START_MS + 44 * _MIN + i * 25_000
        book.raw("lateral_logons", "windows_eventlog",
                 {"EventID": 4624, "TargetUserName": victim, "Computer": f"fs{i + 1:02d}", "IpAddress": ws,
                  "WorkstationName": "ws-" + ws.rsplit(".", 1)[1], "TimeCreated": ts}, ts, ws)

    t_rdp = START_MS + 50 * _MIN
    book.eve_alert("rdp_lateral_alert", IDS, t_rdp, f_rdp, (ws, 51234), (fs, 3389),
                   signature="ET POLICY RDP session from workstation to server segment", sid=2034000,
                   category="Potentially Bad Traffic", severity=2, app_proto="rdp")
    ts = START_MS + 55 * _MIN
    book.raw("priv_grant", "windows_eventlog",
             {"EventID": 4728, "SubjectUserName": victim, "TargetUserName": "backdoor-svc", "Computer": "dc01",
              "IpAddress": ws, "TimeCreated": ts}, ts, ws)
    book.eve_alert("c2_staging", IDS, START_MS + 62 * _MIN, f_c2, c2_src, c2_dst,
                   signature="ET MALWARE Cobalt Strike Beacon Large Download Staged", sid=2033122,
                   category="A Network Trojan was detected", severity=1, app_proto="tls")
    t_ex = START_MS + 75 * _MIN
    book.eve_alert("exfil_alert", IDS, t_ex, f_ex, (fs, 49300), (attacker, 443),
                   signature="ET POLICY Large Outbound TLS Upload to Rare Host", sid=2034010,
                   category="Potentially Bad Traffic", severity=2, app_proto="tls")
    book.eve_alert("c2_exfil_ack", IDS, START_MS + 78 * _MIN, f_c2, c2_src, c2_dst,
                   signature="ET MALWARE Cobalt Strike Beacon Data Exfil Pattern", sid=2033123,
                   category="A Network Trojan was detected", severity=1, app_proto="tls")
    book.eve_flow("rdp_close", IDS, t_rdp - 10_000, START_MS + 95 * _MIN, f_rdp, (ws, 51234), (fs, 3389),
                  app_proto="rdp", bytes_ts=3_400_000, bytes_tc=21_000_000, alerted=True)
    book.eve_flow("exfil_close", IDS, t_ex - 60_000, START_MS + 100 * _MIN, f_ex, (fs, 49300), (attacker, 443),
                  app_proto="tls", bytes_ts=912_000_000, bytes_tc=260_000, alerted=True)
    book.eve_flow("c2_close", IDS, t_checkin - 10_000, START_MS + 170 * _MIN, f_c2, c2_src, c2_dst,
                  app_proto="tls", bytes_ts=4_100_000, bytes_tc=15_000_000, alerted=True)

    # benign alert from a DIFFERENT sensor whose flow_id equals the C2 flow's (same value, other scope)
    book.eve_alert("bystander_other_sensor", IDS_B, START_MS + 21 * _MIN, f_c2, ("10.40.7.15", 52111), ("192.0.2.80", 80),
                   signature="ET POLICY Outdated Browser User-Agent", sid=2008120, category="Potentially Bad Traffic",
                   severity=3, app_proto="http")
    notes = {
        "c2_checkin": f"IDS alert on flow {f_c2} ({ws} -> {attacker}:443); the flow lives until +170 min",
        "ad_bruteforce": f"{ws} fails logon for {victim} {n_fail} times in under a minute",
        "dns_tunnel": f"{ws} resolves {n_names} distinct names under {parent}",
        "lateral_logons": f"{victim} logs on to six file servers from {ws} in 125 s",
        "priv_grant": f"{victim} adds backdoor-svc to a privileged group on dc01",
    }
    return book, notes


def _build(seed: int, *, n_names: int | None = None):
    book, notes = _make(seed, n_names=n_names)
    return book.payloads, {}, notes, None


def build(seed: int):
    return _build(seed)


def derive_causal_links(seed: int = 7) -> list:
    """The network_flow truth links for ``seed``, derived from the keys this builder minted (attack steps only:
    the bystander's other-scope key is in the book and must produce no link)."""
    book, _notes = _make(seed)
    return flow_kit.derive_links(book.notes, STEP_ORDER)


def key_notes(seed: int = 7) -> tuple:
    """``(notes, step_order)`` for the measurement report and the tests."""
    book, _n = _make(seed)
    return book.notes, STEP_ORDER


def _build_decoys(seed: int) -> list:
    """A CDN-heavy laptop: 42 distinct names under one vendor parent (fires the per-source volume rule on its own host)."""
    book = FlowBook(seed, "fscd", STEPS + (BYSTANDER,) + DECOY_STEPS)
    for i in range(42):
        ts = START_MS + 34 * _MIN + 5_000 + i * 1_200
        book.eve_dns("decoy_resolver_burst", IDS, ts, book.flow_id(), ("10.30.8.77", 43000 + i), ("10.30.0.53", 53),
                     f"edge{i:02d}.cloudfront.net")
    return book.payloads


NEGATIVES: tuple[NegativeTwin, ...] = (
    NegativeTwin(
        name="dns_tunnel_39_of_40_names", step="dns_tunnel",
        rule_ids=(_rule_id("common_dns_exfil"), _rule_id("common_dns_tunnel_by_domain")),
        attribute="distinct names queried by the workstation in 60 s: 39, one under the rule's 40",
        build=lambda seed, restored: _build(seed, n_names=40 if restored else 39)),
)


STORYLINE = ScenarioDef(
    name="flow_suricata_c2_exfil",
    steps=STEPS,
    build=build,
    oracle_path=TWIN / "oracle_flow_suricata_c2_exfil.yaml",
    summary="a Suricata-watched C2 flow alerted four times, internal brute force, DNS tunnelling, RDP lateral "
            "movement, a privileged-group add and an exfil upload, each flow with its own flow_id "
            "(network_flow truth links)",
    decoy=_build_decoys,
    decoy_steps=DECOY_STEPS + (BYSTANDER,),
    negatives=NEGATIVES,
)
