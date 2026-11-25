"""storyline_flow_suricata_c2_exfil -- a long-lived C2 channel on a workstation that a Suricata sensor watches,
internal credential brute force from it, DNS tunnelling over one UDP socket, RDP lateral movement to a file server,
a privileged-group add and a large outbound upload.

Registered by ``scenario_registry._discover`` (module name ``storyline_*``, exports ``STORYLINE``).

    c2_checkin -> ad_bruteforce -> dns_tunnel -> dns_tunnel_resume -> lateral_logons -> rdp_lateral_alert
        -> priv_grant -> c2_tasking -> rdp_clipboard_alert -> c2_staging -> exfil_alert -> exfil_close -> c2_close

WHY IT EXISTS (ADR-012 WP 7, basis ``network_flow``). Four Suricata flows (all on ONE sensor, ``perimeter-ids``)
each raise SEVERAL DISTINCT alerts, so each is a chain of alert-raising records on one ``flow_id``:

    * the C2 channel (one TLS flow, ~4 h): three severity-1 signatures in three different hours
      (``common_ids_high_severity_alert``), then the flow record when it ends, carrying 1.6 GiB to the outside
      (``common_large_outbound_flow``): four alerts, three links;
    * the DNS tunnel (one UDP socket, two bursts of 40+ names three minutes apart; ``common_dns_exfil``): two
      alerts, one link;
    * the RDP session (one flow, two severity-1 signatures 75 minutes apart): two alerts, one link;
    * the upload (one TLS flow: a severity-1 signature, then the flow record with 1.3 GiB): two alerts, one link.

The builder mints the ``flow_id`` values itself (``flow_kit``) and the oracle's ``causal_links`` are DERIVED from
the TRIGGER records only (``derive_causal_links``), never typed and never read from the parser's output.

NO FOLDING, BY DESIGN. ``common_ids_high_severity_alert`` and ``common_dns_exfil`` are stateful: their alert id is
(rule, group, window bucket), so two hits of one rule on one flow inside one bucket upsert ONE alert and ws8 keeps
only its last version (the earlier step would then have no alert of its own). Every step on a flow here therefore
sits in its own bucket (severity-1 hits more than one hour apart, DNS bursts more than 60 s apart) or on a different
rule (IDS alert, then the flow-end rule), so each step owns a distinct alert id. The attribution rule for an alert id
that DOES fold is ONE rule everywhere (grader, report.py, test_timeline_order): the earliest step owns it.

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
_GIB = 1024 ** 3
_DNS_THRESHOLD = 40                          # common_dns_exfil: 40 distinct names / 60 s

IDS = Sensor("perimeter-ids", "suricata", "10.0.0.250")
IDS_B = Sensor("dmz-ids", "suricata", "10.0.1.250")

STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("c2_checkin", "suricata_eve", True,
                  "severity-1 IDS alert on the workstation's long TLS flow to an outside address (hour 1)"),
    ChainStepSpec("ad_bruteforce", "active_directory", True, "the workstation fails logon 11-13 times in under a minute"),
    ChainStepSpec("dns_tunnel", "suricata_eve", True,
                  "the workstation resolves 42-45 distinct names under one parent in ~53 s on ONE UDP socket"),
    ChainStepSpec("dns_tunnel_resume", "suricata_eve", True,
                  "three minutes later the SAME UDP socket carries 42-45 further distinct names in ~53 s"),
    ChainStepSpec("lateral_logons", "windows_eventlog", True,
                  "the guessed account logs on to six file servers from the workstation"),
    ChainStepSpec("rdp_lateral_alert", "suricata_eve", True,
                  "severity-1 IDS alert on one RDP flow from the workstation to a file server"),
    ChainStepSpec("priv_grant", "windows_eventlog", True,
                  "the account adds a backdoor service account to a privileged group on the DC"),
    ChainStepSpec("c2_tasking", "suricata_eve", True,
                  "second severity-1 signature on the SAME TLS flow, 75 minutes later (hour 3)"),
    ChainStepSpec("rdp_clipboard_alert", "suricata_eve", True,
                  "second severity-1 signature on the SAME RDP flow, 75 minutes later"),
    ChainStepSpec("c2_staging", "suricata_eve", True,
                  "third severity-1 signature on the SAME TLS flow, 75 minutes later (hour 5)"),
    ChainStepSpec("exfil_alert", "suricata_eve", True,
                  "severity-1 IDS alert on one outbound TLS upload flow from the workstation"),
    ChainStepSpec("exfil_close", "suricata_eve", True,
                  "the upload flow record (1.3 GiB to an outside address), written when it ends"),
    ChainStepSpec("c2_close", "suricata_eve", True,
                  "the long TLS flow record (1.6 GiB to an outside address), written when it finally ends"),
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
    exfil_dst = "203.0.113.250"
    victim = rng.choice(_VICTIMS)
    ws = f"10.30.4.{20 + seed % 9}"
    fs = "10.30.9.5"
    resolver = "10.30.0.53"
    n_fail = 11 + seed % 3                       # rule threshold: 10 failures / 60 s
    n_names = (42 + seed % 4) if n_names is None else n_names    # rule threshold: 40 distinct names / 60 s
    n_names2 = 42 + (seed + 1) % 4
    book = FlowBook(seed, "fsc", STEPS + (BYSTANDER,) + DECOY_STEPS)
    f_c2, f_rdp, f_ex, f_dns = book.flow_id(), book.flow_id(), book.flow_id(), book.flow_id()
    c2_src, c2_dst = (ws, 49822), (attacker, 443)
    dns_src, dns_dst = (ws, 42011), (resolver, 53)
    tls = {"severity": 1, "app_proto": "tls", "category": "A Network Trojan was detected"}

    t_checkin = START_MS + 5 * _MIN
    book.eve_alert("c2_checkin", IDS, t_checkin, f_c2, c2_src, c2_dst,
                   signature="ET MALWARE Cobalt Strike Beacon Observed", sid=2033120, **tls)

    for i in range(n_fail):                                              # 4 s apart: 12 failures span 44 s
        ts = START_MS + 20 * _MIN + i * 4_000
        book.raw("ad_bruteforce", "active_directory",
                 {"EventID": 4625, "TimeCreated": ts, "TargetUserName": victim, "TargetDomainName": "CORP",
                  "IpAddress": ws}, ts, ws)

    parent = "upd-sync.example"
    for step, t0, n in (("dns_tunnel", START_MS + 34 * _MIN, n_names),
                        ("dns_tunnel_resume", START_MS + 38 * _MIN + 5_000, n_names2)):
        for i in range(n):                                               # 1.2 s apart: ~53 s for 44 names, one socket
            book.eve_dns(step, IDS, t0 + i * 1_200, f_dns, dns_src, dns_dst,
                         f"{rng.getrandbits(48):012x}.{parent}", rrtype="TXT", tx_id=i,
                         trigger=i >= _DNS_THRESHOLD - 1)

    for i in range(6):                                                   # 25 s apart: six hosts inside 300 s
        ts = START_MS + 44 * _MIN + i * 25_000
        book.raw("lateral_logons", "windows_eventlog",
                 {"EventID": 4624, "TargetUserName": victim, "Computer": f"fs{i + 1:02d}", "IpAddress": ws,
                  "WorkstationName": "ws-" + ws.rsplit(".", 1)[1], "TimeCreated": ts}, ts, ws)

    rdp_src, rdp_dst = (ws, 51234), (fs, 3389)
    book.eve_alert("rdp_lateral_alert", IDS, START_MS + 50 * _MIN, f_rdp, rdp_src, rdp_dst,
                   signature="ET POLICY RDP session from workstation to server segment", sid=2034000,
                   category="Potentially Bad Traffic", severity=1, app_proto="rdp")
    ts = START_MS + 55 * _MIN
    book.raw("priv_grant", "windows_eventlog",
             {"EventID": 4728, "SubjectUserName": victim, "TargetUserName": "backdoor-svc", "Computer": "dc01",
              "IpAddress": ws, "TimeCreated": ts}, ts, ws)
    book.eve_alert("c2_tasking", IDS, START_MS + 80 * _MIN, f_c2, c2_src, c2_dst,
                   signature="ET MALWARE Cobalt Strike Malleable C2 Response", sid=2033121, **tls)
    book.eve_alert("rdp_clipboard_alert", IDS, START_MS + 125 * _MIN, f_rdp, rdp_src, rdp_dst,
                   signature="ET POLICY RDP Clipboard Redirection Bulk Transfer", sid=2034001,
                   category="Potentially Bad Traffic", severity=1, app_proto="rdp")
    book.eve_alert("c2_staging", IDS, START_MS + 155 * _MIN, f_c2, c2_src, c2_dst,
                   signature="ET MALWARE Cobalt Strike Beacon Large Download Staged", sid=2033122, **tls)
    t_ex = START_MS + 170 * _MIN
    ex_src, ex_dst = (ws, 49300), (exfil_dst, 443)
    book.eve_alert("exfil_alert", IDS, t_ex, f_ex, ex_src, ex_dst,
                   signature="ET POLICY Large Outbound TLS Upload to Rare Host", sid=2034010,
                   category="Potentially Bad Traffic", severity=1, app_proto="tls")
    book.eve_flow("exfil_close", IDS, t_ex - 60_000, START_MS + 240 * _MIN, f_ex, ex_src, ex_dst, app_proto="tls",
                  bytes_ts=int(1.3 * _GIB), bytes_tc=260_000, alerted=True, trigger=True)
    book.eve_flow("c2_close", IDS, t_checkin - 10_000, START_MS + 255 * _MIN, f_c2, c2_src, c2_dst, app_proto="tls",
                  bytes_ts=int(1.6 * _GIB), bytes_tc=15_000_000, alerted=True, trigger=True)

    # benign alert from a DIFFERENT sensor whose flow_id equals the C2 flow's (same value, other scope)
    book.eve_alert("bystander_other_sensor", IDS_B, START_MS - 2 * _MIN, f_c2, ("10.40.7.15", 52111),
                   ("192.0.2.80", 80), signature="ET POLICY Outdated Browser User-Agent", sid=2008120,
                   category="Potentially Bad Traffic", severity=3, app_proto="http")
    notes = {
        "c2_checkin": f"IDS alert on flow {f_c2} ({ws} -> {attacker}:443); the flow lives until +255 min",
        "ad_bruteforce": f"{ws} fails logon for {victim} {n_fail} times in under a minute",
        "dns_tunnel": f"{ws} resolves {n_names} distinct names under {parent} on one UDP socket (flow {f_dns})",
        "dns_tunnel_resume": f"the same socket carries {n_names2} further names three minutes later",
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
    """The network_flow truth links for ``seed``, derived from the keys this builder minted on its TRIGGER records
    (attack steps only: the bystander's other-scope key is context and must produce no link)."""
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
        # only the per-source rule: the oracle's dns_tunnel step expects common_dns_exfil alone (the by-domain
        # companion is not fired by a Suricata EVE dns record), so the restored twin must be judged on that rule.
        rule_ids=(_rule_id("common_dns_exfil"),),
        attribute="distinct names queried by the workstation in 60 s: 39, one under the rule's 40",
        build=lambda seed, restored: _build(seed, n_names=40 if restored else 39)),
)


STORYLINE = ScenarioDef(
    name="flow_suricata_c2_exfil",
    steps=STEPS,
    build=build,
    oracle_path=TWIN / "oracle_flow_suricata_c2_exfil.yaml",
    summary="a Suricata-watched C2 flow alerted in three different hours, internal brute force, DNS tunnelling "
            "over one UDP socket, RDP lateral movement, a privileged-group add and a 1.3 GiB upload, each flow "
            "with its own flow_id and several distinct alerts (network_flow truth links)",
    decoy=_build_decoys,
    decoy_steps=DECOY_STEPS + (BYSTANDER,),
    negatives=NEGATIVES,
)
