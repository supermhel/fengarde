"""storyline_flow_zeek_ot_pivot -- a compromised DMZ jump host scans an OT segment, guesses an engineering login,
tunnels data over ONE long DNS-over-TCP connection and reaches a PLC over ONE long Modbus/TCP session, all of it
seen by a Zeek sensor.

Registered by ``scenario_registry._discover`` (module name ``storyline_*``, exports ``STORYLINE``).

    refused_scan -> ssh_bruteforce -> dns_tunnel_open -> modbus_recon -> lateral_logons -> dns_tunnel_stage
        -> priv_grant -> modbus_write -> dns_tunnel_exfil -> modbus_restore -> dns_tunnel_final -> modbus_close
        -> dns_tunnel_close

WHY IT EXISTS (ADR-012 WP 7, basis ``network_flow``). Two Zeek ``uid`` values each tie several steps together:

    * the DNS-over-TCP tunnel is ONE TCP connection that carries FOUR bursts of 42-45 distinct names (open, stage,
      exfil, final), 16 to 28 minutes apart, in its ``dns.log`` rows, and one ``conn.log`` row written when the
      connection ends 100 minutes after it began. ``common_dns_exfil`` counts 40 distinct names per source in 60 s
      and its alert id carries the 60 s bucket, so each burst raises its OWN alert and all four carry the
      connection's uid: four alerts, three links;
    * the Modbus/TCP session is one TCP connection carrying a recon read, a write and a restore write in its
      ``modbus.log`` rows and one ``conn.log`` row. ``ot_write_unlisted_source`` (default-off, allowlist ships
      empty) is the rule that would read those writes and the twin runs the default rule set, so these steps are
      declared gaps and their records are context, not truth endpoints.

The builder mints the ``uid`` values itself (``flow_kit``; no import of ``services/shared/causal_keys.py``) and the
oracle's ``causal_links`` are DERIVED from the TRIGGER records only (``derive_causal_links``), not typed and not
read from parsed output.

THE SHARED-ENTITY NEGATIVE. ``bystander_hmi_poll`` is a legitimate HMI polling the SAME PLC address over its own
long Modbus connection (a different ``uid``). It shares the PLC with the attacker's session -- the entity join
sees one device -- and shares no flow with it: the oracle forbids ``modbus_write -> bystander_hmi_poll``, and no
network_flow link may join them.

WHAT IS HONEST ABOUT THE DETECTION SIDE. Rules fire on the scan (``common_refused_connection_scan``, a Zeek
conn_state rule), the tunnel's first burst (``common_dns_exfil``) and three Windows/Linux steps. No shipped rule
reads a Zeek Modbus row or a conn row of a completed session, so the other steps are declared gaps and their links
are ``unalerted`` endpoints. Zeek's HTTP and TLS logs are not parsed (``zeek_json.py`` drops them), so the flows
here are the DNS and Modbus ones.

TELEMETRY. Real parsers: ``zeek_json`` (conn / dns / modbus), ``linux_ssh``, ``windows_eventlog``. Simulation
only: documentation and private addresses, ``example`` domains, a fixed calendar epoch.
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

START_MS = epoch_ms(2025, 7, 16, 1, 0)       # Wed 2025-07-16 01:00 UTC
_MIN = 60_000
_DNS_THRESHOLD = 40                          # common_dns_exfil: 40 distinct names / 60 s

ZEEK = Sensor("dmz-zeek", "zeek", "10.20.0.251")

STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("refused_scan", "zeek_json", True, "the jump host is refused (S0/REJ) on 16 distinct ports of one OT host in ~30 s"),
    ChainStepSpec("ssh_bruteforce", "linux_ssh", True, "the jump host fails SSH logon 11-13 times in under a minute"),
    ChainStepSpec("dns_tunnel_open", "zeek_json", True,
                  "42-45 distinct names under one parent on ONE DNS-over-TCP connection in ~53 s"),
    ChainStepSpec("modbus_recon", "zeek_json", True, "five Modbus read requests on ONE long TCP session to the PLC"),
    ChainStepSpec("lateral_logons", "windows_eventlog", True, "the guessed account logs on to six hosts from the jump host"),
    ChainStepSpec("dns_tunnel_stage", "zeek_json", True, "42-45 further TXT names on the SAME DNS-over-TCP connection (second burst)"),
    ChainStepSpec("priv_grant", "windows_eventlog", True, "the account adds a backdoor service account to a privileged group"),
    ChainStepSpec("dns_backup_open", "zeek_json", True,
                  "42-45 distinct names under a second parent on a SECOND DNS-over-TCP connection (backup channel)"),
    ChainStepSpec("modbus_write", "zeek_json", True, "three Modbus write-single-coil requests on the SAME PLC session"),
    ChainStepSpec("dns_backup_resume", "zeek_json", True,
                  "42-45 further distinct names on the SAME backup connection, 14 minutes later"),
    ChainStepSpec("dns_tunnel_exfil", "zeek_json", True,
                  "42-45 data-carrying TXT names on the SAME DNS-over-TCP connection (third burst)"),
    ChainStepSpec("modbus_restore", "zeek_json", True, "two restoring Modbus writes on the SAME PLC session"),
    ChainStepSpec("dns_tunnel_final", "zeek_json", True, "42-45 last TXT names on the SAME DNS-over-TCP connection (fourth burst)"),
    ChainStepSpec("modbus_close", "zeek_json", True, "the PLC session's conn.log row, written when it ends"),
    ChainStepSpec("dns_tunnel_close", "zeek_json", True, "the tunnel connection's conn.log row, written when it ends"),
)
STEP_ORDER = [s.label for s in STEPS]

BYSTANDER = ChainStepSpec("bystander_hmi_poll", "zeek_json", True,
                          "a legitimate HMI polls the SAME PLC over its OWN long Modbus connection (BENIGN, other uid)")
DECOY_STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("decoy_asset_scanner", "zeek_json", True,
                  "an authorised asset scanner is refused on 16 ports of a different host (BENIGN, noisy: fires the scan rule on a disjoint host)"),  # noqa: E501
)

_VICTIMS = ("eng.ops", "plc.admin", "h.ortiz", "s.nakamura")


def _rule_id(stem: str) -> str:
    import yaml  # noqa: PLC0415
    path = TWIN.parents[1] / "contracts" / "rules" / f"{stem}.yml"
    return str(yaml.safe_load(path.read_text(encoding="utf-8"))["id"])


def _make(seed: int, *, n_ports: int | None = None):
    rng = Random(seed * 15485863 + 307)
    victim = rng.choice(_VICTIMS)
    jump = f"10.20.5.{14 + seed % 5}"
    plc = "10.50.1.10"
    resolver = "192.0.2.53"                       # the attacker-controlled authoritative resolver reached via the DMZ
    n_ports = (16 + seed % 3) if n_ports is None else n_ports   # rule threshold: 15 distinct ports / 60 s
    n_fail = 11 + seed % 3
    n_open = 42 + seed % 4                        # rule threshold: 40 distinct names / 60 s
    n_b1, n_b2 = 42 + (seed + 2) % 4, 42 + seed % 4
    n_stage, n_exfil, n_final = 42 + (seed + 1) % 4, 42 + (seed + 2) % 4, 42 + (seed + 3) % 4
    book = FlowBook(seed, "zop", STEPS + (BYSTANDER,) + DECOY_STEPS)
    u_t, u_mb, u_hmi, u_b = book.uid(), book.uid(), book.uid(), book.uid()
    t_src, t_dst = (jump, 51200), (resolver, 53)
    m_src, m_dst = (jump, 49901), (plc, 502)
    parent = "sync-cdn.example"

    for i in range(n_ports):                                             # 2 s apart: ~34 s, 16+ distinct ports
        ts = START_MS + i * 2_000
        book.zeek_conn("refused_scan", ZEEK, ts, 0.0, book.uid(), (jump, 40000 + i), (plc, 1000 + i * 7),
                       state="S0", history="S", orig_bytes=0, resp_bytes=0)

    for i in range(n_fail):                                              # 4 s apart: ~44 s
        ts = START_MS + 4 * _MIN + i * 4_000
        book.raw("ssh_bruteforce", "linux_ssh",
                 f"Jul 16 01:04:{i * 4:02d} eng-gw sshd[{3000 + i}]: Failed password for {victim} "
                 f"from {jump} port {52000 + i} ssh2", ts, jump)

    t_open = START_MS + 12 * _MIN
    for i in range(n_open):                                              # 1.2 s apart on ONE tcp connection
        book.zeek_dns("dns_tunnel_open", ZEEK, t_open + i * 1_200, u_t, t_src, t_dst,
                      f"{rng.getrandbits(48):012x}.{parent}", proto="tcp", qtype="TXT", trans_id=i + 1,
                      trigger=i >= _DNS_THRESHOLD - 1)

    t_recon = START_MS + 30 * _MIN
    for i in range(5):                                                   # one read every 20 s
        book.zeek_modbus("modbus_recon", ZEEK, t_recon + i * 20_000, u_mb, m_src, m_dst,
                         func="READ_HOLDING_REGISTERS", unit=1, tid=i + 1, address=100 + i)

    for i in range(6):                                                   # 25 s apart: six hosts inside 300 s
        ts = START_MS + 36 * _MIN + i * 25_000
        book.raw("lateral_logons", "windows_eventlog",
                 {"EventID": 4624, "TargetUserName": victim, "Computer": f"eng{i + 1:02d}", "IpAddress": jump,
                  "WorkstationName": "jump-" + jump.rsplit(".", 1)[1], "TimeCreated": ts}, ts, jump)

    b_src, b_dst = (jump, 51300), ("192.0.2.54", 53)
    parent_b = "cdn-telemetry.example"

    def burst(step, t0, tid0, tag, n, uid, src, dst, zone):
        for i in range(n):                                               # 1.2 s apart on ONE tcp connection
            book.zeek_dns(step, ZEEK, t0 + i * 1_200, uid, src, dst, f"{tag}{i:02d}{rng.getrandbits(40):010x}.{zone}",
                          proto="tcp", qtype="TXT", trans_id=tid0 + i, trigger=i >= _DNS_THRESHOLD - 1)

    # EMITTED IN EVENT-TIME ORDER: the twin feeds ws4 in emission order, and a stateful 60 s window must see the
    # bursts in the order a sensor would have written them
    burst("dns_tunnel_stage", START_MS + 42 * _MIN, 100, "s", n_stage, u_t, t_src, t_dst, parent)
    ts = START_MS + 48 * _MIN
    book.raw("priv_grant", "windows_eventlog",
             {"EventID": 4728, "SubjectUserName": victim, "TargetUserName": "backdoor-svc", "Computer": "dc01",
              "IpAddress": jump, "TimeCreated": ts}, ts, jump)
    burst("dns_backup_open", START_MS + 52 * _MIN, 400, "b", n_b1, u_b, b_src, b_dst, parent_b)
    for i in range(3):
        book.zeek_modbus("modbus_write", ZEEK, START_MS + 55 * _MIN + i * 20_000, u_mb, m_src, m_dst,
                         func="WRITE_SINGLE_COIL", unit=1, tid=20 + i, address=2 + i)
    burst("dns_backup_resume", START_MS + 66 * _MIN, 500, "r", n_b2, u_b, b_src, b_dst, parent_b)
    burst("dns_tunnel_exfil", START_MS + 70 * _MIN, 200, "x", n_exfil, u_t, t_src, t_dst, parent)
    for i in range(2):
        book.zeek_modbus("modbus_restore", ZEEK, START_MS + 78 * _MIN + i * 20_000, u_mb, m_src, m_dst,
                         func="WRITE_SINGLE_COIL", unit=1, tid=30 + i, address=2 + i)
    burst("dns_tunnel_final", START_MS + 86 * _MIN, 300, "z", n_final, u_t, t_src, t_dst, parent)

    book.zeek_conn("modbus_close", ZEEK, t_recon - 10_000, (92 * _MIN - (t_recon - 10_000 - START_MS)) / 1000.0, u_mb,
                   m_src, m_dst, service="modbus", orig_bytes=620, resp_bytes=540)
    book.zeek_conn("dns_tunnel_close", ZEEK, t_open - 2_000, (100 * _MIN - (t_open - 2_000 - START_MS)) / 1000.0, u_t,
                   t_src, t_dst, service="dns", orig_bytes=51_000, resp_bytes=9_000)

    # the legitimate HMI: same PLC, its own long connection (different uid), one read a minute, ending before the write
    for i in range(30):
        book.zeek_modbus("bystander_hmi_poll", ZEEK, START_MS + 20 * _MIN + i * _MIN, u_hmi, ("10.50.2.20", 50110),
                         m_dst, func="READ_HOLDING_REGISTERS", unit=1, tid=500 + i, address=0)
    notes = {
        "refused_scan": f"{jump} is refused (S0) on {n_ports} distinct ports of {plc}",
        "ssh_bruteforce": f"{jump} fails SSH logon for {victim} {n_fail} times",
        "dns_tunnel_open": f"{n_open} distinct names under {parent} on tcp connection {u_t}",
        "lateral_logons": f"{victim} logs on to six hosts from {jump} in 125 s",
        "priv_grant": f"{victim} adds backdoor-svc to a privileged group on dc01",
        "modbus_recon": f"five Modbus reads on tcp connection {u_mb} ({jump} -> {plc}:502)",
    }
    return book, notes


def _build(seed: int, *, n_ports: int | None = None):
    book, notes = _make(seed, n_ports=n_ports)
    return book.payloads, {}, notes, None


def build(seed: int):
    return _build(seed)


def derive_causal_links(seed: int = 7) -> list:
    """The network_flow truth links for ``seed``, derived from the uids this builder minted (the HMI's uid is a
    different group, so the bystander yields no link)."""
    book, _notes = _make(seed)
    return flow_kit.derive_links(book.notes, STEP_ORDER)


def key_notes(seed: int = 7) -> tuple:
    book, _n = _make(seed)
    return book.notes, STEP_ORDER


def _build_decoys(seed: int) -> list:
    """An authorised asset scanner: refused on 16 distinct ports of another host (fires the scan rule on a disjoint host)."""
    book = FlowBook(seed, "zopd", STEPS + (BYSTANDER,) + DECOY_STEPS)
    for i in range(16):
        book.zeek_conn("decoy_asset_scanner", ZEEK, START_MS + 3_000 + i * 2_000, 0.0, book.uid(),
                       ("10.20.6.9", 41000 + i), ("10.50.3.30", 2000 + i * 11), state="REJ", history="Sr")
    return book.payloads


NEGATIVES: tuple[NegativeTwin, ...] = (
    NegativeTwin(
        name="refused_14_of_15_ports", step="refused_scan", rule_ids=(_rule_id("common_refused_connection_scan"),),
        attribute="distinct destination ports refused (S0/REJ) for the one source in 60 s: 14, one under the rule's 15",
        build=lambda seed, restored: _build(seed, n_ports=15 if restored else 14)),
)


STORYLINE = ScenarioDef(
    name="flow_zeek_ot_pivot",
    steps=STEPS,
    build=build,
    oracle_path=TWIN / "oracle_flow_zeek_ot_pivot.yaml",
    summary="a DMZ jump host scans an OT segment, guesses a login, tunnels over ONE DNS-over-TCP connection and "
            "reaches a PLC over ONE Modbus/TCP session, each connection a Zeek uid (network_flow truth links)",
    decoy=_build_decoys,
    decoy_steps=DECOY_STEPS + (BYSTANDER,),
    negatives=NEGATIVES,
)
