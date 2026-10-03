"""storyline_phishing_bec -- phishing -> endpoint foothold -> account takeover -> business email compromise.

Registered by ``scenario_registry._discover`` (module name ``storyline_*``, exports ``STORYLINE``).

    phish_delivery -> user_execution -> c2_beacon -> victim_session -> proxy_pool_logins
        -> foreign_login -> inbox_rule -> payment_redirect

WHAT IT CAN SHOW THAT THE OTHER STORYLINES CANNOT
    * a PERIODIC rule (``common_beaconing``: coefficient of variation of inter-arrival times) and a
      DISTINCT-COUNTRY rule (``common_impossible_travel``) -- neither is a plain count-in-window;
    * an identity-provider attack on ONE account from MANY addresses (credential stuffing through a
      proxy pool), the inverse of the per-source brute force the older storylines have;
    * a detection that is only possible BECAUSE of an earlier benign step (``foreign_login`` needs
      ``victim_session``): the oracle's ``step_dependencies``;
    * honest gaps on four of eight steps with the ATT&CK technique each one demonstrates, and NO
      rule invented to make them pass (see ``oracle_phishing_bec.yaml``).

TELEMETRY. Real parsers throughout (sysmon, cef, db_audit). ``mail_gateway`` and ``m365_audit`` are
PLACEHOLDER source types with no parser BY DESIGN: their records dead-letter at the parser lookup
exactly like ai_to_ot's ``web_access``, are declared ``parse_expected=False`` and never claim a
type_uid. They are not planned parsers.

STRUCTURE VARIES WITH THE SEED (not only identifiers): the proxy-pool size (9-12 addresses), the
number of beacon beats (7-9), the beacon jitter, the victim account, the workstation, and every
address.

SAFETY. Simulation only: documentation-range addresses (RFC 5737), ``.invalid`` / ``example``
domains, fixed calendar timestamps (no wall clock). Geo map used by the impossible-travel rule:
192.0.2.0/24 = US, 198.51.100.0/24 = CN, 203.0.113.0/24 = RU.
"""
from __future__ import annotations

import sys
from pathlib import Path
from random import Random

TWIN = Path(__file__).resolve().parent
if str(TWIN) not in sys.path:
    sys.path.insert(0, str(TWIN))

from scenario import ChainStepSpec, NegativeTwin, ScenarioDef  # noqa: E402
from scenario_kit import BASE_MS, meta  # noqa: E402

STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("phish_delivery", "mail_gateway", False,
                  "spear-phishing mail with a macro attachment is delivered (no mail parser by design)"),
    ChainStepSpec("user_execution", "sysmon", True,
                  "the user opens the attachment: the office app spawns an encoded PowerShell"),
    ChainStepSpec("c2_beacon", "sysmon", True,
                  "the implant calls home at a regular interval (6+ outbound connections)"),
    ChainStepSpec("victim_session", "cef", True,
                  "the account's own earlier login from its home country (benign enabling telemetry)"),
    ChainStepSpec("proxy_pool_logins", "cef", True,
                  "credential stuffing of the account through a pool of proxy addresses"),
    ChainStepSpec("foreign_login", "cef", True,
                  "the attacker logs in successfully from a second country within the hour"),
    ChainStepSpec("inbox_rule", "m365_audit", False,
                  "a mailbox rule forwards and hides replies (no M365 parser by design)"),
    ChainStepSpec("payment_redirect", "db_audit", True,
                  "the vendor's bank account is changed in the finance application"),
)

_VICTIMS = ("m.rossi", "j.keller", "a.nguyen", "p.dubois")
_HOSTS = ("wks-fin-04", "wks-fin-11", "wks-ap-02", "wks-ap-09")
_IRREGULAR_GAPS_MS = (30_000, 95_000, 45_000, 130_000, 20_000, 110_000, 60_000, 25_000)

#: rule ids (contracts/rules/*.yml) the negative twins are about
_BEACONING = "f6071829-a3b4-4c53-9d6e-7f8091a2b526"
_SPRAY = "4f8a2c61-9e3d-4b57-8a1c-6d2e5f7a8b90"
_TRAVEL = "7081a2b3-c405-4de3-be5f-6a7b8c9d0e12"


def _cef(src: str, user: str, outcome: str, name: str) -> str:
    return f"CEF:0|Contoso|IdP|1.0|100|{name}|3|src={src} dst=10.0.0.9 suser={user} outcome={outcome}"


def _build(seed: int, *, n_pool: int | None = None, n_beats: int | None = None,
           irregular: bool = False, same_country: bool = False):
    """The one builder every twin shares. ``n_pool`` / ``n_beats`` / ``irregular`` /
    ``same_country`` override exactly one attribute of the seed-derived storyline and nothing else
    (all random draws happen before any override, so overriding never shifts another draw)."""
    rng = Random(seed * 15485863 + 29)
    victim = rng.choice(_VICTIMS)
    host = rng.choice(_HOSTS)
    wks_ip = f"10.9.0.{rng.randint(20, 60)}"
    drawn_pool = rng.randint(9, 12)               # rule threshold: 8 distinct source addresses / 300 s
    drawn_beats = rng.randint(7, 9)               # rule threshold: 6 regular connections
    jitter = [rng.randint(-3_000, 3_000) for _ in range(9)]
    home_ip = f"192.0.2.{rng.randint(10, 60)}"            # US
    away_ip = f"203.0.113.{rng.randint(30, 90)}"          # RU
    same_ip = f"192.0.2.{rng.randint(100, 140)}"          # US (the same-country twin)
    pool_base = rng.randint(10, 60)
    c2_ip = f"203.0.113.{rng.randint(200, 240)}"
    n_pool = drawn_pool if n_pool is None else n_pool
    n_beats = drawn_beats if n_beats is None else n_beats
    steps = {s.label: s for s in STEPS}
    ordinal = {s.label: i for i, s in enumerate(STEPS)}
    payloads: list = []
    notes: dict = {}
    seen: dict = {}

    def add(label: str, source_type: str, raw, ts: int, ip: str | None) -> None:
        # The ingest id is (step ordinal, position within the step), NOT a running counter: a twin that
        # adds or removes events of ONE step must not renumber the events of every later step, or
        # "differs from the attack by exactly one attribute" would not be true of the raw records.
        k = seen.get(label, 0)
        seen[label] = k + 1
        payloads.append((steps[label], {"source_type": source_type, "raw": raw,
                                        "meta": meta(seed, "bec", ordinal[label] * 100 + k, ts, ip)}))

    t = BASE_MS
    add("phish_delivery", "mail_gateway",
        {"from": "billing@vendor-update.example.invalid", "to": f"{victim}@corp.example",
         "subject": "Updated remittance details", "attachment": "Invoice_4471.docm",
         "verdict": "delivered", "ts": t}, t, "203.0.113.200")
    notes["phish_delivery"] = "macro attachment delivered by the mail gateway; no parser by design -> chained gap"

    t = BASE_MS + 45_000
    add("user_execution", "sysmon",
        {"EventID": 1, "TimeCreated": t, "Computer": host,
         "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0",
         "ProcessId": "4812", "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
         "ParentProcessId": "3300", "User": victim}, t, wks_ip)
    notes["user_execution"] = f"WINWORD spawns encoded PowerShell on {host} as {victim}"

    if irregular:
        times = [BASE_MS + 90_000]
        for g in _IRREGULAR_GAPS_MS[:max(0, n_beats - 1)]:
            times.append(times[-1] + g)
    else:
        times = [BASE_MS + 90_000 + i * 60_000 + jitter[i] for i in range(n_beats)]
    for i, tb in enumerate(times):
        add("c2_beacon", "sysmon",
            {"EventID": 3, "TimeCreated": tb, "Computer": host, "Image": "C:\\Users\\Public\\svc.exe",
             "User": victim, "SourceIp": wks_ip, "SourcePort": str(49_200 + i), "SourceHostname": host,
             "DestinationIp": c2_ip, "DestinationPort": "443",
             "DestinationHostname": "cdn-sync.example.invalid"}, tb, wks_ip)
    notes["c2_beacon"] = (f"{n_beats} outbound connections from {wks_ip} to {c2_ip}:443 "
                          + ("at irregular intervals" if irregular else "about every 60 s (+/-3 s)"))

    t = BASE_MS + 620_000                                     # after the beacon run: spans never overlap
    add("victim_session", "cef", _cef(home_ip, victim, "success", "User login"), t, home_ip)
    notes["victim_session"] = f"{victim} logs in from {home_ip} (US) -- the account's normal session"

    t = BASE_MS + 700_000
    for i in range(n_pool):                                   # 15 s apart -> 8th address at +105 s
        ip = f"198.51.100.{pool_base + i}"                    # CN, all distinct
        add("proxy_pool_logins", "cef", _cef(ip, victim, "failure", "User login failed"), t + i * 15_000, ip)
    notes["proxy_pool_logins"] = f"{n_pool} failed logins for {victim} from {n_pool} distinct addresses, 15 s apart"

    t = BASE_MS + 1_220_000                                   # 10 min after victim_session
    foreign = same_ip if same_country else away_ip
    add("foreign_login", "cef", _cef(foreign, victim, "success", "User login"), t, foreign)
    notes["foreign_login"] = (f"{victim} logs in from {foreign} ({'US, same country as the home session' if same_country else 'RU'})")

    t = BASE_MS + 1_300_000
    add("inbox_rule", "m365_audit",
        {"Operation": "New-InboxRule", "UserId": f"{victim}@corp.example", "ClientIP": away_ip,
         "Parameters": {"ForwardTo": "ap-desk@vendor-update.example.invalid", "DeleteMessage": True},
         "CreationTime": t}, t, away_ip)
    notes["inbox_rule"] = "forward-and-delete mailbox rule; no M365 parser by design -> chained gap"

    t = BASE_MS + 1_500_000
    add("payment_redirect", "db_audit",
        {"operation": "UPDATE", "object": "vendor_bank_accounts", "user": victim, "host": "erp-db-01",
         "ipAddress": away_ip, "timestamp": t}, t, away_ip)
    notes["payment_redirect"] = f"{victim} updates vendor_bank_accounts from {away_ip}"

    return payloads, {}, notes, None


def build(seed: int):
    return _build(seed)


# ---------------------------------------------------------------------------
# Benign look-alike: a legitimate user whose egress flips country (mobile network -> VPN). It is the
# DOCUMENTED false-positive shape of common_impossible_travel ("expect benign false-fires from
# VPN/mobile users"). Entities are disjoint from the attack's (own account, own addresses), and the
# decoy overlaps the attack window. A correct correlator keeps it out of the attack's incident.
# ---------------------------------------------------------------------------
DECOY_STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("decoy_vpn_roaming", "cef", True,
                  "a sales user's egress flips country when the VPN reconnects (BENIGN)"),
)


def _build_decoys(seed: int) -> list:
    spec = DECOY_STEPS[0]
    out: list = []
    for i, (ip, dt) in enumerate((("192.0.2.201", 750_000), ("198.51.100.201", 900_000))):
        ts = BASE_MS + dt
        out.append((spec, {"source_type": "cef", "raw": _cef(ip, "sales.vpn", "success", "User login"),
                           "meta": meta(seed, "becd", i, ts, ip)}))
    return out


# ---------------------------------------------------------------------------
# Boundary controls: each differs from the attack by exactly ONE attribute, built by the SAME
# builder with the attribute restored for the positive twin.
# ---------------------------------------------------------------------------
NEGATIVES: tuple[NegativeTwin, ...] = (
    NegativeTwin(
        name="spray_7_of_8_addresses", step="proxy_pool_logins", rule_ids=(_SPRAY,),
        attribute="distinct source addresses in the stuffing burst: 7, one under the rule's 8",
        build=lambda seed, restored: _build(seed, n_pool=8 if restored else 7)),
    NegativeTwin(
        name="beacon_5_of_6_beats", step="c2_beacon", rule_ids=(_BEACONING,),
        attribute="beacon connections: 5, one under the rule's 6",
        build=lambda seed, restored: _build(seed, n_beats=6 if restored else 5)),
    NegativeTwin(
        name="beacon_irregular_interval", step="c2_beacon", rule_ids=(_BEACONING,),
        attribute="the same 8 connections at IRREGULAR intervals (coefficient of variation far above 0.25), "
                  "so the count is met and only the periodicity is not",
        build=lambda seed, restored: _build(seed, n_beats=8, irregular=not restored)),
    NegativeTwin(
        name="login_same_country", step="foreign_login", rule_ids=(_TRAVEL,),
        attribute="the second successful login comes from the SAME country as the first",
        build=lambda seed, restored: _build(seed, same_country=not restored)),
)

STORYLINE = ScenarioDef(
    name="phishing_bec",
    steps=STEPS,
    build=build,
    oracle_path=TWIN / "oracle_phishing_bec.yaml",
    summary="phishing -> encoded PowerShell -> C2 beacon -> credential stuffing -> foreign login -> mailbox rule -> payment redirect",
    decoy=_build_decoys,
    decoy_steps=DECOY_STEPS,
    negatives=NEGATIVES,
)
