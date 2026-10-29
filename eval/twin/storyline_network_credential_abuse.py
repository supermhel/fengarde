"""storyline_network_credential_abuse -- external credential abuse that starts with a horizontal sweep:
denied-connection sweep -> password spray from the same source -> slow credential stuffing against the
account the spray found.

Registered by ``scenario_registry._discover`` (module name ``storyline_*``, exports ``STORYLINE``).

    recon_sweep -> password_spray -> slow_stuffing

WHAT IT CAN SHOW THAT NO OTHER STORYLINE CAN
    * the three network-credential rules no oracle named before this one: ``common_port_sweep``
      (ONE source denied across many HOSTS -- the horizontal shape the vertical ``common_port_scan``
      cannot see), ``common_password_spray_by_source`` (ONE source failing against many ACCOUNTS --
      true T1110.003 spraying, the inverse of the older many-sources-to-one-account rule) and
      ``common_credential_stuffing_sustained`` (one account failing from 20+ distinct sources over
      24 h, the slow tier beside the 300 s burst rule);
    * a SPAN no other storyline has: the stuffing step runs over ~4 hours, one failure from a new
      address every 10 minutes. That is the whole point of the sustained tier -- a campaign that
      rotates its pool slowly never puts 8 sources in the burst rule's
      5-minute window, so the burst rule is declared ``must_not_fire`` there;
    * a GENUINE unrelated-entity negative control: ``bystander_stale_password`` is a real user whose
      saved password is stale on a phone, failing from 22 mobile-carrier addresses in a few hours -- the
      DOCUMENTED false-positive shape of ``common_credential_stuffing_sustained``. It rides in the
      BASE build under a step label that is not in the oracle's ``expected_sequence`` (so the grader
      scores it as non-attack activity); the oracle declares ``slow_stuffing -> bystander_stale_password``
      forbidden. It shares no account and no address with the attack, so a correct correlator must NOT
      fold it into the intrusion incident.

THE LINK BETWEEN THE STEPS (so the chain is one story, not three): the sweeping address is also the
spray source and is the LAST address of the stuffing pool, and the account the spray ends on is the
account the stuffing then targets (spray finds the valid account, stuffing keeps guessing against it).

TELEMETRY. Real parsers: ``cisco_asa`` (denied connections, ``%ASA-4-106023``) and ``active_directory``
(Security 4625 failed logon). Native raw shapes; nothing hand-sets a ``type_uid``. No dependency gaps.

STRUCTURE VARIES WITH THE SEED: the attacker address, the number of swept hosts (16-22), of sprayed
accounts (9-11) and of stuffing sources (21-24), and the victim account.

SAFETY. Simulation only: RFC 5737 documentation addresses for the outside, private addresses for the
inside, ``example`` domain, a fixed calendar epoch (no wall clock).
"""
from __future__ import annotations

import sys
from pathlib import Path
from random import Random

TWIN = Path(__file__).resolve().parent
if str(TWIN) not in sys.path:
    sys.path.insert(0, str(TWIN))

from scenario import ChainStepSpec, NegativeTwin, ScenarioDef  # noqa: E402
from scenario_kit import epoch_ms, meta  # noqa: E402

START_MS = epoch_ms(2025, 7, 8, 1, 0)        # Tue 2025-07-08 01:00 UTC

STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("recon_sweep", "cisco_asa", True,
                  "one outside address is denied against 16-22 distinct inside hosts on one port"),
    ChainStepSpec("password_spray", "active_directory", True,
                  "the same address fails logon against 9-11 distinct accounts in four minutes"),
    ChainStepSpec("slow_stuffing", "active_directory", True,
                  "the account the spray ended on fails from 21-24 distinct addresses over ~4 hours"),
)

BYSTANDER = ChainStepSpec("bystander_stale_password", "active_directory", True,
                          "a real user's stale saved password fails from 22 mobile-carrier addresses in a few hours (BENIGN)")
DECOY_STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("decoy_vuln_scanner", "cisco_asa", True,
                  "an internal vulnerability scanner is denied across 18 hosts (BENIGN, authorised)"),
)

_ATTACKERS = ("203.0.113.21", "203.0.113.77", "203.0.113.130", "203.0.113.201")
_ACCOUNTS = ("a.silva", "b.adams", "c.lopez", "d.kim", "e.ross", "f.novak", "g.reed", "h.berger",
             "i.okafor", "j.wong", "k.ito", "l.martin")
_VICTIMS = ("svc_backup", "svc_print", "m.costa", "t.hale")

_SWEEP_GAP = 2_000            # 2 s apart: 22 hosts span 42 s, inside the rule's 60 s
_SPRAY_GAP = 25_000           # 25 s apart: 11 accounts span 250 s, inside the rule's 300 s
_STUFF_GAP = 600_000          # 10 min apart: 24 sources span ~3.8 h, inside 24 h, never 8 sources in 300 s
_T_SWEEP = START_MS
_T_SPRAY = START_MS + 300_000
_T_STUFF = START_MS + 900_000
_T_BYSTANDER = START_MS + 600_000     # starts BEFORE the stuffing, overlaps its window on purpose (the causal-order
                                      # gate wants no forbidden pair whose clock order matches f -> t)


def _rule_id(stem: str) -> str:
    """A rule's id read from its own file (the twins name a rule by stem, never by a copied id)."""
    import yaml  # noqa: PLC0415
    path = TWIN.parents[1] / "contracts" / "rules" / f"{stem}.yml"
    return str(yaml.safe_load(path.read_text(encoding="utf-8"))["id"])


def _build(seed: int, *, n_hosts: int | None = None, n_spray: int | None = None,
           n_pool: int | None = None):
    """The one builder every twin shares; each keyword overrides ONE count and nothing else (every
    random draw happens before any override, so overriding one never shifts another)."""
    rng = Random(seed * 15485863 + 53)
    attacker = rng.choice(_ATTACKERS)
    victim = rng.choice(_VICTIMS)
    drawn_hosts = 16 + seed % 7                # rule threshold: 15 distinct hosts / 60 s
    drawn_spray = 9 + seed % 3                 # rule threshold: 8 distinct accounts / 300 s
    drawn_pool = 21 + seed % 4                 # rule threshold: 20 distinct sources / 24 h
    n_hosts = drawn_hosts if n_hosts is None else n_hosts
    n_spray = drawn_spray if n_spray is None else n_spray
    n_pool = drawn_pool if n_pool is None else n_pool
    sprayed = [a for a in _ACCOUNTS if a != victim][: max(0, n_spray - 1)] + [victim]
    pool_base = rng.randint(1, 200)
    # the proxy pool: documentation-range addresses, the attacker's own address LAST so the final
    # stuffing event shares its address with the sweep and the spray
    pool = [f"198.51.100.{(pool_base + i) % 250 + 1}" for i in range(max(0, n_pool - 1))] + [attacker]

    steps = {s.label: s for s in STEPS}
    steps[BYSTANDER.label] = BYSTANDER
    ordinal = {s.label: i for i, s in enumerate(STEPS)}
    ordinal[BYSTANDER.label] = len(STEPS)
    payloads: list = []
    notes: dict = {}
    seen: dict = {}

    def add(label: str, source_type: str, raw, ts: int, ip_: str | None) -> None:
        k = seen.get(label, 0)
        seen[label] = k + 1
        payloads.append((steps[label], {"source_type": source_type, "raw": raw,
                                        "meta": meta(seed, "nca", ordinal[label] * 100 + k, ts, ip_)}))

    for i in range(n_hosts):
        ts = _T_SWEEP + i * _SWEEP_GAP
        add("recon_sweep", "cisco_asa",
            f"%ASA-4-106023: Deny tcp src outside:{attacker}/{40000 + i} "
            f"dst inside:10.0.{1 + i // 250}.{10 + i % 250}/445 by access-group acl_out",
            ts, attacker)
    notes["recon_sweep"] = f"{attacker} denied on port 445 across {n_hosts} distinct inside hosts"

    for i, account in enumerate(sprayed):
        ts = _T_SPRAY + i * _SPRAY_GAP
        add("password_spray", "active_directory",
            {"EventID": 4625, "TimeCreated": ts, "TargetUserName": account, "TargetDomainName": "CORP",
             "IpAddress": attacker}, ts, attacker)
    notes["password_spray"] = f"{attacker} fails logon for {len(sprayed)} distinct accounts, ending on {victim}"

    for i, pool_ip in enumerate(pool):
        ts = _T_STUFF + i * _STUFF_GAP
        add("slow_stuffing", "active_directory",
            {"EventID": 4625, "TimeCreated": ts, "TargetUserName": victim, "TargetDomainName": "CORP",
             "IpAddress": pool_ip}, ts, pool_ip)
    notes["slow_stuffing"] = (f"{victim} fails logon from {len(pool)} distinct addresses, one every 10 min "
                              f"(span {(len(pool) - 1) * _STUFF_GAP / 3_600_000:.1f} h), last one {attacker}")

    # The unrelated bystander: its own account and its own mobile-carrier addresses.
    for i in range(22):
        ts = _T_BYSTANDER + i * _STUFF_GAP
        ip = f"192.0.2.{10 + i}"
        add("bystander_stale_password", "active_directory",
            {"EventID": 4625, "TimeCreated": ts, "TargetUserName": "c.vance", "TargetDomainName": "CORP",
             "IpAddress": ip}, ts, ip)
    notes["bystander_stale_password"] = "c.vance fails logon from 22 mobile-carrier addresses over ~4 h"

    return payloads, {}, notes, None


def build(seed: int):
    return _build(seed)


# ---------------------------------------------------------------------------
# Benign look-alike for the ``noise`` axis: an internal vulnerability scanner -- the DOCUMENTED
# false-positive shape of common_port_sweep. Disjoint address and targets; overlaps the sweep.
# ---------------------------------------------------------------------------
def _build_decoys(seed: int) -> list:
    spec = DECOY_STEPS[0]
    out: list = []
    for i in range(18):
        ts = _T_SWEEP + 5_000 + i * 2_000
        out.append((spec, {"source_type": "cisco_asa",
                           "raw": f"%ASA-4-106023: Deny tcp src inside:10.66.0.9/{45000 + i} "
                                  f"dst inside:10.9.{1 + i // 250}.{10 + i % 250}/445 by access-group acl_in",
                           "meta": meta(seed, "ncad", i, ts, "10.66.0.9")}))
    return out


NEGATIVES: tuple[NegativeTwin, ...] = (
    NegativeTwin(
        name="sweep_14_of_15_hosts", step="recon_sweep", rule_ids=(_rule_id("common_port_sweep"),),
        attribute="distinct inside hosts denied from the one source: 14, one under the rule's 15",
        build=lambda seed, restored: _build(seed, n_hosts=15 if restored else 14)),
    NegativeTwin(
        name="spray_7_of_8_accounts", step="password_spray",
        rule_ids=(_rule_id("common_password_spray_by_source"),),
        attribute="distinct accounts failing from the one source: 7, one under the rule's 8",
        build=lambda seed, restored: _build(seed, n_spray=8 if restored else 7)),
    NegativeTwin(
        name="stuffing_19_of_20_sources", step="slow_stuffing",
        rule_ids=(_rule_id("common_credential_stuffing_sustained"),),
        attribute="distinct source addresses failing against the one account in 24 h: 19, one under the "
                  "rule's 20",
        build=lambda seed, restored: _build(seed, n_pool=20 if restored else 19)),
)


STORYLINE = ScenarioDef(
    name="network_credential_abuse",
    steps=STEPS,
    build=build,
    oracle_path=TWIN / "oracle_network_credential_abuse.yaml",
    summary="horizontal sweep -> password spray from the same source -> slow credential stuffing "
            "against the account the spray found (plus a real user's stale-password failures)",
    decoy=_build_decoys,
    decoy_steps=DECOY_STEPS + (BYSTANDER,),
    negatives=NEGATIVES,
)
