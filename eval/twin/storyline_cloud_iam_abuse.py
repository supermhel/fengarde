"""storyline_cloud_iam_abuse -- AWS console credential stuffing -> foreign console login ->
discovery -> IAM persistence -> CloudTrail tampering.

Registered by ``scenario_registry._discover`` (module name ``storyline_*``, exports ``STORYLINE``).

    console_stuffing -> victim_session -> attacker_console_login -> account_discovery
        -> create_backdoor_user -> attach_admin_policy -> create_access_key -> log_tampering

WHAT IT CAN SHOW THAT THE OTHER STORYLINES CANNOT
    * the cloud CONTROL PLANE as an inventory of coverage debt: eight steps on real CloudTrail
      records and exactly ONE shipped rule that can fire (``common_impossible_travel`` on the
      foreign console login). Every other step is an honest gap with its ATT&CK technique;
    * a CROSS-SOURCE blind spot measured, not assumed: ``cloudtrail.py`` maps every ConsoleLogin
      to activity 1 (a failure shows only in ``status``), while every failed-authentication rule
      selects activity 4 -- so 9-12 failed console logins from 9-12 addresses are invisible to the
      credential-stuffing rule that would catch the same shape from an IdP. A fix flips the step to
      a stale-gap finding (a self-updating tripwire);
    * IAM persistence split per technique (critic correction): CreateUser T1136.003,
      AttachUserPolicy T1098.003, CreateAccessKey T1098.001 -- one id per step, not one for three.

TELEMETRY. Real cloudtrail parser throughout; every step parses.

STRUCTURE VARIES WITH THE SEED: the failed-login pool size (9-12), the discovery call count
(25-35), the IAM user, the backdoor user name and every address.

SAFETY. Simulation only: RFC 5737 documentation addresses (geo sample map 192.0.2.0/24 = US,
198.51.100.0/24 = CN, 203.0.113.0/24 = RU), the documentation AWS account id 123456789012, fixed
calendar timestamps (no wall clock).
"""
from __future__ import annotations

import sys
from pathlib import Path
from random import Random

TWIN = Path(__file__).resolve().parent
if str(TWIN) not in sys.path:
    sys.path.insert(0, str(TWIN))

from scenario import ChainStepSpec, NegativeTwin, ScenarioDef  # noqa: E402
from scenario_kit import BASE_MS, iso, meta  # noqa: E402

STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("console_stuffing", "cloudtrail", True,
                  "9-12 failed console logins for one IAM user from 9-12 addresses"),
    ChainStepSpec("victim_session", "cloudtrail", True,
                  "the user's own console login from the home country (benign enabling telemetry)"),
    ChainStepSpec("attacker_console_login", "cloudtrail", True,
                  "a successful console login for the same user from a second country"),
    ChainStepSpec("account_discovery", "cloudtrail", True,
                  "25-35 List*/Describe* calls enumerating IAM and EC2"),
    ChainStepSpec("create_backdoor_user", "cloudtrail", True, "a new IAM user is created"),
    ChainStepSpec("attach_admin_policy", "cloudtrail", True, "AdministratorAccess is attached to it"),
    ChainStepSpec("create_access_key", "cloudtrail", True, "an access key is created for it"),
    ChainStepSpec("log_tampering", "cloudtrail", True, "the CloudTrail trail is deleted"),
)

_USERS = ("dev-ops-lead", "billing-admin", "data-eng-01", "platform-sre")
_DISCOVERY = ("ListUsers", "ListRoles", "ListPolicies", "GetAccountAuthorizationDetails",
              "DescribeInstances", "DescribeSecurityGroups", "ListBuckets", "DescribeSnapshots")


def _rule_id(stem: str) -> str:
    """A rule's id read from its own file (the twins name a rule by stem, never by a copied id)."""
    import yaml  # noqa: PLC0415
    path = TWIN.parents[1] / "contracts" / "rules" / f"{stem}.yml"
    return str(yaml.safe_load(path.read_text(encoding="utf-8"))["id"])


def _rec(name: str, ts: int, ip: str, arn: str, **extra) -> dict:
    rec = {"eventTime": iso(ts), "eventSource": "iam.amazonaws.com" if name[0] in "CALDG" else "ec2.amazonaws.com",
           "eventName": name, "sourceIPAddress": ip,
           "userIdentity": {"type": "IAMUser", "arn": arn, "accountId": "123456789012"}}
    rec.update(extra)
    return rec


def _build(seed: int, *, same_country: bool = False):
    """The one builder every twin shares; ``same_country`` moves ONLY the attacker's login
    address into the victim's own country (all draws happen first)."""
    rng = Random(seed * 6151 + 61)
    user = rng.choice(_USERS)
    arn = f"arn:aws:iam::123456789012:user/{user}"
    n_pool = rng.randint(9, 12)
    n_disc = rng.randint(25, 35)
    pool_base = rng.randint(10, 60)
    home_ip = f"192.0.2.{rng.randint(10, 60)}"             # US
    away_ip = f"203.0.113.{rng.randint(30, 90)}"           # RU
    same_ip = f"192.0.2.{rng.randint(100, 140)}"           # US (the same-country twin)
    backdoor = f"svc-sync-{rng.randint(100, 999)}"
    steps = {s.label: s for s in STEPS}
    ordinal = {s.label: i for i, s in enumerate(STEPS)}
    payloads: list = []
    notes: dict = {}
    seen: dict = {}

    def add(label: str, raw: dict, ts: int, ip: str) -> None:
        k = seen.get(label, 0)
        seen[label] = k + 1
        payloads.append((steps[label], {"source_type": "cloudtrail", "raw": raw,
                                        "meta": meta(seed, "ci", ordinal[label] * 100 + k, ts, ip)}))

    t = BASE_MS
    for i in range(n_pool):                                   # 20 s apart, all distinct CN addresses
        ip = f"198.51.100.{pool_base + i}"
        add("console_stuffing", _rec("ConsoleLogin", t + i * 20_000, ip, arn,
                                     eventSource="signin.amazonaws.com",
                                     responseElements={"ConsoleLogin": "Failure"}), t + i * 20_000, ip)
    notes["console_stuffing"] = f"{n_pool} failed console logins for {user} from {n_pool} addresses"

    t = BASE_MS + 400_000
    add("victim_session", _rec("ConsoleLogin", t, home_ip, arn, eventSource="signin.amazonaws.com",
                               responseElements={"ConsoleLogin": "Success"},
                               additionalEventData={"MFAUsed": "Yes"}), t, home_ip)
    notes["victim_session"] = f"{user} logs in from {home_ip} (US)"

    t = BASE_MS + 1_000_000                                   # 10 min after the home session
    login_ip = same_ip if same_country else away_ip
    add("attacker_console_login", _rec("ConsoleLogin", t, login_ip, arn, eventSource="signin.amazonaws.com",
                                       responseElements={"ConsoleLogin": "Success"},
                                       additionalEventData={"MFAUsed": "No"}), t, login_ip)
    notes["attacker_console_login"] = f"{user} logs in from {login_ip} ({'US' if same_country else 'RU'})"

    t = BASE_MS + 1_100_000
    for i in range(n_disc):
        add("account_discovery", _rec(_DISCOVERY[i % len(_DISCOVERY)], t + i * 2_000, away_ip, arn),
            t + i * 2_000, away_ip)
    notes["account_discovery"] = f"{n_disc} discovery calls from {away_ip}"

    t = BASE_MS + 1_300_000
    add("create_backdoor_user", _rec("CreateUser", t, away_ip, arn,
                                     requestParameters={"userName": backdoor}), t, away_ip)
    add("attach_admin_policy", _rec("AttachUserPolicy", t + 20_000, away_ip, arn,
                                    requestParameters={"userName": backdoor,
                                                       "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
        t + 20_000, away_ip)
    add("create_access_key", _rec("CreateAccessKey", t + 40_000, away_ip, arn,
                                  requestParameters={"userName": backdoor}), t + 40_000, away_ip)
    notes["create_backdoor_user"] = f"CreateUser {backdoor}"
    notes["attach_admin_policy"] = f"AttachUserPolicy AdministratorAccess -> {backdoor}"
    notes["create_access_key"] = f"CreateAccessKey for {backdoor}"

    t = BASE_MS + 1_500_000
    add("log_tampering", _rec("DeleteTrail", t, away_ip, arn, eventSource="cloudtrail.amazonaws.com",
                              requestParameters={"name": "org-trail"}), t, away_ip)
    notes["log_tampering"] = "DeleteTrail org-trail"

    return payloads, {}, notes, None


def build(seed: int):
    return _build(seed)


# ---------------------------------------------------------------------------
# Benign look-alike: a sales user's console egress flips country when the VPN reconnects -- the
# DOCUMENTED false-positive shape of common_impossible_travel. Own IAM user, own addresses.
# ---------------------------------------------------------------------------
DECOY_STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("decoy_vpn_roaming", "cloudtrail", True,
                  "a sales user's console login egress flips country on VPN reconnect (BENIGN)"),
)


def _build_decoys(seed: int) -> list:
    spec = DECOY_STEPS[0]
    arn = "arn:aws:iam::123456789012:user/sales-ops"
    out: list = []
    for i, (ip, dt) in enumerate((("192.0.2.201", 700_000), ("198.51.100.201", 900_000))):
        ts = BASE_MS + dt
        out.append((spec, {"source_type": "cloudtrail",
                           "raw": _rec("ConsoleLogin", ts, ip, arn, eventSource="signin.amazonaws.com",
                                       responseElements={"ConsoleLogin": "Success"}),
                           "meta": meta(seed, "cid", i, ts, ip)}))
    return out


NEGATIVES: tuple[NegativeTwin, ...] = (
    NegativeTwin(
        name="console_login_same_country", step="attacker_console_login",
        rule_ids=(_rule_id("common_impossible_travel"),),
        attribute="the second successful console login comes from the SAME country as the first",
        build=lambda seed, restored: _build(seed, same_country=not restored)),
)

STORYLINE = ScenarioDef(
    name="cloud_iam_abuse",
    steps=STEPS,
    build=build,
    oracle_path=TWIN / "oracle_cloud_iam_abuse.yaml",
    summary="AWS console stuffing -> foreign console login -> discovery -> IAM backdoor user + admin "
            "policy + access key -> CloudTrail deleted",
    decoy=_build_decoys,
    decoy_steps=DECOY_STEPS,
    negatives=NEGATIVES,
)
