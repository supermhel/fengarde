"""storyline_insider_exfil -- an insider with legitimate access grants themselves more, reads a
cardholder table in bulk, stages and uploads the data, then deletes audit rows. IN business hours.

Registered by ``scenario_registry._discover`` (module name ``storyline_*``, exports ``STORYLINE``).

    elevated_in_hours -> grant_self_access -> bulk_table_read -> stage_archive -> stage_files
        -> exfil_upload -> cover_tracks

WHAT IT CAN SHOW THAT THE OTHER STORYLINES CANNOT
    * the BANK database rules on real db_audit telemetry: a self-granted privilege
      (``bank_db_priv_esc``) and a bulk read of one table (``bank_mass_card_read``);
    * the NEGATIVE time-of-day control: the whole chain runs Tue 10:30 UTC, so the off-hours
      privileged-logon rule must stay silent on a real 4672 -- an insider working in hours is
      invisible to every time-of-day rule (declared ``must_not_fire``);
    * a periodicity NEGATIVE on real traffic: the upload is 22 connections -- over the beacon
      rule's count -- at irregular intervals, so ``common_beaconing`` could fire on count and must
      not on regularity;
    * four honest gaps (archive staging, file staging, exfiltration over web, audit-row deletion).

TELEMETRY. Real parsers throughout (windows_eventlog, db_audit, sysmon); every step parses.
db_audit's default sector is ``bank`` (the parser's SECTOR), which the bank rules require.

STRUCTURE VARIES WITH THE SEED: the insider account, the table, the bulk-read count (24-32), the
staged-file count (1-3), the upload intervals and every address.

SAFETY. Simulation only: private 10.0.0.0/8 and RFC 5737 documentation addresses,
``.invalid`` / ``example`` names, a fixed calendar instant (no wall clock).
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

#: Tue 2025-07-01 10:30:00 UTC -- INSIDE 08:00-18:00 Mon-Fri on purpose.
START_MS = epoch_ms(2025, 7, 1, 10, 30)

STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("elevated_in_hours", "windows_eventlog", True,
                  "the insider's privileged logon during business hours (benign-looking context)"),
    ChainStepSpec("grant_self_access", "db_audit", True,
                  "the insider grants themselves SELECT on the cardholder table"),
    ChainStepSpec("bulk_table_read", "db_audit", True,
                  "24-32 SELECTs on that one table within four minutes"),
    ChainStepSpec("stage_archive", "sysmon", True,
                  "7-Zip packs the export into an archive"),
    ChainStepSpec("stage_files", "sysmon", True,
                  "1-3 archive parts are written to a temp folder"),
    ChainStepSpec("exfil_upload", "sysmon", True,
                  "22 uploads to an external address at irregular intervals"),
    ChainStepSpec("cover_tracks", "db_audit", True,
                  "the insider deletes rows from the audit table"),
)

_INSIDERS = ("p.schmid", "n.adeyemi", "f.moreau", "g.rossi")
_TABLES = ("cardholder_data", "card_pan_vault", "cards_primary")
#: 21 gaps for 22 uploads: mean ~15 s, CV ~0.7 -- over the beacon count, nowhere near its regularity
_UPLOAD_GAPS_MS = (2_000, 31_000, 6_000, 25_000, 3_000, 40_000, 9_000, 18_000, 4_000, 33_000,
                   7_000, 22_000, 2_000, 29_000, 11_000, 36_000, 5_000, 20_000, 3_000, 27_000, 8_000)


def _rule_id(stem: str) -> str:
    """A rule's id read from its own file (the twins name a rule by stem, never by a copied id)."""
    import yaml  # noqa: PLC0415
    path = TWIN.parents[1] / "contracts" / "rules" / f"{stem}.yml"
    return str(yaml.safe_load(path.read_text(encoding="utf-8"))["id"])


def _build(seed: int, *, n_reads: int | None = None):
    """The one builder every twin shares; ``n_reads`` overrides the bulk-read count only."""
    rng = Random(seed * 7919 + 53)
    insider = rng.choice(_INSIDERS)
    table = rng.choice(_TABLES)
    wks = f"wks-ops-{rng.randint(10, 99)}"
    wks_ip = f"10.40.{rng.randint(1, 9)}.{rng.randint(20, 200)}"
    drawn_reads = rng.randint(24, 32)                # rule threshold: 20 reads of one table / 300 s
    n_parts = rng.randint(1, 3)
    drop_ip = f"203.0.113.{rng.randint(150, 199)}"
    n_reads = drawn_reads if n_reads is None else n_reads
    steps = {s.label: s for s in STEPS}
    ordinal = {s.label: i for i, s in enumerate(STEPS)}
    payloads: list = []
    notes: dict = {}
    seen: dict = {}

    def add(label: str, source_type: str, raw, ts: int, ip: str | None) -> None:
        k = seen.get(label, 0)
        seen[label] = k + 1
        payloads.append((steps[label], {"source_type": source_type, "raw": raw,
                                        "meta": meta(seed, "ix", ordinal[label] * 100 + k, ts, ip)}))

    def db(op: str, obj: str, ts: int) -> dict:
        return {"operation": op, "object": obj, "user": insider, "host": "db-card-01",
                "ipAddress": wks_ip, "timestamp": ts}

    t = START_MS
    add("elevated_in_hours", "windows_eventlog",
        {"EventID": 4672, "SubjectUserName": insider, "Computer": wks, "IpAddress": wks_ip,
         "TimeCreated": t}, t, wks_ip)
    notes["elevated_in_hours"] = f"{insider} privileged logon on {wks} at 10:30 on a Tuesday"

    t = START_MS + 120_000
    add("grant_self_access", "db_audit", db(f"GRANT SELECT ON {table} TO {insider}", table, t), t, wks_ip)
    notes["grant_self_access"] = f"{insider} grants themselves SELECT on {table}"

    t = START_MS + 300_000
    for i in range(n_reads):                                 # 8 s apart -> inside 300 s
        add("bulk_table_read", "db_audit", db("SELECT", table, t + i * 8_000), t + i * 8_000, wks_ip)
    notes["bulk_table_read"] = f"{n_reads} SELECTs on {table} by {insider}"

    t = START_MS + 700_000
    add("stage_archive", "sysmon",
        {"EventID": 1, "TimeCreated": t, "Computer": wks, "Image": "C:\\Program Files\\7-Zip\\7z.exe",
         "CommandLine": f"7z.exe a -p C:\\Users\\{insider}\\AppData\\Local\\Temp\\q3.7z export.csv",
         "ProcessId": "8120", "ParentImage": "C:\\Windows\\explorer.exe", "ParentProcessId": "4100",
         "User": insider}, t, wks_ip)
    notes["stage_archive"] = "7-Zip packs export.csv into a password-protected archive"

    t = START_MS + 760_000
    for i in range(n_parts):
        add("stage_files", "sysmon",
            {"EventID": 11, "TimeCreated": t + i * 3_000, "Computer": wks,
             "Image": "C:\\Program Files\\7-Zip\\7z.exe",
             "TargetFilename": f"C:\\Users\\{insider}\\AppData\\Local\\Temp\\q3.7z.{i + 1:03d}",
             "User": insider}, t + i * 3_000, wks_ip)
    notes["stage_files"] = f"{n_parts} archive part(s) written"

    t = START_MS + 900_000
    times = [t]
    for g in _UPLOAD_GAPS_MS:
        times.append(times[-1] + g)
    for i, tu in enumerate(times):
        add("exfil_upload", "sysmon",
            {"EventID": 3, "TimeCreated": tu, "Computer": wks, "Image": "C:\\Windows\\System32\\curl.exe",
             "User": insider, "SourceIp": wks_ip, "SourcePort": str(50_100 + i), "SourceHostname": wks,
             "DestinationIp": drop_ip, "DestinationPort": "443",
             "DestinationHostname": "files.share-drop.example.invalid"}, tu, wks_ip)
    notes["exfil_upload"] = f"{len(times)} uploads from {wks_ip} to {drop_ip}:443 at irregular intervals"

    t = START_MS + 1_400_000
    add("cover_tracks", "db_audit", db("DELETE FROM audit_log WHERE user_name = :u", "audit_log", t), t, wks_ip)
    notes["cover_tracks"] = f"{insider} deletes their rows from audit_log"

    return payloads, {}, notes, None


def build(seed: int):
    return _build(seed)


# ---------------------------------------------------------------------------
# Benign look-alike: a reporting service account reading a hot reference table 22 times -- the
# documented false-positive shape of bank_mass_card_read. Own account, own address, own table;
# overlaps the attack window. A correct correlator keeps it out of the insider's incident.
# ---------------------------------------------------------------------------
DECOY_STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("decoy_report_job", "db_audit", True,
                  "the nightly-report service account re-reads a reference table (BENIGN)"),
)


def _build_decoys(seed: int) -> list:
    spec = DECOY_STEPS[0]
    out: list = []
    t = START_MS + 320_000
    for i in range(22):
        ts = t + i * 9_000
        out.append((spec, {"source_type": "db_audit",
                           "raw": {"operation": "SELECT", "object": "fx_rates", "user": "svc_report",
                                   "host": "db-card-01", "ipAddress": "10.41.0.9", "timestamp": ts},
                           "meta": meta(seed, "ixd", i, ts, "10.41.0.9")}))
    return out


NEGATIVES: tuple[NegativeTwin, ...] = (
    NegativeTwin(
        name="read_19_of_20", step="bulk_table_read", rule_ids=(_rule_id("bank_mass_card_read"),),
        attribute="SELECTs on the one table: 19, one under the rule's 20",
        build=lambda seed, restored: _build(seed, n_reads=20 if restored else 19)),
)

STORYLINE = ScenarioDef(
    name="insider_exfil",
    steps=STEPS,
    build=build,
    oracle_path=TWIN / "oracle_insider_exfil.yaml",
    summary="in-hours insider: self-grant -> bulk card-table read -> staging -> irregular upload -> audit-row delete",
    decoy=_build_decoys,
    decoy_steps=DECOY_STEPS,
    negatives=NEGATIVES,
)
