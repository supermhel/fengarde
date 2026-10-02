"""Blocking, zero-infra test of the blind-recall lane (synthetic CONTROLS only).

No third-party data is read here. Every dataset below is a tiny hand-built
control written into a temp dir (Splunk-shaped trees with raw ``<Event>`` XML;
EVTX-to-MITRE-shaped trees with a fake ``.evtx`` opener, because python-evtx
cannot write .evtx and must not be required to run this gate). A control
proves the INSTRUMENT works (can score a hit through the real WS-2 -> WS-4
path, can go red, cannot go vacuously green); it is NOT a third-party
measurement and must never be quoted as one.

Positive controls: P1 burst, P2 lateral, P3 merged multi-file scenario,
P4 parent-level label (HIT_EXACT), P5 EVTX path label. Negative controls cover
the label-not-alert rule, sensitivity, rule removal, no vacuous green,
label parsing, sibling sub-techniques, determinism, no leakage, partial parse,
unlabelled, unsupported sources, reader-missing and the selection/pin tooling.

Run: python eval/detection_accuracy/test_blind_recall.py
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import yaml

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))

import blind_recall as BR  # noqa: E402
import corpus_adapters as CA  # noqa: E402
import fetch_corpora as FC  # noqa: E402
import technique_match as TM  # noqa: E402

RULES = REPO / "contracts" / "rules"
BASE_MS = 1709632800000          # 2024-03-05T10:00:00Z (a Tuesday)
SYSMON = "Microsoft-Windows-Sysmon/Operational"
NS = "http://schemas.microsoft.com/win/2004/08/events/event"
LFS_POINTER = "version https://git-lfs.github.com/spec/v1\noid sha256:{oid}\nsize {size}\n"


# ------------------------------------------------------------- fixture builders

def _iso(ms: int) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def ev(eid: int, t_ms: int, computer: str = "DC01", data: dict | None = None,
       channel: str = "Security") -> str:
    d = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in (data or {}).items())
    return (f'<Event xmlns="{NS}"><System><EventID>{eid}</EventID>'
            f'<TimeCreated SystemTime="{_iso(t_ms)}"/><Channel>{channel}</Channel>'
            f'<Computer>{computer}</Computer></System><EventData>{d}</EventData></Event>')


def failed_logons(n: int, start: int = 0, step_s: int = 3, ip: str = "203.0.113.7") -> list:
    return [ev(4625, BASE_MS + (start + i) * step_s * 1000, "DC01",
               {"TargetUserName": "victim", "IpAddress": ip, "WorkstationName": "wks1"})
            for i in range(n)]


def lateral_logons(n: int = 6) -> list:
    # distinct Computer per logon: windows_eventlog maps it to dst_endpoint.hostname
    return [ev(4624, BASE_MS + i * 40_000, f"HOST{i}",
               {"TargetUserName": "svc_x", "IpAddress": "198.51.100.9", "LogonType": "3"})
            for i in range(n)]


def account_create() -> list:
    return [ev(4720, BASE_MS, "DC01", {"TargetUserName": "newuser", "SubjectUserName": "admin"})]


def sysmon_unparsed(n: int) -> list:
    return [ev(10, BASE_MS + i * 1000, "WKS", {"SourceImage": "a.exe"}, SYSMON) for i in range(n)]


def write_splunk(root: Path, tech_dir: str, name: str, files: list, mitre=None,
                 old_style: bool = False) -> Path:
    """One Splunk-shaped scenario. ``files`` = [(filename, source, text|bytes)]."""
    d = root / "datasets" / "attack_techniques" / tech_dir / name
    d.mkdir(parents=True, exist_ok=True)
    doc: dict = {"id": name, "author": "ctl", "date": "2024-03-05",
                 "description": "CONTROL fixture (synthetic)"}
    if mitre is not None:
        doc["mitre_technique"] = mitre
    entries = []
    for fn, src, text in files:
        if isinstance(text, bytes):
            (d / fn).write_bytes(text)
        else:
            (d / fn).write_text(text, encoding="utf-8")
        entries.append({"name": fn, "path": f"/datasets/attack_techniques/{tech_dir}/{name}/{fn}",
                        "sourcetype": "XmlWinEventLog", "source": src})
    if old_style:
        doc["dataset"] = [f"https://media.githubusercontent.com/x/{tech_dir}/{name}/{fn}"
                          for fn, _s, _t in files]
    else:
        doc["datasets"] = entries
    (d / f"{name}.yml").write_text(yaml.safe_dump(doc), encoding="utf-8")
    return d


SEC = "XmlWinEventLog:Security"


def build_splunk_tree(root: Path) -> None:
    burst = "\n".join(failed_logons(12))
    write_splunk(root, "T1110.001", "ctl_burst", [("w.log", SEC, burst)], ["T1110.001"])
    write_splunk(root, "T1110.001", "ctl_below", [("w.log", SEC, "\n".join(failed_logons(3)))],
                 ["T1110.001"])
    write_splunk(root, "T1021.002", "ctl_lateral", [("w.log", SEC, "\n".join(lateral_logons()))],
                 ["T1021.002"])
    # N1: identical events, label of a technique no rule declares
    write_splunk(root, "T1059.001", "ctl_relabelled", [("w.log", SEC, burst)], ["T1059.001"])
    # P3: 12 failures split over TWO files (6 + 6, interleaved in time); alone each is below
    # the 10-in-60s threshold, only the merged scenario fires
    a = "\n".join(ev(4625, BASE_MS + i * 6000, "DC01", {"TargetUserName": "victim",
                     "IpAddress": "203.0.113.7", "WorkstationName": "wks1"}) for i in range(6))
    b = "\n".join(ev(4625, BASE_MS + i * 6000 + 3000, "DC01", {"TargetUserName": "victim",
                     "IpAddress": "203.0.113.7", "WorkstationName": "wks1"}) for i in range(6))
    write_splunk(root, "T1110.001", "ctl_split", [("a.log", SEC, a), ("b.log", SEC, b)],
                 ["T1110.001"])
    write_splunk(root, "T1110.001", "ctl_half", [("a.log", SEC, a)], ["T1110.001"])
    # a rule family exists (T1136) but nothing in this dataset fires it; no ORACLE rule there
    write_splunk(root, "T1136.001", "ctl_miss_nonoracle", [("w.log", SEC, "\n".join(account_create()))],
                 ["T1136.001"])
    # sibling gap: spray label, rules only reach the family via the T1110 brute-force rules
    write_splunk(root, "T1110.003", "ctl_spray_label", [("w.log", SEC, burst)], ["T1110.003"])
    # P4: parent-level label scores against the exact T1110 rule
    write_splunk(root, "T1110", "ctl_parent_label", [("w.log", SEC, burst)], ["T1110"])
    # LFS pointer, never pulled
    write_splunk(root, "T1003.001", "ctl_lfs_only",
                 [("w.log", SEC, LFS_POINTER.format(oid="ab" * 32, size=123456))], ["T1003.001"])
    # unsupported source (CloudTrail JSON): no parser in this adapter
    write_splunk(root, "T1078.004", "ctl_cloudtrail",
                 [("ct.json", "aws_cloudtrail", '{"eventName":"ConsoleLogin"}\n')], ["T1078.004"])
    # no label anywhere: yaml has no mitre_technique and the dir is not a technique id
    write_splunk(root, "misc", "ctl_nolabel", [("w.log", SEC, burst)], None)
    # multi-label scenario: 2 units from 1 replay
    write_splunk(root, "T1110.001", "ctl_multi", [("w.log", SEC, burst)],
                 ["T1110.001", "T1059.001"])
    # old-style YAML: 'dataset:' URL list, no mitre_technique -> label from the dir name, sniffed
    write_splunk(root, "T1110.001", "ctl_old", [("old.log", SEC, burst)], None, old_style=True)
    # partial parse: parseable burst + unparseable Sysmon EID 10 records
    write_splunk(root, "T1110.001", "ctl_partial",
                 [("w.log", SEC, burst + "\n" + "\n".join(sysmon_unparsed(10)))], ["T1110.001"])
    # YAML label and directory disagree
    write_splunk(root, "T1021.002", "ctl_disagree", [("w.log", SEC, burst)], ["T1110.001"])
    # partial fetch: one file present, one still an LFS pointer
    write_splunk(root, "T1110.001", "ctl_partialfetch",
                 [("a.log", SEC, a),
                  ("b.log", SEC, LFS_POINTER.format(oid="cd" * 32, size=999))], ["T1110.001"])


def row_of(results: dict, dataset_suffix: str, label: str | None = None) -> dict:
    hits = [r for r in results["rows"] if r["dataset_id"].endswith(dataset_suffix)
            and (label is None or r["label"] == label)]
    assert len(hits) == 1, (dataset_suffix, label, [r["dataset_id"] for r in hits])
    return hits[0]


def reduced_rules_dir(dst: Path, drop_prefixes=("common_bruteforce", "common_password_spray")) -> Path:
    dst.mkdir(parents=True, exist_ok=True)
    for f in RULES.glob("*.yml"):
        if not f.name.startswith(drop_prefixes):
            shutil.copy(f, dst / f.name)
    return dst


# ------------------------------------------------------------------ the tests

class TestMatchSemantics(unittest.TestCase):
    """N6 -- what counts as 'a rule covering a dataset label'."""

    def test_exact_family_and_sibling(self):
        self.assertEqual(TM.match_level("T1110.001", "T1110.001"), "exact")
        self.assertEqual(TM.match_level("T1110.003", "T1110"), "family")
        self.assertEqual(TM.match_level("T1110", "T1110.004"), "family")
        self.assertEqual(TM.match_level("T1021.002", "T1021"), "family")
        self.assertEqual(TM.match_level("T1021", "T1021.002"), "family")
        # siblings never match: common_password_spray (T1110.004, credential stuffing by
        # documented design) must not be credited for a T1110.003 spray dataset
        self.assertIsNone(TM.match_level("T1110.003", "T1110.004"))
        self.assertIsNone(TM.match_level("T1110.001", "T1021"))
        self.assertIsNone(TM.match_level("", "T1110"))

    def test_normalize_never_guesses(self):
        self.assertEqual(TM.normalize_technique(" t1110.003 "), "T1110.003")
        for bad in ("T1110.xxx", "AML.T0051", "T0801", "T11", "TA0006", None, 7, ""):
            self.assertIsNone(TM.normalize_technique(bad), bad)

    def test_classify_order(self):
        c = TM.classify
        kw = dict(parsed_records=5, family_rules={"r": "family"}, alert_levels=[])
        self.assertEqual(c(fetched=False, label="T1110", **kw), "NOT_FETCHED")
        self.assertEqual(c(fetched=True, reader_ok=False, label="T1110", **kw), "READER_UNAVAILABLE")
        self.assertEqual(c(fetched=True, label=None, **kw), "UNLABELLED")
        self.assertEqual(c(fetched=True, label="T1110", **{**kw, "parsed_records": 0}), "NO_PARSER")
        self.assertEqual(c(fetched=True, label="T1110", **{**kw, "family_rules": {}}), "NO_RULE")
        self.assertEqual(c(fetched=True, label="T1110", **kw), "MISS")
        self.assertEqual(c(fetched=True, label="T1110", **{**kw, "alert_levels": ["family"]}),
                         "HIT_FAMILY")
        self.assertEqual(c(fetched=True, label="T1110",
                           **{**kw, "alert_levels": ["family", "exact"]}), "HIT_EXACT")
        # NO_PARSER wins over NO_RULE (the per-technique gap list is built from row fields)
        self.assertEqual(c(fetched=True, label="T1110", parsed_records=0, family_rules={},
                           alert_levels=[]), "NO_PARSER")


class TestRuleIndex(unittest.TestCase):
    """The framework filter is (framework or 'attack') == 'attack'."""

    def test_framework_filter(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)

            def w(name, doc):
                (d / name).write_text(yaml.safe_dump(doc), encoding="utf-8")
            w("noframework.yml", {"id": "r-none", "mitre": {"technique": "T1110", "tactic": "TA0006"}})
            w("attack.yml", {"id": "r-attack", "mitre": {"framework": "attack", "technique": "T1021.002"}})
            w("atlas.yml", {"id": "r-atlas", "mitre": {"framework": "atlas", "technique": "AML.T0051"}})
            w("ics.yml", {"id": "r-ics", "mitre": {"framework": "attack-ics", "technique": "T0801"}})
            w("nomitre.yml", {"id": "r-nomitre"})
            w("badtech.yml", {"id": "r-bad", "mitre": {"technique": "T1110.xxx"}})
            (d / "list.yml").write_text("- 1\n- 2\n", encoding="utf-8")
            idx = TM.load_rule_index(d)
        self.assertEqual(sorted(idx), ["r-attack", "r-none"])

    def test_real_rules_include_frameworkless_and_exclude_non_attack(self):
        idx = TM.load_rule_index(RULES)
        self.assertGreater(len(idx), 0)
        # frameworkless enterprise rule is in; common_password_spray stays T1110.004
        self.assertEqual(idx["4f8a2c61-9e3d-4b57-8a1c-6d2e5f7a8b90"]["technique"], "T1110.004")
        self.assertEqual(idx["6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c01"]["technique"], "T1110")
        self.assertTrue(all(v["framework"] == "attack" for v in idx.values()))


class TestLabelParsing(unittest.TestCase):
    """N5 -- EVTX-to-MITRE path labels."""

    def test_placeholder_family_label(self):
        p = CA.parse_evtx_to_mitre_path(("TA0006-Credential Access", "T1110.xxx-Brut force", "x.evtx"))
        self.assertEqual(p["technique"], "T1110")                 # not T1110.001
        self.assertEqual(p["flags"], ["sub_unspecified"])
        self.assertEqual(p["tactic"], "TA0006")

    def test_full_subtechnique_and_plain_technique(self):
        p = CA.parse_evtx_to_mitre_path(("TA0003-Persistence", "T1553.002-Code signing", "x.evtx"))
        self.assertEqual((p["technique"], p["flags"]), ("T1553.002", []))
        p = CA.parse_evtx_to_mitre_path(("TA0003-Persistence", "T1136-Create Account", "x.evtx"))
        self.assertEqual(p["technique"], "T1136")

    def test_malformed_is_none_never_guessed(self):
        for parts in (("Antivirus", "x.evtx"),
                      ("EVTX_full_APT_attack_steps", "sub", "x.evtx"),
                      ("TA0006-Credential Access", "ID131-RDP brutforce", "x.evtx"),
                      ("TA0006-Credential Access", "x.evtx"),
                      ("x.evtx",), ()):
            self.assertIsNone(CA.parse_evtx_to_mitre_path(parts)["technique"], parts)


class SplunkLaneBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._td = tempfile.TemporaryDirectory()
        cls.root = Path(cls._td.name) / "splunk like"            # a space on purpose
        build_splunk_tree(cls.root)
        cls.results = BR.run([CA.SplunkAttackData(cls.root)], RULES)

    @classmethod
    def tearDownClass(cls):
        cls._td.cleanup()


class TestSplunkControls(SplunkLaneBase):

    def test_p1_burst_hits_family_through_real_pipeline(self):
        r = row_of(self.results, "T1110.001/ctl_burst/ctl_burst.yml", "T1110.001")
        self.assertEqual(r["bucket"], "HIT_FAMILY")
        self.assertIn("6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c01", r["fired_in_family"])
        self.assertEqual(r["label_source"], "yaml:mitre_technique")
        self.assertEqual(r["records_supported"], 12)
        self.assertEqual(r["parsed_fraction"], 1.0)

    def test_p2_lateral_is_a_second_family(self):
        r = row_of(self.results, "ctl_lateral.yml")
        self.assertEqual(r["bucket"], "HIT_FAMILY")
        self.assertIn("2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061", r["fired_in_family"])

    def test_p3_multi_file_scenario_is_replayed_merged(self):
        merged = row_of(self.results, "ctl_split.yml")
        alone = row_of(self.results, "ctl_half.yml")
        self.assertEqual((merged["files_declared"], merged["files_present"]), (2, 2))
        self.assertEqual(merged["bucket"], "HIT_FAMILY")      # 12 events only exist merged
        self.assertEqual(alone["bucket"], "MISS")              # 6 events: below threshold
        self.assertEqual(alone["oracle"], "agrees_no_fire")

    def test_p4_parent_label_scores_exact_rule(self):
        r = row_of(self.results, "ctl_parent_label.yml")
        self.assertEqual(r["bucket"], "HIT_EXACT")

    def test_n1_alert_without_label_match_is_not_credited(self):
        r = row_of(self.results, "ctl_relabelled.yml")
        self.assertEqual(r["bucket"], "NO_RULE")
        self.assertEqual(r["fired_in_family"], [])
        self.assertIn("6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c01", r["off_label_rules"])
        self.assertEqual(r["rules_in_family"], [])

    def test_n2_below_threshold_is_a_miss_the_oracle_agrees_with(self):
        r = row_of(self.results, "ctl_below.yml")
        self.assertEqual(r["bucket"], "MISS")
        self.assertEqual(r["oracle"], "agrees_no_fire")
        t = self.results["per_technique"]["T1110.001"]
        self.assertGreaterEqual(t["buckets"]["MISS"], 1)

    def test_oracle_only_for_the_six_oracle_rule_families(self):
        r = row_of(self.results, "ctl_miss_nonoracle.yml")
        self.assertEqual(r["bucket"], "MISS")
        self.assertEqual(r["oracle"], "not_applicable")       # T1136 has no ORACLE rule
        for rr in self.results["rows"]:
            if rr["bucket"] != "MISS":
                self.assertIsNone(rr["oracle"], rr["dataset_id"])

    def test_spray_label_is_family_only_and_listed_as_no_exact_rule(self):
        r = row_of(self.results, "ctl_spray_label.yml")
        self.assertEqual(r["bucket"], "HIT_FAMILY")
        self.assertNotIn("4f8a2c61-9e3d-4b57-8a1c-6d2e5f7a8b90", r["rules_in_family"])
        t = self.results["per_technique"]["T1110.003"]
        self.assertFalse(t["exact_rule"])
        self.assertTrue(t["sibling_gap"])
        self.assertIn("T1110.003", [g["technique"] for g in self.results["gap_no_exact_rule"]])

    def test_lfs_pointer_is_not_fetched_not_a_miss(self):
        r = row_of(self.results, "ctl_lfs_only.yml")
        self.assertEqual(r["bucket"], "NOT_FETCHED")
        self.assertEqual(r["fetch_state"], "none_present")
        self.assertEqual(r["records_total"], 0)

    def test_unsupported_source_is_no_parser_and_named(self):
        r = row_of(self.results, "ctl_cloudtrail.yml")
        self.assertEqual(r["bucket"], "NO_PARSER")
        self.assertEqual(r["unsupported_sources"], ["aws_cloudtrail"])
        self.assertEqual(r["files_unsupported"], 1)

    def test_unlabelled_has_its_own_bucket(self):
        r = row_of(self.results, "ctl_nolabel.yml")
        self.assertEqual(r["bucket"], "UNLABELLED")
        self.assertIsNone(r["label"])
        self.assertEqual(r["label_source"], "none")

    def test_multi_label_scenario_is_scored_per_label(self):
        a = row_of(self.results, "ctl_multi.yml", "T1110.001")
        b = row_of(self.results, "ctl_multi.yml", "T1059.001")
        self.assertEqual((a["bucket"], b["bucket"]), ("HIT_FAMILY", "NO_RULE"))
        self.assertIn("6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c01", b["off_label_rules"])

    def test_old_style_yaml_uses_dir_label_and_sniffs_xml(self):
        r = row_of(self.results, "ctl_old.yml")
        self.assertEqual(r["label_source"], "dirname")
        self.assertEqual(r["label"], "T1110.001")
        self.assertEqual(r["bucket"], "HIT_FAMILY")

    def test_partial_parse_is_flagged_with_unparsed_ids(self):
        r = row_of(self.results, "ctl_partial.yml")
        self.assertEqual(r["bucket"], "HIT_FAMILY")
        self.assertTrue(r["partial_parse"])
        self.assertEqual((r["records_total"], r["records_supported"]), (22, 12))
        self.assertAlmostEqual(r["parsed_fraction"], round(12 / 22, 4))
        self.assertEqual(r["unparsed_event_ids"], {f"{SYSMON}:10": 10})
        self.assertGreaterEqual(self.results["partial_parse_units"], 1)

    def test_label_dir_disagreement_is_recorded(self):
        r = row_of(self.results, "ctl_disagree.yml")
        self.assertTrue(r["label_dir_disagree"])
        self.assertEqual((r["label"], r["dir_label"]), ("T1110.001", "T1021.002"))
        self.assertFalse(row_of(self.results, "ctl_burst.yml")["label_dir_disagree"])

    def test_partial_fetch_is_visible(self):
        r = row_of(self.results, "ctl_partialfetch.yml")
        self.assertEqual(r["fetch_state"], "partial")
        self.assertEqual((r["files_declared"], r["files_present"]), (2, 1))
        self.assertEqual(r["bucket"], "MISS")                # half the events only

    def test_accounting_invariants(self):
        res = self.results
        self.assertEqual(sum(res["buckets"].values()), res["units_total"])
        self.assertEqual(res["units_total"], len(res["rows"]))
        n_yml = len(list((self.root / "datasets").rglob("*.yml")))
        self.assertEqual(res["scenarios_total"], n_yml)
        self.assertEqual(res["units_total"], n_yml + 1)      # ctl_multi has two labels
        self.assertEqual(set(res["buckets"]), set(TM.BUCKETS))
        for b in ("HIT_EXACT", "HIT_FAMILY", "MISS", "NO_RULE", "NO_PARSER",
                  "UNLABELLED", "NOT_FETCHED"):
            self.assertGreaterEqual(res["buckets"][b], 1, b)
        self.assertEqual(res["units_fetched"],
                         res["units_total"] - res["buckets"]["NOT_FETCHED"]
                         - res["buckets"]["READER_UNAVAILABLE"])
        for lab, t in res["per_technique"].items():
            self.assertEqual(t["end_to_end"], f'{t["hits"]}/{t["n_fetched"]}', lab)
            self.assertEqual(t["reachable"], f'{t["hits"]}/{t["reachable_n"]}', lab)
            self.assertEqual(sum(t["buckets"].values()), t["n_units"], lab)

    def test_every_per_technique_number_carries_its_n(self):
        t = self.results["per_technique"]["T1110.001"]
        self.assertRegex(t["end_to_end"], r"^\d+/\d+$")
        self.assertRegex(t["reachable"], r"^\d+/\d+$")
        self.assertNotIn("%", json.dumps(self.results))      # never a bare percentage

    def test_no_rule_techniques_are_listed_not_dropped(self):
        gap = {g["technique"]: g["n_fetched"] for g in self.results["gap_no_rule"]}
        self.assertEqual(gap.get("T1059.001"), 2)            # ctl_relabelled + ctl_multi label
        self.assertNotIn("T1003.001", gap)                    # NOT_FETCHED: no fetched dataset
        self.assertNotIn("T1110.001", gap)

    def test_n7_deterministic_and_order_independent(self):
        # a 3-scenario subtree keeps this cheap (one fresh Detector per scenario)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "s"
            write_splunk(root, "T1110.001", "d_burst", [("w.log", SEC, "\n".join(failed_logons(12)))],
                         ["T1110.001"])
            write_splunk(root, "T1110.001", "d_below", [("w.log", SEC, "\n".join(failed_logons(3)))],
                         ["T1110.001"])
            write_splunk(root, "T1059.001", "d_norule", [("w.log", SEC, "\n".join(failed_logons(12)))],
                         ["T1059.001"])
            first = BR.run([CA.SplunkAttackData(root)], RULES)
            again = BR.run([CA.SplunkAttackData(root)], RULES)
            ad = CA.SplunkAttackData(root)
            rev = type("Rev", (), {"name": ad.name,
                                   "scenarios": lambda s: reversed(list(ad.scenarios()))})()
            shuffled = BR.run([rev], RULES)
        dump = lambda r: json.dumps(r, sort_keys=True)          # noqa: E731
        self.assertEqual(dump(first), dump(again))
        self.assertEqual(dump(first), dump(shuffled))
        self.assertEqual([r["bucket"] for r in first["rows"]], ["NO_RULE", "MISS", "HIT_FAMILY"])
        self.assertNotRegex(json.dumps(self.results), r"(timestamp|generated_at|run_at|\bdate\b)")

    def test_files_listed_in_adapter_are_sorted_by_path(self):
        ids = [s.dataset_id for s in CA.SplunkAttackData(self.root).scenarios()]
        self.assertEqual(ids, sorted(ids))


class TestNegativeControls(unittest.TestCase):

    def _one(self, td: Path, rules: Path):
        root = td / "s"
        write_splunk(root, "T1110.001", "ctl_burst", [("w.log", SEC, "\n".join(failed_logons(12)))],
                     ["T1110.001"])
        return BR.run([CA.SplunkAttackData(root)], rules)

    def test_n3_lane_can_go_red_when_the_rules_are_gone(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            full = self._one(td, RULES)
            self.assertEqual(full["rows"][0]["bucket"], "HIT_FAMILY")
            reduced = self._one(td, reduced_rules_dir(td / "rules"))
            self.assertEqual(reduced["rows"][0]["bucket"], "NO_RULE")
            key = BR.unit_key(full["rows"][0])
            rc, msgs = BR.verdict(reduced, baseline={key: "HIT_FAMILY"})
            self.assertEqual(rc, 1)
            self.assertTrue(any("regression" in m and key in m for m in msgs), msgs)
            rc_ok, _ = BR.verdict(full, baseline={key: "HIT_FAMILY"})
            self.assertEqual(rc_ok, 0)
            # a unit that was never a HIT may change freely (no invented threshold)
            rc_free, _ = BR.verdict(reduced, baseline={key: "MISS"})
            self.assertEqual(rc_free, 0)

    def test_n4_no_vacuous_green(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "s"
            write_splunk(root, "T1110.001", "only_ptr",
                         [("w.log", SEC, LFS_POINTER.format(oid="ef" * 32, size=1))], ["T1110.001"])
            write_splunk(root, "T1110.001", "only_missing", [], ["T1110.001"])
            res = BR.run([CA.SplunkAttackData(root)], RULES)
        self.assertEqual(res["units_fetched"], 0)
        self.assertEqual(res["buckets"]["NOT_FETCHED"], 2)
        rc, msgs = BR.verdict(res)
        self.assertEqual(rc, 0)
        self.assertTrue(msgs[0].startswith("[SKIP]"))
        rc, msgs = BR.verdict(res, require_corpus=True)
        self.assertEqual(rc, 1)
        self.assertIn("--require-corpus", msgs[0])

    def test_n9_nothing_scoreable_fails_require_corpus(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "s"
            # fetched, but only NO_PARSER (CloudTrail) and NO_RULE (T1059.001) -> measured nothing
            write_splunk(root, "T1078.004", "ct", [("c.json", "aws_cloudtrail", "{}\n")], ["T1078.004"])
            write_splunk(root, "T1059.001", "norule", [("w.log", SEC, "\n".join(failed_logons(12)))],
                         ["T1059.001"])
            res = BR.run([CA.SplunkAttackData(root)], RULES)
        self.assertEqual(res["scoreable_units"], 0)
        self.assertGreater(res["units_fetched"], 0)
        self.assertEqual(BR.verdict(res)[0], 0)
        rc, msgs = BR.verdict(res, require_corpus=True)
        self.assertEqual(rc, 1)
        self.assertIn("scoreable", msgs[0])

    def test_n8_no_label_leakage_adapters_never_see_rules_or_alerts(self):
        src = (HERE / "corpus_adapters.py").read_text(encoding="utf-8")
        for token in ("load_rule_index", "rules_in_family", "alert_level", "Detector",
                      "ORACLE_RULES", "oracle(", "contracts/rules", "ws4", "alerts"):
            self.assertNotIn(token, src, f"corpus_adapters.py must not reference {token!r}")

    def test_n8b_bucket_follows_the_label_not_the_alert(self):
        """A stub adapter hands back a deliberately wrong label for events the
        engine DOES alert on: the row must carry exactly that label and score
        NO_RULE; with the right label the same records score HIT_FAMILY."""
        recs = []
        res = CA.LoadResult()
        import evtx_eval as E
        CA.route_records((E.extract_record(x) for x in failed_logons(12)), res)
        recs = res.records

        def stub(label):
            sc = CA.Scenario(dataset_id="stub", corpus="stub", labels=[label], label_source="stub",
                             files=[], fetch_state="present", _loader=lambda s: res)
            return SimpleNamespace(name="stub", scenarios=lambda: iter([sc]))
        wrong = BR.run([stub("T1059.001")], RULES)
        right = BR.run([stub("T1110.001")], RULES)
        self.assertEqual(len(recs), 12)
        self.assertEqual((wrong["rows"][0]["label"], wrong["rows"][0]["bucket"]), ("T1059.001", "NO_RULE"))
        self.assertTrue(wrong["rows"][0]["off_label_rules"])
        self.assertEqual((right["rows"][0]["label"], right["rows"][0]["bucket"]),
                         ("T1110.001", "HIT_FAMILY"))

    def test_run_refuses_to_drop_a_unit(self):
        sc = CA.Scenario(dataset_id="x", corpus="x", labels=["T1110"], label_source="s",
                         files=[], fetch_state="present", _loader=lambda s: CA.LoadResult())
        ad = SimpleNamespace(name="x", scenarios=lambda: iter([sc]))

        def dropping(sc_, index, rules_dir, replay_fn=None):
            return []
        orig = BR.score_scenario
        BR.score_scenario = dropping
        try:
            with self.assertRaises(AssertionError):
                BR.run([ad], RULES)
        finally:
            BR.score_scenario = orig


class TestEvtxToMitre(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._td = tempfile.TemporaryDirectory()
        cls.root = Path(cls._td.name) / "evtx like"
        files = {
            "TA0006-Credential Access/T1110.xxx-Brut force/ctl burst & co.evtx": failed_logons(12),
            "TA0006-Credential Access/T1136.001-Create Account/ctl_acct.evtx": account_create(),
            "TA0002-Execution/T1059.001-PowerShell/ctl_norule.evtx": failed_logons(12),
            "Antivirus/ctl_av.evtx": failed_logons(12),
            "TA0006-Credential Access/T1110.xxx-Brut force/ctl_empty.evtx": None,
        }
        cls.xml = {}
        for rel, events in files.items():
            p = cls.root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b"" if events is None else b"ElfFile\x00placeholder")
            cls.xml[p.name] = events
        (cls.root / ".git").mkdir()                       # must be ignored by the walker
        (cls.root / ".git" / "junk.evtx").write_bytes(b"ElfFile\x00")

        def opener(path):
            return iter(cls.xml[Path(path).name])
        cls.opener = staticmethod(opener)
        cls.results = BR.run([CA.EvtxToMitre(cls.root, opener=opener)], RULES)

    @classmethod
    def tearDownClass(cls):
        cls._td.cleanup()

    def test_p5_path_label_scores_exact_for_parent_level_label(self):
        r = row_of(self.results, "ctl burst & co.evtx")
        self.assertEqual(r["label"], "T1110")
        self.assertEqual(r["label_flags"], ["sub_unspecified"])
        self.assertEqual(r["bucket"], "HIT_EXACT")
        self.assertEqual(r["tactics"], ["TA0006"])
        self.assertEqual(r["label_source"], "path:TAxxxx-<Tactic>/Txxxx[.yyy]-<name>")

    def test_miss_no_rule_unlabelled_not_fetched(self):
        self.assertEqual(row_of(self.results, "ctl_acct.evtx")["bucket"], "MISS")
        self.assertEqual(row_of(self.results, "ctl_acct.evtx")["oracle"], "not_applicable")
        self.assertEqual(row_of(self.results, "ctl_norule.evtx")["bucket"], "NO_RULE")
        r = row_of(self.results, "ctl_av.evtx")
        self.assertEqual((r["bucket"], r["label"]), ("UNLABELLED", None))
        self.assertEqual(row_of(self.results, "ctl_empty.evtx")["bucket"], "NOT_FETCHED")

    def test_git_dir_is_ignored_and_accounting_holds(self):
        self.assertFalse(any(".git" in r["dataset_id"] for r in self.results["rows"]))
        self.assertEqual(self.results["scenarios_total"], 5)
        self.assertEqual(sum(self.results["buckets"].values()), 5)

    def test_reader_unavailable_is_its_own_bucket_and_not_scored(self):
        def no_reader(path):
            raise CA.ReaderUnavailable("python-evtx not installed")
        res = BR.run([CA.EvtxToMitre(self.root, opener=no_reader)], RULES)
        # labelled datasets: reader missing; Antivirus/ has no label so it is UNLABELLED
        # regardless of the reader; the 0-byte file is NOT_FETCHED
        self.assertEqual(res["buckets"]["READER_UNAVAILABLE"], 3)
        self.assertEqual(res["buckets"]["UNLABELLED"], 1)
        self.assertEqual(res["buckets"]["NOT_FETCHED"], 1)
        self.assertEqual(res["buckets"]["MISS"], 0)
        # the empty-file dataset and the reader-less ones are outside the denominator
        self.assertEqual(res["units_fetched"], 1)      # only the UNLABELLED one
        self.assertEqual(res["scoreable_units"], 0)
        rc, _ = BR.verdict(res, require_corpus=True)
        self.assertEqual(rc, 1)

    def test_python_evtx_is_imported_lazily(self):
        code = ("import sys; sys.path.insert(0, %r); import corpus_adapters, blind_recall; "
                "assert 'Evtx' not in sys.modules, 'python-evtx imported at module import'" % str(HERE))
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_default_opener_reports_missing_dependency(self):
        saved = sys.modules.get("Evtx"), sys.modules.get("Evtx.Evtx")
        sys.modules["Evtx"] = None                     # makes `from Evtx.Evtx import Evtx` fail
        sys.modules["Evtx.Evtx"] = None
        try:
            with self.assertRaises(CA.ReaderUnavailable):
                CA.default_evtx_opener(Path("x.evtx"))
        finally:
            for k, v in zip(("Evtx", "Evtx.Evtx"), saved):
                if v is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = v


class TestVerdict(unittest.TestCase):

    def test_skip_is_rc0_and_require_is_rc1_on_empty(self):
        empty = {"units_fetched": 0, "scoreable_units": 0, "rows": []}
        self.assertEqual(BR.verdict(empty)[0], 0)
        self.assertEqual(BR.verdict(empty, require_corpus=True)[0], 1)

    def test_baseline_missing_unit_counts_as_regression(self):
        res = {"units_fetched": 1, "scoreable_units": 1, "rows": []}
        rc, msgs = BR.verdict(res, baseline={"c::d::T1110": "HIT_EXACT"})
        self.assertEqual(rc, 1)
        self.assertIn("ABSENT", msgs[0])


class TestFetchTooling(unittest.TestCase):

    def test_committed_manifest_is_valid_and_honest(self):
        m = FC.load_manifest()["corpora"]
        self.assertEqual(m["splunk-attack-data"]["license_spdx"], "Apache-2.0")
        self.assertEqual(m["evtx-to-mitre"]["license_spdx"], "CC0-1.0")
        self.assertEqual(m["evtx-attack-samples"]["license_spdx"], "GPL-3.0")
        for name, c in m.items():
            self.assertFalse(c["vendored"], name)              # nothing is vendored
        self.assertFalse(m["evtx-attack-samples"]["redistributable"])
        self.assertNotIn("blind_recall", m["evtx-attack-samples"]["lanes"])
        # sizes/file counts of an unmeasured corpus are not asserted anywhere
        self.assertNotIn("288", json.dumps(m["evtx-to-mitre"]))

    def test_manifest_validation_rejects_untrustworthy_entries(self):
        base = json.loads((HERE / "corpus_manifest.json").read_text(encoding="utf-8"))

        def with_(name, **kw):
            doc = json.loads(json.dumps(base))
            doc["corpora"][name].update(kw)
            return doc
        for kw in ({"pin": "abc123"}, {"pin": "G" * 40}, {"url": "http://example.org/x"},
                   {"dest": "../escape"}, {"dest": "/abs"}, {"license_spdx": ""}):
            with self.assertRaises(ValueError, msg=str(kw)):
                FC.validate_manifest(with_("splunk-attack-data", **kw))
        with self.assertRaises(ValueError):
            FC.validate_manifest(with_("evtx-attack-samples", vendored=True))

    def test_selection_is_outcome_blind_and_capped(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ptr = lambda n: LFS_POINTER.format(oid="aa" * 32, size=n)       # noqa: E731
            sizes = {"c": 300, "a": 100, "b": 200, "d": 400}
            for nm, sz in sizes.items():
                write_splunk(root, "T1110.001", f"s_{nm}", [("w.log", SEC, ptr(sz))], ["T1110.001"])
            write_splunk(root, "T1059.001", "s_norule", [("w.log", SEC, ptr(1))], ["T1059.001"])
            write_splunk(root, "T1110.001", "s_ct", [("c.json", "aws_cloudtrail", ptr(1))], ["T1110.001"])
            write_splunk(root, "T1110.001", "s_present", [("w.log", SEC, "\n".join(failed_logons(2)))],
                         ["T1110.001"])
            sel = FC.select_splunk_files(root, RULES, {"per_technique": 2, "max_files": 60,
                                                       "max_bytes": 10 ** 9})
            self.assertEqual([s["dataset_id"].split("/")[1] for s in sel["scenarios"]],
                             ["s_a", "s_b"])                       # two smallest, by size
            self.assertEqual(sel["bytes"], 300)
            self.assertTrue(all(f.endswith("w.log") and "s_norule" not in f and "s_ct" not in f
                                and "s_present" not in f for f in sel["files"]))
            capped = FC.select_splunk_files(root, RULES, {"per_technique": 4, "max_files": 60,
                                                          "max_bytes": 350})
            self.assertEqual([s["dataset_id"].split("/")[1] for s in capped["scenarios"]],
                             ["s_a", "s_b"])
            self.assertGreaterEqual(capped["skipped"]["over_cap"], 1)
            again = FC.select_splunk_files(root, RULES, {"per_technique": 2, "max_files": 60,
                                                         "max_bytes": 10 ** 9})
            self.assertEqual(sel, again)

    def test_lfs_pull_failure_is_reported_not_swallowed(self):
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td)
            (dest / "p.log").write_text(LFS_POINTER.format(oid="bb" * 32, size=5), encoding="utf-8")
            (dest / "ok.log").write_text("<Event/>", encoding="utf-8")

            def run_no_lfs(cmd, **kw):
                rc = 1 if cmd[1:3] == ["lfs", "version"] else 0
                return SimpleNamespace(returncode=rc, stdout="", stderr="git: 'lfs' is not a git command")
            r = FC.lfs_pull(dest, ["p.log"], run=run_no_lfs)
            self.assertFalse(r["ok"])
            self.assertIn("git-lfs", r["errors"][0])

            def run_silent_noop(cmd, **kw):                  # pull 'succeeds' but delivers nothing
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            r = FC.lfs_pull(dest, ["p.log", "ok.log", "gone.log"], run=run_silent_noop)
            self.assertFalse(r["ok"])
            self.assertEqual((r["pulled"], r["still_pointer"], r["missing"]),
                             (1, ["p.log"], ["gone.log"]))

    def test_head_sha_ignores_nested_non_repo_dirs(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertIsNone(FC.head_sha(Path(td)))

    def test_pinned_fetch_checks_out_the_pin_and_rejects_a_bad_one(self):
        if shutil.which("git") is None:
            print("[SKIP-LOUD] git not on PATH: pinned-fetch control not executed")
            return
        env_cfg = ["-c", "user.name=ctl", "-c", "user.email=ctl@example.org", "-c", "commit.gpgsign=false"]
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            origin = td / "origin repo"
            origin.mkdir()

            def g(*a):
                r = subprocess.run(["git", *env_cfg, *a], cwd=origin, capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stderr)
                return r.stdout.strip()
            g("init", "-q")
            (origin / "f.txt").write_text("one", encoding="utf-8")
            g("add", "-A")
            g("commit", "-q", "-m", "one")
            first = g("rev-parse", "HEAD")
            (origin / "f.txt").write_text("two", encoding="utf-8")
            g("commit", "-qam", "two")
            second = g("rev-parse", "HEAD")
            self.assertNotEqual(first, second)
            entry = {"url": str(origin), "allow_local_url": True, "pin": first, "sparse_paths": []}
            st = FC.fetch_corpus("ctl", entry, td / "dest")
            self.assertTrue(st["ok"], st)
            self.assertEqual((st["head"], st["pin_matches"]), (first, True))
            self.assertEqual((td / "dest" / "f.txt").read_text(encoding="utf-8"), "one")
            bad = dict(entry, pin="0" * 40)
            st = FC.fetch_corpus("ctl", bad, td / "dest2")
            self.assertFalse(st["ok"])
            self.assertTrue(st["errors"])
            dry = FC.fetch_corpus("ctl", entry, td / "dest3", dry_run=True)
            self.assertTrue(dry["ok"])
            self.assertFalse((td / "dest3").exists())              # dry run touches nothing


if __name__ == "__main__":
    unittest.main(verbosity=2)
