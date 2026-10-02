"""Tests for tools/validate_rules.py (B4 rule validation gate).

Proves the validator ACCEPTS the shipped rules and REJECTS each class of
malformed rule it exists to catch -- a validator that never says no is
worthless, so every check gets an adversarial negative case.

Run: python tools/test_validate_rules.py
"""
from __future__ import annotations

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from validate_rules import validate_rule, RULES_DIR, main  # noqa: E402
import validate_rules as vr  # noqa: E402  -- for RULES_DIR monkeypatching in the floor tests

import yaml  # noqa: E402


def _base_rule() -> dict:
    """A minimal VALID rule; each test corrupts one thing."""
    return {
        "title": "Test rule",
        "id": "6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c01",
        "level": "high",
        "detection": {
            "sel": {"class_uid": 3002, "activity_id": 4},
            "condition": "sel",
        },
        "siem": {"sector": "common", "score_weight": 70,
                 "window_seconds": 60, "threshold": 10},
    }


class TestValidateRule(unittest.TestCase):
    def _errs(self, mutate):
        rule = _base_rule()
        mutate(rule)
        return validate_rule(rule)

    def test_base_rule_is_valid(self):
        self.assertEqual(validate_rule(_base_rule()), [])

    def test_missing_title(self):
        self.assertTrue(any("title" in e for e in self._errs(
            lambda r: r.pop("title"))))

    def test_bad_uuid(self):
        self.assertTrue(any("UUID" in e for e in self._errs(
            lambda r: r.update(id="not-a-uuid"))))

    def test_bad_level(self):
        self.assertTrue(any("level" in e for e in self._errs(
            lambda r: r.update(level="catastrophic"))))

    def test_no_selections(self):
        self.assertTrue(any("no selections" in e for e in self._errs(
            lambda r: r.update(detection={"condition": ""}))))

    def test_condition_references_undefined_selection(self):
        # INTENTIONAL reject (not a false-reject): the engine defaults an unknown
        # selection name to False, so `sel and ghost` can never fire and
        # `sel or ghost` has a dead term -- both are typos that silently break the
        # rule. Catching that is the gate's core anti-dormancy purpose.
        errs = self._errs(lambda r: r["detection"].update(condition="sel and ghost"))
        self.assertTrue(any("undefined selection 'ghost'" in e for e in errs))

    def test_list_value_is_accepted_as_equality_match(self):
        # The engine treats a non-dict value as equality (`actual != expected`),
        # so a list value legitimately matches an array-valued OCSF field. Must
        # NOT be rejected (was a false-reject caught in review).
        errs = self._errs(lambda r: r["detection"].__setitem__(
            "sel", {"observables.value": ["a", "b"]}))
        self.assertEqual(errs, [])

    def test_empty_selection_rejected_because_it_matches_everything(self):
        errs = self._errs(lambda r: r["detection"].__setitem__("sel", {}))
        self.assertTrue(any("matches EVERY event" in e for e in errs))

    def test_condition_unbalanced_parens(self):
        errs = self._errs(lambda r: r["detection"].update(condition="(sel"))
        self.assertTrue(any("condition" in e for e in errs))

    def test_unknown_operator_rejected(self):
        errs = self._errs(lambda r: r["detection"].__setitem__(
            "sel", {"score": {"regex": ".*"}}))
        self.assertTrue(any("unknown operator 'regex'" in e for e in errs))

    def test_numeric_operator_needs_number(self):
        errs = self._errs(lambda r: r["detection"].__setitem__(
            "sel", {"score": {"gt": "sixty"}}))
        self.assertTrue(any("needs a number" in e for e in errs))

    def test_not_in_missing_allowlist(self):
        errs = self._errs(lambda r: r["detection"].__setitem__(
            "sel", {"src_endpoint.ip": {"not_in": "does_not_exist"}}))
        self.assertTrue(any("does_not_exist" in e and "missing" in e for e in errs))

    def test_not_in_existing_allowlist_ok(self):
        # corp_ranges.yml ships in contracts/allowlists/
        errs = self._errs(lambda r: r["detection"].__setitem__(
            "sel", {"src_endpoint.ip": {"not_in": "corp_ranges"}}))
        self.assertEqual(errs, [])

    def test_outside_hours_bad_time_format(self):
        errs = self._errs(lambda r: r["detection"].__setitem__(
            "sel", {"time": {"outside_hours": {"start": "8am", "end": "18:00"}}}))
        self.assertTrue(any("HH:MM" in e for e in errs))

    def test_outside_hours_empty_window(self):
        errs = self._errs(lambda r: r["detection"].__setitem__(
            "sel", {"time": {"outside_hours": {"start": "08:00", "end": "08:00"}}}))
        self.assertTrue(any("start == end" in e for e in errs))

    def test_outside_hours_unknown_key(self):
        errs = self._errs(lambda r: r["detection"].__setitem__(
            "sel", {"time": {"outside_hours": {"start": "08:00", "end": "18:00",
                                               "timezone": "UTC"}}}))
        self.assertTrue(any("unknown key" in e for e in errs))

    def test_outside_hours_valid(self):
        errs = self._errs(lambda r: r["detection"].__setitem__(
            "sel", {"time": {"outside_hours": {"start": "08:00", "end": "18:00",
                                               "days": ["mon", "tue"],
                                               "tz_offset_minutes": 60}}}))
        self.assertEqual(errs, [])

    def test_outside_hours_never_falsely_flagged_always_matches(self):
        # R3-#35 regression: both fixed probes land on Thursday, so a
        # days=mon,tue window returns True for both -- the OLD two-probe check
        # could not tell "always matches" from "the probe day just isn't a
        # business day". The whole-week sweep must NOT flag a legitimate
        # mon/tue window (Monday noon is inside business hours).
        errs = self._errs(lambda r: r["detection"].__setitem__(
            "sel", {"time": {"outside_hours": {"start": "08:00", "end": "18:00",
                                               "days": ["mon", "tue"],
                                               "tz_offset_minutes": 60}}}))
        self.assertEqual(errs, [], f"legit mon/tue window must pass, got {errs}")
        self.assertFalse(any("EVERY timestamp" in e for e in errs))

    def test_exists_valid(self):
        errs = self._errs(lambda r: r["detection"].__setitem__(
            "sel", {"unmapped.ot.change_ticket_id": {"exists": True}}))
        self.assertEqual(errs, [])

    def test_exists_needs_boolean(self):
        errs = self._errs(lambda r: r["detection"].__setitem__(
            "sel", {"unmapped.ot.change_ticket_id": {"exists": "true"}}))
        self.assertTrue(any("exists" in e and "boolean" in e for e in errs))

    def test_score_weight_out_of_range(self):
        self.assertTrue(any("score_weight" in e for e in self._errs(
            lambda r: r["siem"].update(score_weight=150))))

    def test_stateful_requires_both_window_and_threshold(self):
        errs = self._errs(lambda r: r["siem"].pop("threshold"))
        self.assertTrue(any("together" in e for e in errs))

    def test_negative_window(self):
        self.assertTrue(any("window_seconds" in e for e in self._errs(
            lambda r: r["siem"].update(window_seconds=-5))))

    # -- C3: optional mitre block --------------------------------------

    def test_mitre_absent_is_fine(self):
        self.assertEqual(validate_rule(_base_rule()), [])

    def test_mitre_valid_attack(self):
        self.assertEqual(self._errs(
            lambda r: r.update(mitre={"tactic": "TA0006", "technique": "T1110"})), [])

    def test_mitre_valid_attack_subtechnique(self):
        self.assertEqual(self._errs(
            lambda r: r.update(mitre={"tactic": "TA0006", "technique": "T1110.003"})), [])

    def test_mitre_valid_ics(self):
        self.assertEqual(self._errs(
            lambda r: r.update(mitre={"framework": "attack-ics", "tactic": "TA0106",
                                      "technique": "T0836"})), [])

    def test_mitre_valid_atlas(self):
        self.assertEqual(self._errs(
            lambda r: r.update(mitre={"framework": "atlas", "tactic": "AML.TA0004",
                                      "technique": "AML.T0051"})), [])

    def test_mitre_missing_technique(self):
        self.assertTrue(any("technique" in e for e in self._errs(
            lambda r: r.update(mitre={"tactic": "TA0006"}))))

    def test_mitre_bad_technique_shape(self):
        self.assertTrue(any("technique" in e for e in self._errs(
            lambda r: r.update(mitre={"technique": "not-a-technique-id"}))))

    def test_mitre_bad_tactic_shape(self):
        self.assertTrue(any("tactic" in e for e in self._errs(
            lambda r: r.update(mitre={"technique": "T1110", "tactic": "bogus"}))))

    def test_mitre_bad_framework(self):
        self.assertTrue(any("framework" in e for e in self._errs(
            lambda r: r.update(mitre={"technique": "T1110", "framework": "made-up"}))))

    def test_mitre_unknown_key(self):
        self.assertTrue(any("unknown key" in e for e in self._errs(
            lambda r: r.update(mitre={"technique": "T1110", "url": "https://example.com"}))))

    def test_mitre_not_a_mapping(self):
        self.assertTrue(any("mitre" in e for e in self._errs(
            lambda r: r.update(mitre="T1110"))))

    # -- v0.5 A3: optional periodicity block -----------------------------

    def test_periodicity_valid(self):
        self.assertEqual(self._errs(
            lambda r: r["siem"].update(periodicity={"max_cv": 0.3})), [])

    def test_periodicity_not_a_mapping(self):
        self.assertTrue(any("periodicity must be a mapping" in e for e in self._errs(
            lambda r: r["siem"].update(periodicity=0.3))))

    def test_periodicity_max_cv_out_of_range(self):
        self.assertTrue(any("max_cv" in e for e in self._errs(
            lambda r: r["siem"].update(periodicity={"max_cv": 1.5}))))

    def test_periodicity_max_cv_zero_rejected(self):
        self.assertTrue(any("max_cv" in e for e in self._errs(
            lambda r: r["siem"].update(periodicity={"max_cv": 0}))))

    def test_periodicity_missing_max_cv(self):
        self.assertTrue(any("max_cv" in e for e in self._errs(
            lambda r: r["siem"].update(periodicity={}))))

    def test_periodicity_unknown_key(self):
        self.assertTrue(any("unknown key" in e for e in self._errs(
            lambda r: r["siem"].update(periodicity={"max_cv": 0.3, "bogus": 1}))))

    def test_periodicity_requires_window_and_threshold(self):
        def mutate(r):
            r["siem"].pop("window_seconds")
            r["siem"].pop("threshold")
            r["siem"]["periodicity"] = {"max_cv": 0.3}
        self.assertTrue(any("periodicity requires" in e for e in self._errs(mutate)))

    def test_periodicity_cannot_combine_with_distinct_field(self):
        def mutate(r):
            r["siem"]["periodicity"] = {"max_cv": 0.3}
            r["siem"]["distinct_field"] = "dst_endpoint.port"
        self.assertTrue(any("cannot be combined with distinct_field" in e
                            for e in self._errs(mutate)))

    # -- gap-hunt (2026-08-26): siem unknown-key rejection -------------------

    def test_siem_typoed_threshold_key_rejected(self):
        # The exact defect that shipped in common_bruteforce.yml: `treshold`
        # instead of `threshold` makes the rule STATELESS at runtime -- the
        # engine reads only the canonical keys and silently ignores this one,
        # so the rule fires on every matching event instead of after N.
        errs = self._errs(lambda r: r["siem"].__setitem__("treshold", 5))
        self.assertTrue(any("unknown key" in e and "treshold" in e for e in errs),
                        f"expected a typo'd 'treshold' key to fail, got {errs}")

    def test_siem_typoed_score_weight_key_rejected(self):
        errs = self._errs(lambda r: r["siem"].__setitem__("score_weigth", 70))
        self.assertTrue(any("unknown key" in e and "score_weigth" in e for e in errs),
                        f"expected a typo'd 'score_weigth' key to fail, got {errs}")

    def test_siem_all_canonical_keys_accepted(self):
        # Every key the real engine.Rule.__init__ consumes must stay legal --
        # the unknown-key check must reject typos, not the schema itself.
        def mutate(r):
            r["siem"].update(llm_gate=False, periodicity={"max_cv": 0.3},
                             group_by="src_endpoint.ip",
                             distinct_field="dst_endpoint.port")
        errs = self._errs(mutate)
        # distinct_field + periodicity don't compose: drop periodicity to
        # isolate the unknown-key check from the (separate, already-pinned)
        # composition rule.
        if any("cannot be combined" in e for e in errs):
            errs = [e for e in errs if "cannot be combined" not in e]
        self.assertTrue(not any("unknown key" in e for e in errs),
                        f"canonical siem keys must be accepted, got {errs}")


class TestMainFloors(unittest.TestCase):
    """Zero-rule / missing-file behavior of main().

    Regression for the gap-hunt finding: with an empty RULES_DIR every check
    in main() is vacuously true, so the gate printed "[OK] all 0 rule(s)
    valid" and exited 0 -- a contributor gate that validated NOTHING kept the
    tree green. Mutation-sound: delete the floor in main() and these tests go
    red (rc becomes 0).
    """

    def _run_main(self, args, rules_dir=None):
        real_dir = vr.RULES_DIR
        buf = io.StringIO()
        try:
            if rules_dir is not None:
                vr.RULES_DIR = rules_dir
            with contextlib.redirect_stdout(buf):
                rc = main(args)
        finally:
            vr.RULES_DIR = real_dir
        return rc, buf.getvalue()

    def test_empty_rules_dir_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, out = self._run_main(["validate_rules.py"], rules_dir=Path(tmp))
        self.assertNotEqual(rc, 0, f"ZERO rules must fail the gate, got rc={rc}")
        self.assertIn("ZERO rule files", out)

    def test_missing_rules_dir_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ghost = Path(tmp) / "does-not-exist"
            rc, out = self._run_main(["validate_rules.py"], rules_dir=ghost)
        self.assertNotEqual(rc, 0)
        self.assertIn("ZERO rule files", out)

    def test_missing_single_file_fails_cleanly(self):
        # Used to crash with a bare FileNotFoundError traceback instead of
        # producing a verdict -- the same "fails but says nothing" class.
        rc, out = self._run_main(["validate_rules.py", "no_such_rule_xyz.yml"])
        self.assertNotEqual(rc, 0)
        self.assertIn("[FAIL]", out)
        self.assertIn("not found", out)


_SIB_ID = "6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c01"
_COMP_ID = "d83b71c3-93eb-439f-86f9-5985ebcc38cb"
_OTHER_ID = "a1b2c3d4-5e6f-4708-9a1b-2c3d4e5f6071"


def _sibling() -> dict:
    r = _base_rule()
    r["id"] = _SIB_ID
    return r


def _companion(companion_of=_SIB_ID) -> dict:
    r = _base_rule()
    r["id"] = _COMP_ID
    r["siem"]["companion_of"] = companion_of
    return r


class TestCompanionOf(unittest.TestCase):
    """siem.companion_of is whitelisted by _SIEM_ALLOWED_KEYS but its VALUE used
    to be unchecked: a typo'd id, a list, a self-link or a chained link all
    shipped silently as a "companion" that is never suppressed nor disabled with
    its sibling (the engine just stores None for anything that is not a str)."""

    def _index(self, *rules):
        return {r["id"]: r for r in rules}

    def test_valid_link_passes(self):
        sib, comp = _sibling(), _companion()
        self.assertEqual(validate_rule(comp, self._index(sib, comp)), [])
        # the sibling itself (no companion_of) is unaffected
        self.assertEqual(validate_rule(sib, self._index(sib, comp)), [])

    def test_typo_id_fails(self):
        sib, comp = _sibling(), _companion("6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c02")
        errs = validate_rule(comp, self._index(sib, comp))
        self.assertTrue(any("companion_of" in e and "not the id of any rule" in e
                            for e in errs), errs)

    def test_list_value_fails_even_without_index(self):
        for bad in ([_SIB_ID], {"id": _SIB_ID}, 7, True, ""):
            comp = _companion(bad)
            errs = validate_rule(comp)  # shape check needs no index
            self.assertTrue(any("companion_of must be a non-empty string" in e
                                for e in errs), (bad, errs))

    def test_self_link_fails(self):
        comp = _companion(_COMP_ID)
        errs = validate_rule(comp, self._index(comp))
        self.assertTrue(any("own id" in e for e in errs), errs)

    def test_chained_link_fails(self):
        sib = _sibling()
        mid = _companion(_SIB_ID)               # mid is a companion of sib ...
        mid["id"] = _OTHER_ID
        leaf = _companion(_OTHER_ID)            # ... and leaf is a companion of mid
        errs = validate_rule(leaf, self._index(sib, mid, leaf))
        self.assertTrue(any("itself a companion" in e for e in errs), errs)
        # the one-hop link mid -> sib stays valid
        self.assertEqual(validate_rule(mid, self._index(sib, mid, leaf)), [])

    def test_main_checks_links_against_the_same_rules_dir(self):
        def write(d, name, rule):
            (Path(d) / name).write_text(yaml.safe_dump(rule), encoding="utf-8")

        real_dir = vr.RULES_DIR
        try:
            with tempfile.TemporaryDirectory() as tmp:
                vr.RULES_DIR = Path(tmp)
                write(tmp, "sib.yml", _sibling())
                write(tmp, "comp.yml", _companion())
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(main(["validate_rules.py"]), 0)
                    # single-file mode resolves siblings from the file's own dir
                    self.assertEqual(main(["validate_rules.py", str(Path(tmp) / "comp.yml")]), 0)
                write(tmp, "comp.yml", _companion("6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c02"))
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    self.assertNotEqual(main(["validate_rules.py"]), 0)
                    self.assertNotEqual(
                        main(["validate_rules.py", str(Path(tmp) / "comp.yml")]), 0)
                self.assertIn("companion_of", buf.getvalue())
        finally:
            vr.RULES_DIR = real_dir

    def test_every_shipped_companion_resolves(self):
        """Positive control on the REAL rule set: each shipped companion names a
        real, non-companion sibling (this is the gate working, not a tautology:
        test_typo_id_fails proves the same code rejects a bad link)."""
        index = vr.load_rules_index(RULES_DIR)
        links = [(r["id"], r["siem"]["companion_of"]) for r in index.values()
                 if isinstance(r.get("siem"), dict) and "companion_of" in r["siem"]]
        self.assertGreaterEqual(len(links), 5, links)
        for comp_id, sib_id in links:
            self.assertIn(sib_id, index, f"{comp_id} -> {sib_id}")
            self.assertEqual(validate_rule(index[comp_id], index), [])


class TestShippedRules(unittest.TestCase):
    def test_all_shipped_rules_pass(self):
        for path in sorted(RULES_DIR.glob("*.yml")):
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
            self.assertEqual(validate_rule(rule), [],
                             f"shipped rule {path.name} failed validation")

    def test_main_returns_zero_on_shipped_rules(self):
        self.assertEqual(main(["validate_rules.py"]), 0)


if __name__ == "__main__":
    unittest.main()
