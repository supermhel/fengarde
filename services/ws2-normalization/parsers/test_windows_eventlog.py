"""Unit tests for the windows_eventlog parser.

Run with:
    C:/Python313/python.exe services/ws2-normalization/parsers/test_windows_eventlog.py
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

# Make shared/ and parsers/ importable when running this file directly.
HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent.parent   # services/
ROOT = SERVICES.parent          # repo root

sys.path.insert(0, str(HERE.parent))   # ws2-normalization/ (so `parsers` pkg works)
sys.path.insert(0, str(SERVICES))       # services/ (so `shared` works)

from shared.ocsf import validate  # noqa: E402
from parsers.windows_eventlog import WindowsEventLogParser  # noqa: E402

PARSER = WindowsEventLogParser()


def _raw(rec, meta=None):
    return {"source_type": "windows_eventlog", "raw": rec, "meta": meta or {}}


REC_4624 = {
    "EventID": 4624, "TimeCreated": 1750000000000,
    "TargetUserName": "jdoe", "TargetDomainName": "BANKCORP",
    "TargetUserSid": "S-1-5-21-1", "IpAddress": "10.20.30.40",
    "WorkstationName": "wks-jdoe", "Computer": "dc01",
}
REC_4634 = {"EventID": 4634, "TargetUserName": "jdoe", "Computer": "wks-jdoe"}
REC_4647 = {"EventID": 4647, "TargetUserName": "jdoe", "Computer": "wks-jdoe"}
REC_4688 = {
    "EventID": 4688, "TimeCreated": 1750000000000,
    "SubjectUserName": "jdoe", "SubjectDomainName": "BANKCORP",
    "Computer": "wks-jdoe",
    "NewProcessName": r"C:\Windows\System32\cmd.exe", "NewProcessId": "0x1f4",
}
REC_4672 = {
    "EventID": 4672, "SubjectUserName": "admin",
    "SubjectDomainName": "BANKCORP", "Computer": "dc01",
}
# v0.3 (A4): Account Change fixtures. Subject = acting admin; Target = the
# account being created/enabled/deleted/granted.
REC_4720 = {
    "EventID": 4720, "TimeCreated": 1750000000000,
    "SubjectUserName": "admin", "SubjectDomainName": "BANKCORP",
    "TargetUserName": "new_svc_acct", "TargetDomainName": "BANKCORP",
    "TargetUserSid": "S-1-5-21-9", "Computer": "dc01",
}
REC_4722 = {
    "EventID": 4722, "SubjectUserName": "admin",
    "TargetUserName": "new_svc_acct", "Computer": "dc01",
}
REC_4726 = {
    "EventID": 4726, "SubjectUserName": "admin",
    "TargetUserName": "old_svc_acct", "Computer": "dc01",
}
REC_4728 = {
    "EventID": 4728, "SubjectUserName": "admin",
    "TargetUserName": "new_svc_acct", "Computer": "dc01",
}
REC_4732 = {
    "EventID": 4732, "SubjectUserName": "admin",
    "TargetUserName": "new_svc_acct", "Computer": "dc01",
}


class TestWindowsEventLogParser(unittest.TestCase):

    # ---- 4624 successful logon -> Authentication / Success -----------
    def test_4624_logon(self):
        event = PARSER.parse(_raw(REC_4624))
        self.assertIsNotNone(event)
        self.assertEqual(event["class_uid"], 3002)
        self.assertEqual(event["activity_id"], 1)
        self.assertEqual(event["type_uid"], 300201)
        self.assertEqual(event["status"], "Success")
        # IpAddress/WorkstationName is the logon SOURCE...
        self.assertEqual(event["src_endpoint"]["ip"], "10.20.30.40")
        self.assertEqual(event["src_endpoint"]["hostname"], "wks-jdoe")
        # ...and Computer is the host logged INTO (destination) -- this is what the
        # lateral-movement rule distinct-counts per account.
        self.assertEqual(event["dst_endpoint"]["hostname"], "dc01")
        self.assertEqual(event["actor"]["user"]["name"], "jdoe")
        self.assertEqual(event["actor"]["user"]["domain"], "BANKCORP")
        self.assertEqual(validate(event), [])

    # ---- 4634 / 4647 logoff -> Authentication activity 2 -------------
    def test_4634_logoff(self):
        event = PARSER.parse(_raw(REC_4634))
        self.assertIsNotNone(event)
        self.assertEqual(event["class_uid"], 3002)
        self.assertEqual(event["activity_id"], 2)
        self.assertEqual(event["type_uid"], 300202)
        self.assertEqual(validate(event), [])

    def test_4647_logoff(self):
        event = PARSER.parse(_raw(REC_4647))
        self.assertIsNotNone(event)
        self.assertEqual(event["activity_id"], 2)
        self.assertEqual(validate(event), [])

    # ---- 4688 new process -> Kernel/Process, Launch -----------------
    def test_4688_process_created(self):
        event = PARSER.parse(_raw(REC_4688))
        self.assertIsNotNone(event)
        self.assertEqual(event["class_uid"], 1002)
        self.assertEqual(event["activity_id"], 1)
        self.assertEqual(event["type_uid"], 100201)
        self.assertEqual(event["actor"]["process"]["name"], REC_4688["NewProcessName"])
        self.assertEqual(event["actor"]["process"]["pid"], 0x1f4)  # hex parsed
        self.assertEqual(event["actor"]["user"]["name"], "jdoe")
        self.assertEqual(validate(event), [])

    # ---- 4672 special privileges -> Kernel/Process, priv use --------
    def test_4672_special_privileges(self):
        event = PARSER.parse(_raw(REC_4672))
        self.assertIsNotNone(event)
        self.assertEqual(event["class_uid"], 1002)
        self.assertEqual(event["activity_id"], 2)
        self.assertEqual(event["type_uid"], 100202)
        self.assertEqual(event["severity_id"], 3)  # Medium
        self.assertEqual(event["actor"]["user"]["name"], "admin")
        self.assertEqual(validate(event), [])

    # ---- unhandled EventID -> None ----------------------------------
    def test_unhandled_eventid_returns_none(self):
        # 4625 is owned by the active_directory parser; not handled here.
        self.assertIsNone(PARSER.parse(_raw({"EventID": 4625, "TargetUserName": "x"})))
        self.assertIsNone(PARSER.parse(_raw({"EventID": 9999})))

    # ---- malformed / empty input -> None ----------------------------
    def test_malformed_input_returns_none(self):
        self.assertIsNone(PARSER.parse(_raw(None)))
        self.assertIsNone(PARSER.parse(_raw("not json")))
        self.assertIsNone(PARSER.parse(_raw({})))                 # no EventID
        self.assertIsNone(PARSER.parse(_raw({"EventID": "abc"}))) # non-int EventID
        self.assertIsNone(PARSER.parse({}))                       # empty payload

    def test_json_string_raw_parses(self):
        import json
        event = PARSER.parse(_raw(json.dumps(REC_4624)))
        self.assertIsNotNone(event)
        self.assertEqual(event["class_uid"], 3002)
        self.assertEqual(validate(event), [])

    # ---- meta.sector override propagates -----------------------------
    def test_sector_override(self):
        event = PARSER.parse(_raw(REC_4624, {"sector": "datacenter"}))
        self.assertIsNotNone(event)
        self.assertEqual(event["siem"]["sector"], "datacenter")
        self.assertEqual(validate(event), [])

    def test_default_sector(self):
        event = PARSER.parse(_raw(REC_4624))
        self.assertEqual(event["siem"]["sector"], "common")

    # ---- meta.ingest_id propagates -----------------------------------
    def test_ingest_id_from_meta(self):
        event = PARSER.parse(_raw(REC_4624, {"ingest_id": "fixed-id-1"}))
        self.assertEqual(event["siem"]["ingest_id"], "fixed-id-1")

    # ---- type_uid invariant for every handled EventID ----------------
    def test_type_uid_invariant(self):
        for rec in (REC_4624, REC_4634, REC_4647, REC_4688, REC_4672,
                    REC_4720, REC_4722, REC_4726, REC_4728, REC_4732):
            with self.subTest(eventid=rec["EventID"]):
                event = PARSER.parse(_raw(rec))
                self.assertIsNotNone(event)
                self.assertEqual(
                    event["type_uid"],
                    event["class_uid"] * 100 + event["activity_id"],
                )
                self.assertEqual(validate(event), [])

    # ---- v0.3 (A4): Account Change (3003) EventIDs --------------------
    def test_4720_account_created(self):
        event = PARSER.parse(_raw(REC_4720))
        self.assertIsNotNone(event)
        self.assertEqual(event["class_uid"], 3003)
        self.assertEqual(event["activity_id"], 1)
        self.assertEqual(event["type_uid"], 300301)
        self.assertEqual(validate(event), [])

    def test_4722_account_enabled(self):
        event = PARSER.parse(_raw(REC_4722))
        self.assertEqual(event["class_uid"], 3003)
        self.assertEqual(event["activity_id"], 2)

    def test_4726_account_deleted(self):
        event = PARSER.parse(_raw(REC_4726))
        self.assertEqual(event["class_uid"], 3003)
        self.assertEqual(event["activity_id"], 4)

    def test_4728_and_4732_are_privilege_grant(self):
        for rec in (REC_4728, REC_4732):
            with self.subTest(eventid=rec["EventID"]):
                event = PARSER.parse(_raw(rec))
                self.assertEqual(event["class_uid"], 3003)
                self.assertEqual(event["activity_id"], 5)

    def test_account_change_actor_is_acting_admin_not_target(self):
        """The acting admin (Subject) goes in actor.user; the affected account
        (Target) is a DIFFERENT identity and must NOT leak into actor.user."""
        event = PARSER.parse(_raw(REC_4720))
        self.assertEqual(event["actor"]["user"]["name"], "admin")
        self.assertNotEqual(event["actor"]["user"]["name"], "new_svc_acct")

    def test_account_change_target_user_exposed_under_unmapped(self):
        event = PARSER.parse(_raw(REC_4720))
        self.assertEqual(event["unmapped"]["target_user"]["name"], "new_svc_acct")
        self.assertEqual(event["unmapped"]["target_user"]["domain"], "BANKCORP")
        self.assertEqual(event["unmapped"]["target_user"]["uid"], "S-1-5-21-9")

    def test_account_change_no_target_user_no_unmapped_key(self):
        """4688/4672 (process/priv-use, not account-change) never populate
        TargetUserName in these fixtures -- `unmapped` must be absent, not an
        empty/garbage dict."""
        event = PARSER.parse(_raw(REC_4672))
        self.assertNotIn("unmapped", event)

    def test_wrong_typed_ip_mac_user_dropped_not_crashed(self):
        """Regression for a Hypothesis property-testing finding (M1): see
        services/ws2-normalization/parsers/test_db_audit.py's identical
        regression for the shared root cause (services/shared/ocsf.py::
        valid_ip/valid_mac/safe_str)."""
        rec = {
            "EventID": 4624, "TimeCreated": 1750000000000,
            "TargetUserName": {"bad": "type"}, "IpAddress": 12345,
            "MacAddress": "not-a-mac", "WorkstationName": ["also", "bad"],
        }
        event = PARSER.parse(_raw(rec))
        self.assertIsNotNone(event)
        self.assertEqual(validate(event), [])
        self.assertNotIn("src_endpoint", event)
        self.assertNotIn("actor", event)


if __name__ == "__main__":
    unittest.main(verbosity=2)
