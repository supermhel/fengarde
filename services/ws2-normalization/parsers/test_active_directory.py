"""Unit tests for the active_directory parser.

Run with:
    python services/ws2-normalization/parsers/test_active_directory.py
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

# Make shared/ and parsers/ importable when running this file directly.
HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent.parent   # services/

sys.path.insert(0, str(HERE.parent))   # ws2-normalization/ (so `parsers` pkg works)
sys.path.insert(0, str(SERVICES))       # services/ (so `shared` works)

from shared.ocsf import validate  # noqa: E402
from parsers.active_directory import ActiveDirectoryParser  # noqa: E402

PARSER = ActiveDirectoryParser()


def _raw(rec, meta=None):
    return {"source_type": "active_directory", "raw": rec, "meta": meta or {}}


REC_4625 = {
    "EventID": 4625, "TimeCreated": 1750000000000,
    "TargetUserName": "jdoe", "TargetDomainName": "BANKCORP",
    "TargetUserSid": "S-1-5-21-1", "IpAddress": "10.20.30.40",
    "WorkstationName": "wks-jdoe", "MacAddress": "AA:BB:CC:DD:EE:FF",
}


class TestActiveDirectoryParser(unittest.TestCase):

    def test_failed_logon_parses_with_valid_fields(self):
        event = PARSER.parse(_raw(REC_4625))
        self.assertIsNotNone(event)
        self.assertEqual(event["class_uid"], 3002)
        self.assertEqual(event["activity_id"], 4)
        self.assertEqual(event["status"], "Failure")
        self.assertEqual(event["src_endpoint"]["ip"], "10.20.30.40")
        self.assertEqual(event["src_endpoint"]["hostname"], "wks-jdoe")
        self.assertEqual(event["src_endpoint"]["mac"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(event["actor"]["user"]["name"], "jdoe")
        self.assertEqual(event["actor"]["user"]["domain"], "BANKCORP")
        self.assertEqual(event["actor"]["user"]["uid"], "S-1-5-21-1")
        self.assertEqual(validate(event), [])

    def test_unknown_event_id_returns_none(self):
        self.assertIsNone(PARSER.parse(_raw({"EventID": 9999})))

    def test_wrong_typed_ip_mac_user_dropped_not_crashed(self):
        """F6 regression (adversarial repo-wide bug hunt, 2026-07-16): this
        parser skipped the M1 fix (services/shared/ocsf.py::valid_ip/
        valid_mac/safe_str) that db_audit/linux_ssh/mcp_agent/n8n_audit/
        opcua_audit/windows_eventlog already got -- see
        test_windows_eventlog.py's identical regression for the shared root
        cause. `rec` is attacker-controllable JSON; a wrong-typed IP/MAC/
        hostname/user field must be dropped from the event, never crash the
        parser and never produce a schema-invalid OCSF event that gets
        silently dead-lettered (missing a real logon/failure event on this
        bank-sector Authentication source).

        Note for future maintainers: this exact bug was NOT caught by
        test_property_hardening.py's generic Hypothesis fuzzing despite
        that suite covering every registered parser -- its random `raw`
        dicts essentially never happen to set EventID to one of this
        parser's 6 specific recognized values (4624/4634/4647/4625/4768/
        4771), so `parse()` returns None before ever reaching the
        vulnerable field assignments. A property test alone is not a
        substitute for a deterministic case on the parser's actual
        accepted-input shape.
        """
        rec = {
            "EventID": 4625, "TimeCreated": 1750000000000,
            "TargetUserName": {"bad": "type"}, "IpAddress": 12345,
            "MacAddress": ["also", "bad"], "WorkstationName": {"nested": True},
            "TargetUserSid": ["not", "a", "sid"],
        }
        event = PARSER.parse(_raw(rec))
        self.assertIsNotNone(event)
        self.assertEqual(validate(event), [])
        self.assertNotIn("src_endpoint", event)
        # actor.user.name is dropped (TargetUserName was wrong-typed) so the
        # whole actor block is absent -- SubjectUserName wasn't provided either.
        self.assertNotIn("actor", event)

    def test_wrong_typed_sid_alone_still_stringified_not_dropped(self):
        """TargetUserSid uses str(), not safe_str() (mirrors
        windows_eventlog.py) -- a wrong-typed sid degrades to a stringified
        value rather than silently dropping the whole actor/user block when
        the user's NAME is otherwise valid."""
        rec = {
            "EventID": 4625, "TimeCreated": 1750000000000,
            "TargetUserName": "jdoe", "TargetUserSid": ["weird"],
        }
        event = PARSER.parse(_raw(rec))
        self.assertIsNotNone(event)
        self.assertEqual(validate(event), [])
        self.assertEqual(event["actor"]["user"]["name"], "jdoe")
        self.assertEqual(event["actor"]["user"]["uid"], "['weird']")


if __name__ == "__main__":
    unittest.main(verbosity=2)
