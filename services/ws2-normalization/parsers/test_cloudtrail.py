"""Unit tests for the cloudtrail parser (v0.5 Track A4).

Fixtures are SPEC-DERIVED from AWS's published CloudTrail record schema, not
captured from a real AWS account -- same discipline as opcua_audit.py.

Run with:
    python services/ws2-normalization/parsers/test_cloudtrail.py
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent.parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(SERVICES))

from shared.ocsf import validate  # noqa: E402
from parsers.cloudtrail import CloudTrailParser  # noqa: E402
from parsers import resolve  # noqa: E402

PARSER = CloudTrailParser()


def _raw(rec, meta=None):
    return {"source_type": "cloudtrail", "raw": rec, "meta": meta or {}}


class TestCloudTrailParser(unittest.TestCase):

    def test_root_console_login_no_mfa(self):
        event = PARSER.parse(_raw({
            "eventVersion": "1.08", "eventTime": "2026-07-20T10:00:00Z",
            "eventSource": "signin.amazonaws.com", "eventName": "ConsoleLogin",
            "sourceIPAddress": "203.0.113.9",
            "userIdentity": {"type": "Root", "arn": "arn:aws:iam::123456789012:root",
                              "accountId": "123456789012"},
            "responseElements": {"ConsoleLogin": "Success"},
            "additionalEventData": {"MFAUsed": "No"},
        }))
        self.assertIsNotNone(event)
        self.assertEqual(event["class_uid"], 3002)
        self.assertEqual(event["activity_id"], 1)
        self.assertEqual(event["status"], "Success")
        self.assertEqual(event["unmapped"]["cloud"]["identity_type"], "Root")
        self.assertEqual(event["unmapped"]["cloud"]["mfa_used"], "No")
        self.assertEqual(validate(event), [])

    def test_failed_console_login(self):
        event = PARSER.parse(_raw({
            "eventTime": "2026-07-20T10:00:00Z", "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin", "userIdentity": {"type": "IAMUser"},
            "responseElements": {"ConsoleLogin": "Failure"},
        }))
        self.assertEqual(event["status"], "Failure")
        self.assertEqual(event["severity_id"], 4)  # SEV_HIGH

    def test_create_api_call_is_write(self):
        event = PARSER.parse(_raw({
            "eventTime": "2026-07-20T10:00:00Z", "eventSource": "ec2.amazonaws.com",
            "eventName": "CreateSecurityGroup", "userIdentity": {"type": "IAMUser", "arn": "u1"},
        }))
        self.assertEqual(event["class_uid"], 6003)
        self.assertEqual(event["activity_id"], 1)

    def test_delete_api_call_is_destroy_severity(self):
        event = PARSER.parse(_raw({
            "eventTime": "2026-07-20T10:00:00Z", "eventSource": "ec2.amazonaws.com",
            "eventName": "DeleteSecurityGroup", "userIdentity": {"type": "IAMUser", "arn": "u1"},
        }))
        self.assertEqual(event["activity_id"], 4)
        self.assertEqual(event["severity_id"], 5)  # SEV_CRITICAL

    def test_missing_event_name_returns_none(self):
        self.assertIsNone(PARSER.parse(_raw({"eventSource": "ec2.amazonaws.com"})))

    def test_content_sniff_routes_by_field_combo(self):
        parser = resolve({"source_type": "", "raw": {
            "eventName": "GetObject", "eventSource": "s3.amazonaws.com",
            "eventTime": "2026-07-20T10:00:00Z"}, "meta": {}})
        self.assertIs(type(parser), CloudTrailParser)


if __name__ == "__main__":
    unittest.main()
