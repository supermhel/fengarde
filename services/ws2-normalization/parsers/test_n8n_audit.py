"""Unit tests for the n8n_audit parser (v0.4 Track P3).

Run with:
    python services/ws2-normalization/parsers/test_n8n_audit.py
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
from parsers.n8n_audit import N8nAuditParser  # noqa: E402
from parsers import resolve  # noqa: E402

PARSER = N8nAuditParser()


def _raw(rec, meta=None):
    return {"source_type": "n8n_audit", "raw": rec, "meta": meta or {}}


class TestN8nAuditParser(unittest.TestCase):

    def test_webhook_created_is_api_activity(self):
        event = PARSER.parse(_raw({
            "eventType": "webhook.created", "user": "alice", "ip": "203.0.113.9",
            "workflowId": "wf-42", "path": "/webhook/incoming-order",
            "ts": 1751500000000,
        }))
        self.assertIsNotNone(event)
        self.assertEqual(event["class_uid"], 6003)
        self.assertEqual(event["activity_id"], 1)
        self.assertEqual(event["actor"]["user"]["name"], "alice")
        self.assertEqual(event["unmapped"]["n8n"]["webhook_path"], "/webhook/incoming-order")
        self.assertEqual(validate(event), [])

    def test_workflow_modified_is_update(self):
        event = PARSER.parse(_raw({"eventType": "workflow.updated", "user": "bob",
                                    "workflowId": "wf-7"}))
        self.assertEqual(event["activity_id"], 3)

    def test_credentials_accessed_is_high_severity(self):
        event = PARSER.parse(_raw({"eventType": "credentials.accessed", "user": "bob"}))
        self.assertEqual(event["severity_id"], 4)  # SEV_HIGH

    def test_login_is_authentication(self):
        event = PARSER.parse(_raw({"eventType": "user.login", "user": "alice",
                                    "ip": "10.0.0.5"}))
        self.assertEqual(event["class_uid"], 3002)
        self.assertEqual(event["activity_id"], 1)

    def test_logout_is_authentication_logoff(self):
        event = PARSER.parse(_raw({"eventType": "user.logout", "user": "alice"}))
        self.assertEqual(event["activity_id"], 2)

    def test_missing_event_type_returns_none(self):
        self.assertIsNone(PARSER.parse(_raw({"user": "alice"})))

    def test_malformed_input_returns_none(self):
        self.assertIsNone(PARSER.parse(_raw("not json")))
        self.assertIsNone(PARSER.parse(_raw(None)))
        self.assertIsNone(PARSER.parse({}))

    def test_json_string_raw_parses(self):
        import json
        event = PARSER.parse(_raw(json.dumps({"eventType": "workflow.created", "user": "x"})))
        self.assertIsNotNone(event)

    def test_content_sniff_resolves_to_n8n_audit(self):
        payload = {"source_type": "unknown",
                   "raw": {"eventType": "webhook.created", "workflowId": "wf-1"}}
        self.assertIsInstance(resolve(payload), N8nAuditParser)

    def test_type_uid_invariant(self):
        for rec in (
            {"eventType": "workflow.created", "user": "x"},
            {"eventType": "webhook.created", "user": "x"},
            {"eventType": "user.login", "user": "x"},
        ):
            with self.subTest(rec=rec):
                event = PARSER.parse(_raw(rec))
                self.assertEqual(event["type_uid"],
                                event["class_uid"] * 100 + event["activity_id"])
                self.assertEqual(validate(event), [])

    def test_wrong_typed_ip_and_user_dropped_not_crashed(self):
        """Regression for a Hypothesis property-testing finding (M1): see
        test_db_audit.py's identical regression for the shared root cause
        (services/shared/ocsf.py::valid_ip/safe_str)."""
        event = PARSER.parse(_raw({"eventType": "user.login", "ip": 12345, "user": [1, 2]}))
        self.assertIsNotNone(event)
        self.assertEqual(validate(event), [])
        self.assertNotIn("src_endpoint", event)
        self.assertNotIn("actor", event)


if __name__ == "__main__":
    unittest.main(verbosity=2)
