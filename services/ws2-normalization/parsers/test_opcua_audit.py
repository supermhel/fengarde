"""Unit tests for the opcua_audit parser (v0.4 Track P2).

Fixtures here are SPEC-DERIVED from OPC UA Part 5's audit-event field
definitions, not captured from a live server -- labeled per the honest-
status convention (see the module docstring in opcua_audit.py).

Run with:
    python services/ws2-normalization/parsers/test_opcua_audit.py
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
from parsers.opcua_audit import OpcUaAuditParser  # noqa: E402
from parsers import resolve  # noqa: E402

PARSER = OpcUaAuditParser()


def _raw(rec, meta=None):
    return {"source_type": "opcua_audit", "raw": rec, "meta": meta or {}}


class TestOpcUaAuditParser(unittest.TestCase):

    def test_session_create_is_authentication_logon(self):
        event = PARSER.parse(_raw({
            "eventType": "AuditCreateSessionEventType", "clientUserId": "engineer01",
            "clientAddress": "10.20.0.15", "serverId": "plc-line3",
            "status": True, "time": 1751500000000,
        }))
        self.assertIsNotNone(event)
        self.assertEqual(event["class_uid"], 3002)
        self.assertEqual(event["activity_id"], 1)
        self.assertEqual(event["status"], "Success")
        self.assertEqual(event["actor"]["user"]["name"], "engineer01")
        self.assertEqual(validate(event), [])

    def test_session_close_is_logoff(self):
        event = PARSER.parse(_raw({"eventType": "AuditCloseSessionEventType",
                                    "clientUserId": "engineer01"}))
        self.assertEqual(event["activity_id"], 2)

    def test_failed_session_is_high_severity_failure(self):
        event = PARSER.parse(_raw({"eventType": "AuditActivateSessionEventType",
                                    "clientUserId": "attacker", "status": False}))
        self.assertEqual(event["status"], "Failure")
        self.assertEqual(event["severity_id"], 4)  # SEV_HIGH

    def test_certificate_event_is_authentication(self):
        event = PARSER.parse(_raw({"eventType": "AuditCertificateInvalidEventType",
                                    "clientUserId": "unknown", "status": False}))
        self.assertEqual(event["class_uid"], 3002)
        self.assertEqual(event["status"], "Failure")

    def test_write_event_is_api_activity_update(self):
        event = PARSER.parse(_raw({
            "eventType": "AuditWriteUpdateEventType", "clientUserId": "engineer01",
            "clientAddress": "10.20.0.15", "serverId": "plc-line3",
            "nodeId": "ns=2;s=Line3.SetpointTemp", "status": True,
        }))
        self.assertEqual(event["class_uid"], 6003)
        self.assertEqual(event["activity_id"], 3)
        self.assertTrue(event["unmapped"]["ot"]["is_config_node"])
        self.assertEqual(event["unmapped"]["ot"]["device_type"], "plc")
        self.assertEqual(validate(event), [])

    def test_write_event_non_config_node_lower_severity(self):
        event = PARSER.parse(_raw({
            "eventType": "AuditWriteUpdateEventType", "clientUserId": "op1",
            "nodeId": "ns=2;s=Line3.HeartbeatCounter", "status": True,
        }))
        self.assertFalse(event["unmapped"]["ot"]["is_config_node"])
        self.assertEqual(event["severity_id"], 3)  # SEV_MEDIUM

    def test_method_call_is_api_activity_create(self):
        event = PARSER.parse(_raw({
            "eventType": "AuditUpdateMethodEventType", "clientUserId": "engineer01",
            "nodeId": "ns=2;s=Line3.ResetAlarm", "status": True,
        }))
        self.assertEqual(event["class_uid"], 6003)
        self.assertEqual(event["activity_id"], 1)

    def test_unknown_event_type_returns_none(self):
        self.assertIsNone(PARSER.parse(_raw({"eventType": "SomeOtherEventType"})))

    def test_missing_event_type_returns_none(self):
        self.assertIsNone(PARSER.parse(_raw({"clientUserId": "x"})))

    def test_malformed_input_returns_none(self):
        self.assertIsNone(PARSER.parse(_raw("not json")))
        self.assertIsNone(PARSER.parse(_raw(None)))
        self.assertIsNone(PARSER.parse({}))

    def test_json_string_raw_parses(self):
        import json
        event = PARSER.parse(_raw(json.dumps({
            "eventType": "AuditCreateSessionEventType", "clientUserId": "x"})))
        self.assertIsNotNone(event)

    def test_content_sniff_resolves_to_opcua_audit(self):
        payload = {"source_type": "unknown",
                   "raw": {"eventType": "AuditWriteUpdateEventType",
                           "nodeId": "ns=2;s=X", "clientUserId": "x"}}
        self.assertIsInstance(resolve(payload), OpcUaAuditParser)

    def test_type_uid_invariant(self):
        for rec in (
            {"eventType": "AuditCreateSessionEventType", "clientUserId": "x"},
            {"eventType": "AuditWriteUpdateEventType", "nodeId": "ns=2;s=X", "clientUserId": "x"},
            {"eventType": "AuditUpdateMethodEventType", "nodeId": "ns=2;s=X", "clientUserId": "x"},
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
        event = PARSER.parse(_raw({
            "eventType": "AuditCreateSessionEventType",
            "clientAddress": 12345, "clientUserId": {"bad": "type"},
        }))
        self.assertIsNotNone(event)
        self.assertEqual(validate(event), [])
        self.assertNotIn("src_endpoint", event)
        self.assertNotIn("actor", event)


if __name__ == "__main__":
    unittest.main(verbosity=2)
