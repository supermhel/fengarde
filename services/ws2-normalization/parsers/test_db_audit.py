"""Unit tests for the db_audit parser.

Run with:
    C:/Python313/python.exe services/ws2-normalization/parsers/test_db_audit.py
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
from parsers.db_audit import DbAuditParser  # noqa: E402

PARSER = DbAuditParser()


def _raw(rec, meta=None):
    return {"source_type": "db_audit", "raw": rec, "meta": meta or {}}


class TestDbAuditParser(unittest.TestCase):

    def test_grant_is_privileged_op(self):
        """This is the exact case bank_db_priv_esc.yml needs: class 6005,
        activity_id 5, sector bank."""
        event = PARSER.parse(_raw({
            "operation": "GRANT", "object": "customers", "user": "dba_svc",
            "host": "db-prod-01", "ipAddress": "10.4.4.9", "timestamp": 1750000100000,
        }))
        self.assertIsNotNone(event)
        self.assertEqual(event["class_uid"], 6005)
        self.assertEqual(event["activity_id"], 5)
        self.assertEqual(event["type_uid"], 600505)
        self.assertEqual(event["siem"]["sector"], "bank")
        self.assertEqual(event["actor"]["user"]["name"], "dba_svc")
        self.assertEqual(event["dst_endpoint"]["hostname"], "db-prod-01")
        self.assertEqual(validate(event), [])

    def test_select_is_query(self):
        event = PARSER.parse(_raw({"operation": "SELECT", "user": "reporting_svc"}))
        self.assertEqual(event["activity_id"], 1)
        self.assertEqual(validate(event), [])

    def test_revoke_and_alter_also_privileged(self):
        for op in ("REVOKE", "ALTER TABLE"):
            with self.subTest(op=op):
                event = PARSER.parse(_raw({"operation": op, "user": "x"}))
                self.assertEqual(event["activity_id"], 5)

    def test_sector_override(self):
        event = PARSER.parse(_raw({"operation": "GRANT", "user": "x"},
                                  {"sector": "datacenter"}))
        self.assertEqual(event["siem"]["sector"], "datacenter")

    def test_malformed_input_returns_none(self):
        self.assertIsNone(PARSER.parse(_raw("not json")))
        self.assertIsNone(PARSER.parse(_raw(None)))
        self.assertIsNone(PARSER.parse({}))

    def test_json_string_raw_parses(self):
        import json
        event = PARSER.parse(_raw(json.dumps({"operation": "GRANT", "user": "x"})))
        self.assertIsNotNone(event)
        self.assertEqual(event["activity_id"], 5)

    def test_type_uid_invariant(self):
        for op in ("SELECT", "INSERT", "UPDATE", "DELETE", "GRANT"):
            with self.subTest(op=op):
                event = PARSER.parse(_raw({"operation": op, "user": "x"}))
                self.assertEqual(event["type_uid"],
                                event["class_uid"] * 100 + event["activity_id"])
                self.assertEqual(validate(event), [])

    def test_wrong_typed_ip_and_user_dropped_not_crashed(self):
        """Regression for a Hypothesis property-testing finding (M1): a
        structured record's ipAddress/host/user fields can be any JSON type,
        not just str. A wrong-typed value must be dropped (field omitted),
        never assigned raw -- that used to emit a schema-invalid OCSF event
        (`.src_endpoint.ip: expected string, got int`)."""
        event = PARSER.parse(_raw({
            "operation": "SELECT", "ipAddress": 12345, "host": ["not", "a", "string"],
            "user": {"nested": "dict"},
        }))
        self.assertIsNotNone(event)
        self.assertEqual(validate(event), [])
        self.assertNotIn("src_endpoint", event)
        self.assertNotIn("dst_endpoint", event)
        self.assertNotIn("actor", event)


if __name__ == "__main__":
    unittest.main(verbosity=2)
