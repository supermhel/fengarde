"""Unit tests for the mail_gateway and m365_audit parsers (2026-10-14).

Fixtures are SPEC-DERIVED (gateway message-log fields common to the major
vendors; the Office 365 Management Activity API common schema), not captured
from a real gateway or tenant -- same discipline as test_cloudtrail.py.

Run with:
    python services/ws2-normalization/parsers/test_mail_m365.py
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
from parsers import resolve  # noqa: E402
from parsers.mail_gateway import MailGatewayParser  # noqa: E402
from parsers.m365_audit import M365AuditParser  # noqa: E402
import main as ws2  # noqa: E402

MAIL = MailGatewayParser()
M365 = M365AuditParser()
T0 = 1_751_500_000_000


def _mail(rec, meta=None):
    return {"source_type": "mail_gateway", "raw": rec, "meta": meta or {}}


def _m365(rec, meta=None):
    return {"source_type": "m365_audit", "raw": rec, "meta": meta or {}}


class TestMailGateway(unittest.TestCase):

    def test_macro_attachment_delivered(self):
        ev = MAIL.parse(_mail({"from": "Billing@Vendor-Update.example.invalid", "to": "m.rossi@corp.example",
                               "subject": "Updated remittance details", "attachment": "Invoice_4471.docm",
                               "verdict": "delivered", "ts": T0}, {"ip": "203.0.113.200"}))
        self.assertEqual((ev["class_uid"], ev["activity_id"], ev["type_uid"]), (4009, 2, 400902))
        self.assertEqual(ev["status"], "Success")
        self.assertEqual(ev["severity_id"], 3)                      # macro + delivered
        self.assertEqual(ev["email"]["from"], "billing@vendor-update.example.invalid")
        self.assertEqual(ev["email"]["to"], ["m.rossi@corp.example"])
        u = ev["unmapped"]["email"]
        self.assertTrue(u["has_macro_attachment"])
        self.assertEqual(u["sender_domain"], "vendor-update.example.invalid")
        self.assertEqual(u["attachments"][0]["extension"], "docm")
        self.assertEqual(ev["src_endpoint"]["ip"], "203.0.113.200")
        self.assertEqual(ev["time"], T0)
        self.assertEqual(validate(ev), [])

    def test_blocked_is_failure_and_low_severity(self):
        ev = MAIL.parse(_mail({"sender": "a@x.example", "recipients": ["b@y.example", "c@y.example"],
                               "attachments": [{"filename": "x.xlsm"}], "action": "Quarantined"}))
        self.assertEqual(ev["status"], "Failure")
        self.assertEqual(ev["severity_id"], 1)
        self.assertEqual(ev["email"]["to"], ["b@y.example", "c@y.example"])
        self.assertEqual(validate(ev), [])

    def test_outbound_is_send(self):
        ev = MAIL.parse(_mail({"from": "a@corp.example", "to": "b@x.example", "direction": "outbound"}))
        self.assertEqual(ev["activity_id"], 1)

    def test_not_a_message_record(self):
        for rec in ({}, {"from": "a@x.example"}, {"to": "b@x.example"}, "not json", 7, {"from": 1, "to": 2}):
            self.assertIsNone(MAIL.parse(_mail(rec)), rec)

    def test_hostile_fields_are_capped_and_never_evaluated(self):
        long = "A" * 5000
        ev = MAIL.parse(_mail({"from": long + "@x.example", "to": "b@x.example", "subject": long,
                               "attachments": [{"name": f"f{i}.docm"} for i in range(500)]}))
        self.assertLessEqual(len(ev["email"]["from"]), 512)
        self.assertLessEqual(len(ev["email"]["subject"]), 512)
        self.assertEqual(len(ev["unmapped"]["email"]["attachments"]), 32)

    def test_routed_by_source_type_only(self):
        self.assertIsInstance(resolve(_mail({"from": "a@x", "to": "b@x"})), MailGatewayParser)
        self.assertIsNone(resolve({"raw": {"from": "a@x.example", "to": "b@x.example"}, "meta": {}}))


class TestM365Audit(unittest.TestCase):

    def test_forwarding_inbox_rule(self):
        ev = M365.parse(_m365({"Operation": "New-InboxRule", "Workload": "Exchange",
                               "UserId": "m.rossi@corp.example", "ClientIP": "203.0.113.51:50432",
                               "CreationTime": "2025-07-03T00:08:20Z",
                               "Parameters": [{"Name": "ForwardTo", "Value": "ap-desk@vendor-update.example.invalid"},
                                              {"Name": "DeleteMessage", "Value": "True"},
                                              {"Name": "Name", "Value": "."}]}))
        self.assertEqual((ev["class_uid"], ev["activity_id"]), (6003, 1))
        self.assertEqual(ev["actor"]["user"]["name"], "m.rossi@corp.example")
        self.assertEqual(ev["src_endpoint"]["ip"], "203.0.113.51")
        rule = ev["unmapped"]["m365"]["inbox_rule"]
        self.assertEqual(rule["forward_to"], ["ap-desk@vendor-update.example.invalid"])
        self.assertTrue(rule["forwards_external"])
        self.assertTrue(rule["hides_mail"])
        self.assertEqual(validate(ev), [])

    def test_internal_forward_is_not_external(self):
        ev = M365.parse(_m365({"Operation": "Set-InboxRule", "Workload": "Exchange", "UserId": "a@corp.example",
                               "CreationTime": T0, "Parameters": {"RedirectTo": "smtp:B@CORP.EXAMPLE"}}))
        rule = ev["unmapped"]["m365"]["inbox_rule"]
        self.assertFalse(rule["forwards_external"])
        self.assertFalse(rule["hides_mail"])
        self.assertEqual(ev["activity_id"], 3)

    def test_unknown_own_domain_never_guesses_external(self):
        ev = M365.parse(_m365({"Operation": "New-InboxRule", "Workload": "Exchange", "UserId": "svc",
                               "CreationTime": T0, "Parameters": {"ForwardTo": "x@evil.example"}}))
        self.assertFalse(ev["unmapped"]["m365"]["inbox_rule"]["forwards_external"])

    def test_logins_map_to_authentication(self):
        ok = M365.parse(_m365({"Operation": "UserLoggedIn", "Workload": "AzureActiveDirectory",
                               "UserId": "a@corp.example", "ClientIP": "[2001:db8::1]:443", "CreationTime": T0}))
        bad = M365.parse(_m365({"Operation": "UserLoginFailed", "Workload": "AzureActiveDirectory",
                                "UserId": "a@corp.example", "CreationTime": T0}))
        self.assertEqual((ok["class_uid"], ok["activity_id"], ok["status"]), (3002, 1, "Success"))
        self.assertEqual(ok["src_endpoint"]["ip"], "2001:db8::1")
        self.assertEqual((bad["class_uid"], bad["activity_id"], bad["status"]), (3002, 4, "Failure"))
        self.assertEqual(validate(ok), [])
        self.assertEqual(validate(bad), [])

    def test_non_rule_operation_has_no_inbox_rule(self):
        ev = M365.parse(_m365({"Operation": "MailItemsAccessed", "Workload": "Exchange", "CreationTime": T0}))
        self.assertNotIn("inbox_rule", ev["unmapped"]["m365"])
        self.assertEqual(ev["activity_id"], 2)

    def test_rejects_non_records(self):
        for rec in ({}, {"Operation": ""}, {"Operation": 5}, "nope", [], None):
            self.assertIsNone(M365.parse(_m365(rec)), rec)

    def test_content_sniff(self):
        rec = {"Operation": "UserLoggedIn", "Workload": "AzureActiveDirectory", "CreationTime": T0}
        self.assertIsInstance(resolve({"raw": rec, "meta": {}}), M365AuditParser)


class TestClockSkewStamp(unittest.TestCase):
    """F4 (owner decision 2026-10-14, flag only): WS-2 stamps siem.clock_skew_ms."""

    def _norm(self, record_ts, received_at):
        payload = _m365({"Operation": "UserLoggedIn", "Workload": "AzureActiveDirectory",
                         "UserId": "a@corp.example", "CreationTime": record_ts},
                        {"received_at": received_at, "ingest_id": "skew-1"})
        ev, errors = ws2.normalize_one(payload)
        self.assertEqual(errors, [])
        return ev

    def test_far_record_clock_is_stamped(self):
        ev = self._norm(T0 - 3_600_000, T0)
        self.assertEqual(ev["siem"]["clock_skew_ms"], -3_600_000)
        self.assertEqual(ev["time"], T0 - 3_600_000)          # flag only: time unchanged

    def test_within_tolerance_is_not_stamped(self):
        self.assertNotIn("clock_skew_ms", self._norm(T0 - 299_000, T0)["siem"])

    def test_no_receipt_time_is_not_stamped(self):
        payload = _m365({"Operation": "UserLoggedIn", "Workload": "AzureActiveDirectory", "CreationTime": T0})
        ev, _ = ws2.normalize_one(payload)
        self.assertNotIn("clock_skew_ms", ev["siem"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
