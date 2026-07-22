"""Unit tests for the cef parser (v0.5 Track A4).

Run with:
    python services/ws2-normalization/parsers/test_cef.py
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
from parsers.cef import CefParser  # noqa: E402
from parsers import resolve  # noqa: E402

PARSER = CefParser()


def _raw(line, meta=None):
    return {"source_type": "cef", "raw": line, "meta": meta or {}}


class TestCefParser(unittest.TestCase):

    def test_auth_failure_line_is_authentication(self):
        line = ("CEF:0|Acme|Firewall|1.0|100|Auth failure|5|"
                "suser=admin src=203.0.113.5 spt=51000 outcome=failure")
        event = PARSER.parse(_raw(line))
        self.assertIsNotNone(event)
        self.assertEqual(event["class_uid"], 3002)
        self.assertEqual(event["activity_id"], 4)
        self.assertEqual(event["status"], "Failure")
        self.assertEqual(event["actor"]["user"]["name"], "admin")
        self.assertEqual(event["src_endpoint"]["ip"], "203.0.113.5")
        self.assertEqual(event["src_endpoint"]["port"], 51000)
        self.assertEqual(validate(event), [])

    def test_auth_success_line(self):
        line = "CEF:0|Acme|Firewall|1.0|101|Auth success|1|suser=jdoe outcome=success"
        event = PARSER.parse(_raw(line))
        self.assertEqual(event["activity_id"], 1)
        self.assertEqual(event["status"], "Success")

    def test_network_deny_line_is_network_activity(self):
        line = "CEF:0|Acme|Firewall|1.0|200|Traffic|3|src=10.0.0.5 dst=10.0.0.10 dpt=22 act=blocked"
        event = PARSER.parse(_raw(line))
        self.assertEqual(event["class_uid"], 4001)
        self.assertEqual(event["activity_id"], 6)
        self.assertEqual(event["dst_endpoint"]["ip"], "10.0.0.10")
        self.assertEqual(event["dst_endpoint"]["port"], 22)

    def test_network_accept_line(self):
        line = "CEF:0|Acme|Firewall|1.0|201|Traffic|1|src=10.0.0.5 dst=10.0.0.10 act=allowed"
        event = PARSER.parse(_raw(line))
        self.assertEqual(event["activity_id"], 7)

    def test_non_cef_line_returns_none(self):
        self.assertIsNone(PARSER.parse(_raw("not a cef line")))

    def test_malformed_short_header_returns_none(self):
        self.assertIsNone(PARSER.parse(_raw("CEF:0|Acme|Firewall")))

    def test_content_sniff_routes_cef_prefix(self):
        parser = resolve({"source_type": "", "raw":
                          "CEF:0|Acme|FW|1.0|1|Test|1|src=10.0.0.1", "meta": {}})
        self.assertIs(type(parser), CefParser)


if __name__ == "__main__":
    unittest.main()
