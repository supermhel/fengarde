"""Unit tests for the inventory_diff parser (M7 Track Y, 2026-08-05).

Covers the edge-rejection paths in particular: this parser's input is the
inventory worker's JSON notification, so every field is unguarded external
input. A malformed value that passes the parser does not fail loudly -- it
produces an event that fails Contract A validation downstream and
dead-letters, which is a much harder failure to trace back to here.

Run with:
    python services/ws2-normalization/parsers/test_inventory_diff.py
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
from parsers.inventory_diff import InventoryDiffParser  # noqa: E402
from parsers import resolve  # noqa: E402

PARSER = InventoryDiffParser()

_OT_DEVICE = {
    "mac": "AA:BB:CC:DD:EE:FF",
    "ip": "10.20.0.77",
    "hostname": "plc-line4",
    "device_type": "plc",
    "sector": "ot",
    "seen_at": 1751500000000,
}


def _raw(rec, meta=None):
    return {"source_type": "inventory_diff", "raw": rec, "meta": meta or {}}


class TestInventoryDiffParser(unittest.TestCase):

    def test_ot_device_produces_valid_ocsf_event(self):
        event = PARSER.parse(_raw(_OT_DEVICE))
        self.assertIsNotNone(event)
        self.assertEqual(validate(event), [])
        self.assertEqual(event["class_uid"], 4001)
        self.assertEqual(event["activity_id"], 1)
        self.assertEqual(event["type_uid"], 4001 * 100 + 1)
        self.assertEqual(event["src_endpoint"]["mac"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(event["src_endpoint"]["ip"], "10.20.0.77")
        self.assertEqual(event["unmapped"]["ot"]["sector"], "ot")

    def test_ot_sector_raises_severity(self):
        event = PARSER.parse(_raw(_OT_DEVICE))
        self.assertEqual(event["severity_id"], 4)

    def test_non_ot_sector_stays_informational(self):
        rec = {**_OT_DEVICE, "sector": "datacenter"}
        event = PARSER.parse(_raw(rec))
        self.assertNotEqual(event["severity_id"], 4)

    # --- edge rejection -------------------------------------------------
    def test_malformed_mac_is_rejected_at_the_edge(self):
        # Would otherwise be written straight into src_endpoint.mac and fail
        # Contract A's MAC pattern downstream.
        self.assertIsNone(PARSER.parse(_raw({**_OT_DEVICE, "mac": "not-a-mac"})))

    def test_non_string_mac_is_rejected(self):
        self.assertIsNone(PARSER.parse(_raw({**_OT_DEVICE, "mac": 12345})))

    def test_missing_mac_is_rejected(self):
        rec = {k: v for k, v in _OT_DEVICE.items() if k != "mac"}
        self.assertIsNone(PARSER.parse(_raw(rec)))

    def test_malformed_ip_is_rejected(self):
        self.assertIsNone(PARSER.parse(_raw({**_OT_DEVICE, "ip": "999.1.1.1"})))

    def test_missing_ip_is_rejected(self):
        rec = {k: v for k, v in _OT_DEVICE.items() if k != "ip"}
        self.assertIsNone(PARSER.parse(_raw(rec)))

    def test_non_dict_raw_returns_none(self):
        self.assertIsNone(PARSER.parse(_raw("not a dict")))

    # --- tenancy ---------------------------------------------------------
    def test_tenant_id_from_meta_is_propagated(self):
        event = PARSER.parse(_raw(_OT_DEVICE, {"tenant_id": "acme"}))
        self.assertEqual(event["siem"]["tenant"], "acme")

    def test_missing_tenant_falls_back_to_default(self):
        event = PARSER.parse(_raw(_OT_DEVICE))
        self.assertTrue(event["siem"]["tenant"])

    def test_content_sniff_routes_to_inventory_diff_parser(self):
        parser = resolve({"raw": _OT_DEVICE})
        self.assertIsNotNone(parser)
        self.assertEqual(parser.SOURCE_TYPE, "inventory_diff")


if __name__ == "__main__":
    unittest.main()
