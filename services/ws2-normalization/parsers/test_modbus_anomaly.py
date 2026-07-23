"""Unit tests for the modbus_anomaly parser (v0.5 M7 Track X, 2026-07-22).

Fixtures here are PROTOCOL-SPEC-DERIVED (Modbus Application Protocol
V1.1b3's public function-code table), not captured from a live PLC -- this
parser has no vendor audit-log format to capture from in the first place;
see the module docstring in modbus_anomaly.py for the scope boundary this
labeling protects.

Run with:
    python services/ws2-normalization/parsers/test_modbus_anomaly.py
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
from parsers.modbus_anomaly import ModbusAnomalyParser  # noqa: E402
from parsers import resolve  # noqa: E402

PARSER = ModbusAnomalyParser()


def _raw(rec, meta=None):
    return {"source_type": "modbus_anomaly", "raw": rec, "meta": meta or {}}


class TestModbusAnomalyParser(unittest.TestCase):

    def test_normal_read_is_not_anomalous(self):
        event = PARSER.parse(_raw({
            "unitId": 1, "functionCode": 3, "address": 40001,
            "sourceIp": "10.20.0.50", "destIp": "10.20.0.5", "time": 1751500000000,
        }))
        self.assertIsNotNone(event)
        self.assertEqual(event["class_uid"], 4001)
        self.assertEqual(event["activity_id"], 6)
        self.assertIsNone(event["unmapped"]["ot"]["anomaly_type"])
        self.assertEqual(event["severity_id"], 1)  # SEV_INFO
        self.assertEqual(validate(event), [])

    def test_write_inside_expected_range_is_not_anomalous(self):
        event = PARSER.parse(_raw({
            "unitId": 1, "functionCode": 6, "address": 40005,
            "sourceIp": "10.20.0.50", "destIp": "10.20.0.5",
        }))
        self.assertIsNone(event["unmapped"]["ot"]["anomaly_type"])

    def test_write_outside_expected_range_is_unauthorized_write(self):
        event = PARSER.parse(_raw({
            "unitId": 1, "functionCode": 6, "address": 41999,
            "sourceIp": "10.20.0.99", "destIp": "10.20.0.5",
        }))
        self.assertEqual(event["unmapped"]["ot"]["anomaly_type"], "unauthorized_write")
        self.assertEqual(event["severity_id"], 4)  # SEV_HIGH
        self.assertEqual(validate(event), [])

    def test_write_multiple_coils_with_no_address_is_unauthorized_write(self):
        # A write function code with a missing/unparseable address can't be
        # proven safe -- fail toward flagging, same discipline as every
        # other "can't judge -> don't pass it" guard in this codebase.
        event = PARSER.parse(_raw({"unitId": 1, "functionCode": 15}))
        self.assertEqual(event["unmapped"]["ot"]["anomaly_type"], "unauthorized_write")

    def test_exception_response_is_flagged(self):
        # function code 3 (Read Holding Registers) with the exception bit set.
        event = PARSER.parse(_raw({"unitId": 1, "functionCode": 3 | 0x80, "address": 1}))
        self.assertEqual(event["unmapped"]["ot"]["anomaly_type"], "exception_response")
        self.assertEqual(event["severity_id"], 3)  # SEV_MEDIUM

    def test_unknown_function_code_is_flagged(self):
        event = PARSER.parse(_raw({"unitId": 1, "functionCode": 99}))
        self.assertEqual(event["unmapped"]["ot"]["anomaly_type"], "unknown_function_code")

    def test_vendor_specific_function_code_is_not_flagged_unknown(self):
        # 65-72 and 100-110 are the spec's own reserved vendor-specific
        # bands -- a generic tap genuinely cannot judge these, so they must
        # NOT be miscategorized as "unknown" (a false claim of protocol
        # violation the spec itself doesn't support).
        event = PARSER.parse(_raw({"unitId": 1, "functionCode": 68}))
        self.assertIsNone(event["unmapped"]["ot"]["anomaly_type"])

    def test_missing_function_code_returns_none(self):
        self.assertIsNone(PARSER.parse(_raw({"unitId": 1, "address": 1})))

    def test_non_dict_raw_returns_none(self):
        self.assertIsNone(PARSER.parse(_raw("not a dict")))

    def test_content_sniff_routes_to_modbus_parser(self):
        payload = {"raw": {"unitId": 1, "functionCode": 6, "address": 41999}}
        parser = resolve(payload)
        self.assertIsNotNone(parser)
        self.assertEqual(parser.SOURCE_TYPE, "modbus_anomaly")


if __name__ == "__main__":
    unittest.main()
