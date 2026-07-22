"""Unit tests for the sysmon parser (P0-3, 2026-07-21 audit fix plan).

Run with:
    python services/ws2-normalization/parsers/test_sysmon.py
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
from parsers.sysmon import SysmonParser  # noqa: E402
from parsers import resolve  # noqa: E402

PARSER = SysmonParser()


def _raw(rec, meta=None):
    return {"source_type": "sysmon", "raw": rec, "meta": meta or {}}


REC_PROCESS = {
    "EventID": 1, "TimeCreated": 1750000000000, "Computer": "wks-jdoe",
    "Image": r"C:\Windows\System32\cmd.exe", "CommandLine": "cmd /c whoami",
    "ProcessId": "1234", "ParentImage": r"C:\Windows\explorer.exe",
    "ParentProcessId": "800", "User": "CORP\\jdoe",
    "Hashes": "SHA256=ABCDEF0123456789",
}

REC_NETWORK = {
    "EventID": 3, "TimeCreated": 1750000001000, "Computer": "wks-jdoe",
    "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "User": "CORP\\jdoe",
    "SourceIp": "10.0.1.15", "SourcePort": "51000", "SourceHostname": "wks-jdoe",
    "DestinationIp": "203.0.113.9", "DestinationPort": "443",
    "DestinationHostname": "evil.example",
}

REC_FILE = {
    "EventID": 11, "TimeCreated": 1750000002000, "Computer": "wks-jdoe",
    "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "TargetFilename": r"C:\Users\jdoe\AppData\Local\Temp\payload.exe",
    "User": "CORP\\jdoe",
}


class TestSysmonParser(unittest.TestCase):

    def test_process_create_maps_to_kernel_process(self):
        event = PARSER.parse(_raw(REC_PROCESS))
        self.assertIsNotNone(event)
        self.assertEqual(event["class_uid"], 1002)
        self.assertEqual(event["activity_id"], 1)
        self.assertEqual(event["type_uid"], 100201)
        self.assertEqual(event["actor"]["user"]["name"], "CORP\\jdoe")
        self.assertEqual(event["actor"]["process"]["name"], r"C:\Windows\System32\cmd.exe")
        self.assertEqual(event["actor"]["process"]["pid"], 1234)
        self.assertEqual(event["src_endpoint"]["hostname"], "wks-jdoe")
        self.assertEqual(validate(event), [])

    def test_network_connect_maps_to_network_activity_with_src_dst(self):
        event = PARSER.parse(_raw(REC_NETWORK))
        self.assertIsNotNone(event)
        self.assertEqual(event["class_uid"], 4001)
        self.assertEqual(event["activity_id"], 7)  # Accept, per ocsf-classes.md
        self.assertEqual(event["src_endpoint"]["ip"], "10.0.1.15")
        self.assertEqual(event["src_endpoint"]["port"], 51000)
        self.assertEqual(event["src_endpoint"]["hostname"], "wks-jdoe")
        self.assertEqual(event["dst_endpoint"]["ip"], "203.0.113.9")
        self.assertEqual(event["dst_endpoint"]["port"], 443)
        self.assertEqual(event["dst_endpoint"]["hostname"], "evil.example")
        self.assertEqual(validate(event), [])

    def test_file_create_maps_to_file_system_activity_first_producer(self):
        """P0-3's headline fix: class 1001 had ZERO producers before this
        parser (contracts/detection-coverage.md's documented gap)."""
        event = PARSER.parse(_raw(REC_FILE))
        self.assertIsNotNone(event)
        self.assertEqual(event["class_uid"], 1001)
        self.assertEqual(event["activity_id"], 1)
        self.assertEqual(event["unmapped"]["target_filename"],
                         r"C:\Users\jdoe\AppData\Local\Temp\payload.exe")
        self.assertEqual(validate(event), [])

    def test_unmapped_event_id_returns_none(self):
        """EventID 13 (RegistryValueSet) is deliberately unmapped -- no clean
        OCSF class fit in the restricted profile (see module docstring)."""
        self.assertIsNone(PARSER.parse(_raw({"EventID": 13, "TimeCreated": 1})))
        self.assertIsNone(PARSER.parse(_raw({"EventID": 9999})))

    def test_malformed_input_never_raises(self):
        self.assertIsNone(PARSER.parse({"source_type": "sysmon", "raw": "not json{"}))
        self.assertIsNone(PARSER.parse({"source_type": "sysmon", "raw": 12345}))
        self.assertIsNone(PARSER.parse({"source_type": "sysmon", "raw": {"EventID": "abc"}}))

    def test_out_of_range_port_dropped_not_crashed(self):
        rec = dict(REC_NETWORK, SourcePort="999999")
        event = PARSER.parse(_raw(rec))
        self.assertIsNotNone(event)
        self.assertNotIn("port", event["src_endpoint"])
        self.assertEqual(validate(event), [])

    def test_content_sniff_routes_sysmon_eventids_without_explicit_source_type(self):
        """P0-3: the registry's content-sniff discriminator must route
        EventID 1/3/11 to sysmon, not fall through to windows_eventlog's
        catch-all (which doesn't know these IDs and would silently drop
        the event)."""
        for eid, rec in ((1, REC_PROCESS), (3, REC_NETWORK), (11, REC_FILE)):
            parser = resolve({"raw": rec})  # no source_type set
            self.assertIsInstance(parser, SysmonParser,
                                  f"EventID {eid} must content-sniff to SysmonParser")


if __name__ == "__main__":
    unittest.main()
