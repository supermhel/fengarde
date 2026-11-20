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

REC_TERMINATE = {
    "EventID": 5, "TimeCreated": 1750000003000, "Computer": "wks-jdoe",
    "Image": r"C:\Windows\System32\cmd.exe", "ProcessId": "1234",
    "User": "CORP\\jdoe",
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

    def test_process_terminate_maps_to_kernel_process_distinct_activity(self):
        """Added 2026-09-10: EventID 5 is a clean sibling of EventID 1 under
        the SAME class (1002) -- must get its OWN activity_id, not collide
        with Launch (1) or windows_eventlog's Priv-use (2)."""
        event = PARSER.parse(_raw(REC_TERMINATE))
        self.assertIsNotNone(event)
        self.assertEqual(event["class_uid"], 1002)
        self.assertEqual(event["activity_id"], 3)
        self.assertNotEqual(event["activity_id"], 1)  # not Launch
        self.assertNotEqual(event["activity_id"], 2)  # not windows_eventlog's Priv-use
        self.assertEqual(event["type_uid"], 100203)
        self.assertEqual(event["actor"]["process"]["name"], r"C:\Windows\System32\cmd.exe")
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
        """Deliberately unmapped -- no clean OCSF class fit in the restricted
        profile (see module docstring's full accounting, updated 2026-09-10):
        7 ImageLoad, 8 CreateRemoteThread, 12/13/14 Registry*, 18 PipeConnected.
        (10 ProcessAccess was mapped to class 1002/activity 5 on 2026-10-20 for the lsass rule;
        see test_recall_events.py.)"""
        for eid in (7, 8, 12, 13, 14, 18, 9999):
            self.assertIsNone(PARSER.parse(_raw({"EventID": eid, "TimeCreated": 1})),
                              f"EventID {eid} must stay an honest gap, not a forced mapping")

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
        for eid, rec in ((1, REC_PROCESS), (3, REC_NETWORK), (5, REC_TERMINATE), (11, REC_FILE)):
            parser = resolve({"raw": rec})  # no source_type set
            self.assertIsInstance(parser, SysmonParser,
                                  f"EventID {eid} must content-sniff to SysmonParser")


# --- ADR-012 WP 3: causal process keys -------------------------------------------------------------------------
# FIXTURE PROVENANCE: TEMPLATE-DERIVED. The GUIDs below are INVENTED to match the documented Sysmon
# ProcessGuid / ParentProcessGuid shape ("{8-4-4-4-12}" hex). They are NOT from a real capture; whether real
# Sysmon output reaches the parser with these field names is UNVERIFIED until the owner's lab capture (ADR-012 WP 1).
_G_CHILD = "{AAAAAAAA-1111-2222-3333-444444444444}"
_G_PARENT = "{BBBBBBBB-5555-6666-7777-888888888888}"
_NULL = "{00000000-0000-0000-0000-000000000000}"
_CHILD = "aaaaaaaa-1111-2222-3333-444444444444"
_PARENT = "bbbbbbbb-5555-6666-7777-888888888888"


class TestSysmonCausalKeys(unittest.TestCase):

    def test_eid1_process_and_parent_keys_canonicalised(self):
        rec = dict(REC_PROCESS, ProcessGuid=_G_CHILD, ParentProcessGuid=_G_PARENT)
        ev = PARSER.parse(_raw(rec))
        proc = ev["actor"]["process"]
        self.assertEqual(proc["uid"], _CHILD)
        self.assertEqual(proc["parent_process"],
                         {"uid": _PARENT, "pid": 800, "name": r"C:\Windows\explorer.exe"})
        self.assertEqual(ev["siem"]["key_scope"], {"host": "wks-jdoe", "sensor": "sysmon"})
        self.assertNotIn("boot", ev["siem"]["key_scope"])
        self.assertEqual(validate(ev), [])

    def test_eid1_without_guids_has_no_uid_or_scope_but_keeps_parent_pid_name(self):
        ev = PARSER.parse(_raw(REC_PROCESS))
        self.assertNotIn("uid", ev["actor"]["process"])
        self.assertNotIn("key_scope", ev["siem"])
        self.assertEqual(ev["actor"]["process"]["parent_process"]["pid"], 800)
        self.assertNotIn("uid", ev["actor"]["process"]["parent_process"])
        self.assertEqual(validate(ev), [])

    def test_eid3_eid5_eid11_carry_process_uid(self):
        for rec in (REC_NETWORK, REC_TERMINATE, REC_FILE):
            ev = PARSER.parse(_raw(dict(rec, ProcessGuid=_G_CHILD)))
            self.assertEqual(ev["actor"]["process"]["uid"], _CHILD, rec["EventID"])
            self.assertNotIn("parent_process", ev["actor"]["process"])
            self.assertEqual(ev["siem"]["key_scope"]["host"], "wks-jdoe")
            self.assertEqual(validate(ev), [])

    def test_eid10_uses_source_guid_not_target(self):
        rec = {"EventID": 10, "TimeCreated": 1750000005000, "Computer": "wks-jdoe",
               "SourceImage": r"C:\Users\Public\x.exe", "SourceProcessId": "4242",
               "SourceProcessGUID": _G_CHILD, "TargetProcessGUID": _G_PARENT,
               "TargetImage": r"C:\Windows\System32\lsass.exe", "GrantedAccess": "0x1010"}
        ev = PARSER.parse(_raw(rec))
        self.assertEqual(ev["actor"]["process"]["uid"], _CHILD)
        self.assertEqual(ev["actor"]["process"]["pid"], 4242)
        self.assertEqual(validate(ev), [])
        rec2 = {k: v for k, v in rec.items() if k != "SourceProcessGUID"}
        ev2 = PARSER.parse(_raw(rec2))
        self.assertNotIn("uid", ev2["actor"]["process"])   # a target GUID must never become the actor's key
        self.assertNotIn("key_scope", ev2["siem"])

    def test_negative_values_dropped(self):
        bad = (_NULL, "00000000-0000-0000-0000-000000000000", "-", "0x0", "", "  ", None, 0, 12345,
               "not-a-guid", "{AAAAAAAA-1111-2222-3333-44444444444}", "A" * 129,
               ("{" + "a" * 200 + "}"))
        for v in bad:
            rec = dict(REC_PROCESS, ProcessGuid=v, ParentProcessGuid=v)
            ev = PARSER.parse(_raw(rec))
            self.assertIsNotNone(ev, repr(v))
            self.assertNotIn("uid", ev["actor"]["process"], repr(v))
            self.assertNotIn("uid", ev["actor"]["process"].get("parent_process", {}), repr(v))
            self.assertNotIn("key_scope", ev["siem"], repr(v))
            self.assertEqual(validate(ev), [], repr(v))

    def test_one_bad_guid_does_not_drop_the_other(self):
        ev = PARSER.parse(_raw(dict(REC_PROCESS, ProcessGuid=_G_CHILD, ParentProcessGuid=_NULL)))
        self.assertEqual(ev["actor"]["process"]["uid"], _CHILD)
        self.assertNotIn("uid", ev["actor"]["process"]["parent_process"])

    def test_no_host_means_no_keys(self):
        rec = {k: v for k, v in REC_PROCESS.items() if k != "Computer"}
        ev = PARSER.parse(_raw(dict(rec, ProcessGuid=_G_CHILD, ParentProcessGuid=_G_PARENT)))
        self.assertNotIn("uid", ev["actor"]["process"])
        self.assertNotIn("uid", ev["actor"]["process"]["parent_process"])
        self.assertNotIn("key_scope", ev["siem"])
        self.assertEqual(validate(ev), [])

    def test_type_uid_still_derived(self):
        ev = PARSER.parse(_raw(dict(REC_PROCESS, ProcessGuid=_G_CHILD)))
        self.assertEqual(ev["type_uid"], ev["class_uid"] * 100 + ev["activity_id"])


if __name__ == "__main__":
    unittest.main()
