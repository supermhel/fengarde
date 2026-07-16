"""Unit tests for the generic_syslog parser.

Run with:
    C:/Python313/python.exe services/ws2-normalization/parsers/test_generic_syslog.py
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

# Make shared/ and parsers/ importable when running this file directly.
HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent.parent   # services/
ROOT = SERVICES.parent          # repo root

sys.path.insert(0, str(HERE.parent))   # ws2-normalization/ (so `parsers` pkg works)
sys.path.insert(0, str(SERVICES))       # services/ (so `shared` works)

from shared.ocsf import validate  # noqa: E402
from parsers.generic_syslog import GenericSyslogParser  # noqa: E402

PARSER = GenericSyslogParser()

# ---- helpers ---------------------------------------------------------------

RFC_FULL = "<134>Jun 10 13:55:36 db01 crond[2154]: (root) CMD (/usr/lib/sa/sa1 1 1)"
RFC_NO_PRI = "Jun 10 13:55:36 db01 crond[2154]: (root) CMD (/usr/lib/sa/sa1 1 1)"
RFC_NO_PID = "<134>Jun 10 13:55:36 db01 kernel: EXT4-fs (sda1): mounted filesystem"
RFC_META_SECTOR = "<134>Jun 10 13:55:36 db01 syslogd[1]: server started"


class TestGenericSyslogParser(unittest.TestCase):

    # ------------------------------------------------------------------
    # 1. Standard RFC 3164 line with PRI, hostname, program[pid], message
    # ------------------------------------------------------------------
    def test_full_rfc3164(self):
        raw = {"source_type": "generic_syslog", "raw": RFC_FULL, "meta": {}}
        event = PARSER.parse(raw)
        self.assertIsNotNone(event, "parser returned None for a valid RFC 3164 line")

        self.assertEqual(event["class_uid"], 1002)
        self.assertEqual(event["activity_id"], 1)
        self.assertEqual(event["type_uid"], 100201)
        self.assertEqual(event["src_endpoint"]["hostname"], "db01")
        self.assertEqual(event["actor"]["process"]["name"], "crond")
        self.assertEqual(event["actor"]["process"]["pid"], 2154)
        self.assertIn("(root) CMD", event["message"])
        self.assertEqual(event["siem"]["sector"], "common")
        self.assertEqual(event["siem"]["source_type"], "generic_syslog")
        self.assertIn("ingest_id", event["siem"])

    def test_full_rfc3164_validates(self):
        raw = {"source_type": "generic_syslog", "raw": RFC_FULL, "meta": {}}
        event = PARSER.parse(raw)
        errs = validate(event)
        self.assertEqual(errs, [], f"OCSF validation errors: {errs}")

    # ------------------------------------------------------------------
    # 2. Line without PRI -> still parses, severity_id defaults to 1
    # ------------------------------------------------------------------
    def test_no_pri(self):
        raw = {"source_type": "generic_syslog", "raw": RFC_NO_PRI, "meta": {}}
        event = PARSER.parse(raw)
        self.assertIsNotNone(event)
        self.assertEqual(event["severity_id"], 1)  # default Informational
        errs = validate(event)
        self.assertEqual(errs, [], f"OCSF validation errors: {errs}")

    # ------------------------------------------------------------------
    # 3. Line without pid -> actor.process.pid absent or None
    # ------------------------------------------------------------------
    def test_no_pid(self):
        raw = {"source_type": "generic_syslog", "raw": RFC_NO_PID, "meta": {}}
        event = PARSER.parse(raw)
        self.assertIsNotNone(event)
        proc = event.get("actor", {}).get("process", {})
        self.assertNotIn("pid", proc,
                         "pid should not be set when not present in log line")
        errs = validate(event)
        self.assertEqual(errs, [], f"OCSF validation errors: {errs}")

    # ------------------------------------------------------------------
    # 4. meta.sector override -> propagates to siem.sector
    # ------------------------------------------------------------------
    def test_sector_override(self):
        raw = {
            "source_type": "generic_syslog",
            "raw": RFC_META_SECTOR,
            "meta": {"sector": "bank"},
        }
        event = PARSER.parse(raw)
        self.assertIsNotNone(event)
        self.assertEqual(event["siem"]["sector"], "bank")
        errs = validate(event)
        self.assertEqual(errs, [], f"OCSF validation errors: {errs}")

    # ------------------------------------------------------------------
    # 5. Malformed line (empty/whitespace) -> returns None
    # ------------------------------------------------------------------
    def test_empty_line_returns_none(self):
        for bad in ("", "   ", "\t\n"):
            with self.subTest(line=repr(bad)):
                raw = {"source_type": "generic_syslog", "raw": bad, "meta": {}}
                self.assertIsNone(PARSER.parse(raw))

    def test_non_string_raw_returns_none(self):
        raw = {"source_type": "generic_syslog", "raw": None, "meta": {}}
        self.assertIsNone(PARSER.parse(raw))

    def test_garbled_line_returns_none(self):
        """A string that has no RFC 3164 timestamp header should return None."""
        raw = {"source_type": "generic_syslog", "raw": "XXXXXXXXX no timestamp here", "meta": {}}
        self.assertIsNone(PARSER.parse(raw))

    # ------------------------------------------------------------------
    # 6. meta.ingest_id -> propagates to siem.ingest_id
    # ------------------------------------------------------------------
    def test_ingest_id_from_meta(self):
        my_id = "test-ingest-id-1234"
        raw = {
            "source_type": "generic_syslog",
            "raw": RFC_FULL,
            "meta": {"ingest_id": my_id},
        }
        event = PARSER.parse(raw)
        self.assertIsNotNone(event)
        self.assertEqual(event["siem"]["ingest_id"], my_id)

    # ------------------------------------------------------------------
    # 7. PRI severity mapping (syslog sev 3 = Error -> OCSF High = 4)
    # ------------------------------------------------------------------
    def test_pri_severity_mapping(self):
        # facility 16 (local0) + severity 3 (Error) = PRI 16*8 + 3 = 131
        line = "<131>Jun 10 13:55:36 host1 app[99]: disk error"
        raw = {"source_type": "generic_syslog", "raw": line, "meta": {}}
        event = PARSER.parse(raw)
        self.assertIsNotNone(event)
        self.assertEqual(event["severity_id"], 4,
                         "syslog severity 3 (Error) should map to OCSF High (4)")

    # ------------------------------------------------------------------
    # 8. type_uid invariant
    # ------------------------------------------------------------------
    def test_type_uid_invariant(self):
        raw = {"source_type": "generic_syslog", "raw": RFC_FULL, "meta": {}}
        event = PARSER.parse(raw)
        self.assertIsNotNone(event)
        self.assertEqual(
            event["type_uid"],
            event["class_uid"] * 100 + event["activity_id"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
