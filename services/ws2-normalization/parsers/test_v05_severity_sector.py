"""P2.2 regression: cross-source severity rubric + validated sector override.

  - A destructive op (delete/destroy/drop) must land on the same OCSF severity
    (CRITICAL) regardless of which parser produced it -- previously vmware's
    delete/destroy/remove was CRITICAL while db_audit's delete and n8n's
    deleted were MEDIUM, so the exact same real-world action (irreversible
    resource loss) skewed scoring.yaml's weighted sum differently per source.
  - meta.sector overrides a parser's default SECTOR, but only with a value in
    Contract A's enum (bank|datacenter|common); an unvalidated override would
    otherwise reach the schema's enum check and dead-letter the whole event.

Run: C:/Python313/python.exe services/ws2-normalization/parsers/test_v05_severity_sector.py
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
from parsers.base import SEV_CRITICAL  # noqa: E402
from parsers.vmware_vsphere import VmwareVsphereParser  # noqa: E402
from parsers.db_audit import DbAuditParser  # noqa: E402
from parsers.n8n_audit import N8nAuditParser  # noqa: E402
from parsers.linux_ssh import LinuxSshParser  # noqa: E402
from parsers.cisco_asa import CiscoAsaParser  # noqa: E402


def _raw(rec, st="x", meta=None):
    return {"source_type": st, "raw": rec, "meta": meta or {}}


class TestSeverityRubricHarmonized(unittest.TestCase):
    def test_vmware_delete_is_critical(self):
        ev = VmwareVsphereParser().parse(_raw(
            {"operation": "VM.Delete", "vm": "v", "userName": "u"}))
        self.assertEqual(ev["severity_id"], SEV_CRITICAL)

    def test_db_delete_is_critical_like_drop(self):
        ev = DbAuditParser().parse(_raw(
            {"operation": "DELETE", "object": "accounts", "user": "u"}))
        self.assertEqual(ev["severity_id"], SEV_CRITICAL)

    def test_n8n_deleted_is_critical(self):
        ev = N8nAuditParser().parse(_raw(
            {"eventType": "workflow.deleted", "user": "u"}))
        self.assertEqual(ev["severity_id"], SEV_CRITICAL)


class TestSectorOverrideValidated(unittest.TestCase):
    def test_valid_override_honored_on_previously_unwired_parser(self):
        # linux_ssh never read meta.sector before P2.2
        line = "Nov 1 10:00:00 h sshd[7]: Accepted password for deploy from 10.0.0.6 port 1 ssh2"
        ev = LinuxSshParser().parse(_raw(line, st="linux_ssh", meta={"sector": "bank"}))
        self.assertEqual(ev["siem"]["sector"], "bank")
        self.assertEqual(validate(ev), [])

    def test_invalid_override_falls_back_to_default(self):
        line = "%ASA-4-106023: deny tcp src outside:10.0.0.9/55 dst inside:10.0.0.1/80"
        ev = CiscoAsaParser().parse(_raw(line, st="cisco_asa", meta={"sector": "not-a-real-sector"}))
        self.assertEqual(ev["siem"]["sector"], "common")  # CiscoAsaParser.SECTOR
        self.assertEqual(validate(ev), [])

    def test_no_override_keeps_parser_default(self):
        ev = VmwareVsphereParser().parse(_raw({"operation": "VM.Delete", "vm": "v"}))
        self.assertEqual(ev["siem"]["sector"], "datacenter")


if __name__ == "__main__":
    unittest.main(verbosity=1)
