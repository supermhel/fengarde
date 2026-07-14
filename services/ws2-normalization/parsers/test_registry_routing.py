"""P0.4 registry content-sniff routing tests.

The old resolve() shadowed and dropped events: a DB GRANT (bare "operation") was
parsed as a vSphere read; a windows-only EventID (4688) routed to the AD parser
and was dropped; three parsers were unreachable via sniff; and a *value*
containing a marker substring could steer routing. These tests pin the fixed,
non-shadowing, spoof-resistant behavior.

Run: C:/Python313/python.exe services/ws2-normalization/parsers/test_registry_routing.py
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent.parent
sys.path.insert(0, str(HERE.parent))   # for `parsers`
sys.path.insert(0, str(SERVICES))      # for `shared`

from parsers import resolve  # noqa: E402
from parsers.db_audit import DbAuditParser  # noqa: E402
from parsers.vmware_vsphere import VmwareVsphereParser  # noqa: E402
from parsers.active_directory import ActiveDirectoryParser  # noqa: E402
from parsers.windows_eventlog import WindowsEventLogParser  # noqa: E402
from parsers.n8n_audit import N8nAuditParser  # noqa: E402
from parsers.opcua_audit import OpcUaAuditParser  # noqa: E402
from parsers.linux_ssh import LinuxSshParser  # noqa: E402
from parsers.generic_syslog import GenericSyslogParser  # noqa: E402


def _p(raw, st="unknown"):
    return {"source_type": st, "raw": raw}


class TestRegistryRouting(unittest.TestCase):
    def test_source_type_is_authoritative(self):
        # exact source_type wins even if content looks like something else
        self.assertIsInstance(resolve(_p({"tool": "x", "args": {}}, st="db_audit")),
                              DbAuditParser)

    def test_db_grant_not_shadowed_by_vmware(self):
        # bare DB privileged op -> db_audit, NOT vmware (the shadowing bug)
        rec = {"operation": "GRANT", "object": "customers", "user": "dba"}
        self.assertIsInstance(resolve(_p(rec)), DbAuditParser)

    def test_vmware_still_routes(self):
        rec = {"operation": "VM.Delete", "vm": "prod-07", "userName": "svc"}
        self.assertIsInstance(resolve(_p(rec)), VmwareVsphereParser)

    def test_windows_only_eventid_not_dropped(self):
        # 4688 is windows-only; must reach windows_eventlog, not AD (which drops it)
        self.assertIsInstance(resolve(_p({"EventID": 4688})), WindowsEventLogParser)

    def test_ad_eventid_routes_to_ad(self):
        self.assertIsInstance(resolve(_p({"EventID": 4625})), ActiveDirectoryParser)

    def test_n8n_login_event_routes_to_n8n(self):
        # a credential/login event with no workflow field still reaches n8n
        self.assertIsInstance(resolve(_p({"eventType": "user.login", "user": "a"})),
                              N8nAuditParser)

    def test_opcua_routes_by_camelcase_eventtype(self):
        self.assertIsInstance(resolve(_p({"eventType": "AuditWriteUpdateEventType"})),
                              OpcUaAuditParser)

    def test_ssh_text_line_routes(self):
        line = "Nov  1 10:00:00 host sshd[42]: Failed password for root from 10.0.0.1"
        self.assertIsInstance(resolve(_p(line)), LinuxSshParser)

    def test_generic_syslog_is_reachable(self):
        # a plain syslog line that is not ASA/ssh must reach the catch-all parser
        line = "Nov  1 10:00:00 host myapp: something happened"
        self.assertIsInstance(resolve(_p(line)), GenericSyslogParser)

    def test_value_substring_cannot_steer_routing(self):
        # a DB record whose object name literally contains "EventID" / "sshd[" must
        # still route to db_audit, not be hijacked by a value-substring match
        rec = {"operation": "GRANT", "object": "EventID_sshd[audit%ASA", "user": "x"}
        self.assertIsInstance(resolve(_p(rec)), DbAuditParser)

    def test_ambiguous_operation_is_dead_lettered(self):
        # bare "delete" with no db/vm discriminating field -> ambiguous -> None
        self.assertIsNone(resolve(_p({"operation": "delete"})))


if __name__ == "__main__":
    unittest.main(verbosity=1)
