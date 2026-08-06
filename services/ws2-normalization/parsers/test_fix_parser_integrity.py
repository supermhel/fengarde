"""Regression tests for Phase 1-3 parser-integrity fixes (unified_fix_plan_2026-08-06.md).

Pins the fixes whose regressions would silently downgrade or dead-letter events:

  FIX 3 : db_audit GRANT SELECT no longer downgraded to activity 1 (read).
  FIX 11: db_audit / vmware no longer crash on a non-string operation.
  FIX 7 : linux_ssh normalizes ::ffff:10.0.0.5 -> 10.0.0.5 and emits the event.
  FIX 8 : inventory_diff converts epoch-seconds seen_at to epoch-ms.
  FIX 12: VM.Undeploy classifies as activity 4 (Destroy), not 1 (Create).
  FIX L3: mcp_agent "compute"/"output"/"status" not misclassified as Create.
  FIX L9: inventory_diff non-string hostname dropped (schema-valid event).
  OPC-UA: 'Audit.CustomAction' routes to opcua_audit, not n8n.

Run: python services/ws2-normalization/parsers/test_fix_parser_integrity.py
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
from parsers.vmware_vsphere import VmwareVsphereParser  # noqa: E402
from parsers.linux_ssh import LinuxSshParser  # noqa: E402
from parsers.inventory_diff import InventoryDiffParser  # noqa: E402
from parsers.mcp_agent import McpAgentParser  # noqa: E402
from parsers import resolve  # noqa: E402
from parsers.opcua_audit import OpcUaAuditParser  # noqa: E402
from parsers.n8n_audit import N8nAuditParser  # noqa: E402

DB = DbAuditParser()
VM = VmwareVsphereParser()
SSH = LinuxSshParser()
INV = InventoryDiffParser()
MCP = McpAgentParser()


def _raw(rec, meta=None):
    return {"source_type": "unknown", "raw": rec, "meta": meta or {}}


class TestFix3GrantSelect(unittest.TestCase):
    """FIX 3: GRANT SELECT must classify as activity/severity 5, not 1."""

    def test_grant_select_is_privileged_op(self):
        event = DB.parse(_raw({
            "operation": "GRANT SELECT ON users TO bob", "user": "dba_svc",
            "object": "users", "timestamp": 1750000100000,
        }))
        self.assertIsNotNone(event)
        self.assertEqual(event["class_uid"], 6005)
        self.assertEqual(event["activity_id"], 5)
        self.assertEqual(event["severity_id"], 5)  # privilege category severity
        self.assertEqual(event["type_uid"], 600505)
        self.assertEqual(validate(event), [])

    def test_plain_select_still_read(self):
        event = DB.parse(_raw({"operation": "SELECT * FROM users", "user": "r"}))
        self.assertEqual(event["activity_id"], 1)

    def test_create_user_still_privileged(self):
        event = DB.parse(_raw({"operation": "CREATE USER alice", "user": "dba"}))
        self.assertEqual(event["activity_id"], 5)


class TestFix11NonStringOperation(unittest.TestCase):
    """FIX 11: a non-string operation must not crash db_audit / vmware."""

    def test_db_audit_int_operation_no_crash(self):
        event = DB.parse(_raw({"operation": 5, "user": "x"}))
        self.assertIsNotNone(event)  # falls through to default (read/info)
        self.assertEqual(event["activity_id"], 1)
        self.assertEqual(validate(event), [])

    def test_vmware_int_operation_no_crash(self):
        event = VM.parse(_raw({"operation": 5, "vm": "x"}))
        self.assertIsNotNone(event)
        self.assertEqual(validate(event), [])

    def test_db_audit_list_operation_no_crash(self):
        event = DB.parse(_raw({"operation": ["grant"], "user": "x"}))
        self.assertIsNotNone(event)
        self.assertEqual(validate(event), [])


class TestFix12VmUndeploy(unittest.TestCase):
    """FIX 12: VM.Undeploy must be activity 4 (Destroy), not 1 (Create)."""

    def test_undeploy_is_destroy(self):
        event = VM.parse(_raw({"operation": "VM.Undeploy", "vm": "prod-db-07"}))
        self.assertIsNotNone(event)
        self.assertEqual(event["activity_id"], 4)
        self.assertEqual(event["severity_id"], 5)  # destroy -> CRITICAL (SEV_BY_CATEGORY)
        self.assertEqual(validate(event), [])

    def test_deploy_is_create(self):
        event = VM.parse(_raw({"operation": "VM.Deploy", "vm": "web-01"}))
        self.assertEqual(event["activity_id"], 1)

    def test_remove_is_destroy(self):
        event = VM.parse(_raw({"operation": "VM.RemoveFromInventory", "vm": "x"}))
        self.assertEqual(event["activity_id"], 4)


class TestFix7Ipv4Mapped(unittest.TestCase):
    """FIX 7: ::ffff:10.0.0.5 normalizes to 10.0.0.5 and event is emitted."""

    _LINE = ("Nov  1 10:00:00 db sshd[42]: Accepted password for root "
             "from ::ffff:10.0.0.5 port 22 ssh2")

    def test_mapped_ip_normalizes_to_dotted_quad(self):
        event = SSH.parse(_raw(self._LINE,
                               {"received_at": 1751500000}))
        self.assertIsNotNone(event)
        self.assertEqual(event["src_endpoint"]["ip"], "10.0.0.5")
        self.assertNotEqual(event["src_endpoint"]["ip"], "::ffff:10.0.0.5")
        self.assertEqual(validate(event), [])


class TestFix8InventoryEpochSeconds(unittest.TestCase):
    """FIX 8: inventory_diff seen_at epoch-seconds -> correct epoch-ms."""

    _DEV = {"mac": "AA:BB:CC:DD:EE:FF", "ip": "10.20.0.77",
            "device_type": "plc", "sector": "ot", "hostname": "plc-line4"}

    def test_epoch_seconds_converted_to_ms(self):
        event = INV.parse(_raw({**self._DEV, "seen_at": 1751500000}))
        self.assertIsNotNone(event)
        self.assertEqual(event["time"], 1751500000000)  # seconds -> ms

    def test_epoch_ms_passes_through_unchanged(self):
        event = INV.parse(_raw({**self._DEV, "seen_at": 1751500000000}))
        self.assertEqual(event["time"], 1751500000000)

    def test_filestone_passes_through(self):
        event = INV.parse(_raw({**self._DEV, "seen_at": 133500000000000000}))
        self.assertIsNotNone(event)
        self.assertEqual(validate(event), [])


class TestFixL3McpShortWords(unittest.TestCase):
    """FIX L3: compute/output/status must NOT classify as Create."""

    def test_compute_not_create(self):
        event = MCP.parse(_raw({"tool": "compute", "arguments": {}}))
        self.assertIsNotNone(event)
        self.assertEqual(event["activity_id"], 2)

    def test_output_not_create(self):
        event = MCP.parse(_raw({"tool": "output", "arguments": {}}))
        self.assertEqual(event["activity_id"], 2)

    def test_status_not_create(self):
        event = MCP.parse(_raw({"tool": "status", "arguments": {}}))
        self.assertEqual(event["activity_id"], 2)

    def test_output_file_not_create(self):
        event = MCP.parse(_raw({"tool": "output_file", "arguments": {}}))
        self.assertEqual(event["activity_id"], 2)

    def test_put_object_still_create(self):
        event = MCP.parse(_raw({"tool": "put_object", "arguments": {}}))
        self.assertEqual(event["activity_id"], 1)

    def test_add_user_still_create(self):
        event = MCP.parse(_raw({"tool": "add_user", "arguments": {}}))
        self.assertEqual(event["activity_id"], 1)


class TestFixL9InventoryHostname(unittest.TestCase):
    """FIX L9: non-string hostname dropped -> schema-valid event."""

    def test_non_string_hostname_dropped(self):
        event = INV.parse(_raw({
            "mac": "AA:BB:CC:DD:EE:FF", "ip": "10.20.0.77",
            "hostname": 12345, "device_type": "plc", "sector": "ot",
            "seen_at": 1751500000000,
        }))
        self.assertIsNotNone(event)
        self.assertNotIn("hostname", event["src_endpoint"])
        self.assertEqual(validate(event), [])


class TestOpcUaRoutingEdge(unittest.TestCase):
    """OPC UA 'Audit.CustomAction' (Audit prefix, no EventType suffix) -> opcua_audit."""

    def test_audit_prefix_without_suffix_routes_to_opcua(self):
        parser = resolve(_raw({"eventType": "Audit.CustomAction"}))
        self.assertIsInstance(parser, OpcUaAuditParser)

    def test_audit_eventtype_still_routes_to_opcua(self):
        parser = resolve(_raw({"eventType": "AuditWriteUpdateEventType"}))
        self.assertIsInstance(parser, OpcUaAuditParser)

    def test_n8n_dotted_still_routes_to_n8n(self):
        parser = resolve(_raw({"eventType": "user.login", "user": "a"}))
        self.assertIsInstance(parser, N8nAuditParser)

    def test_source_type_authoritative_unaffected(self):
        parser = resolve({"source_type": "n8n_audit",
                          "raw": {"eventType": "Audit.CustomAction"}})
        self.assertIsInstance(parser, N8nAuditParser)


if __name__ == "__main__":
    unittest.main(verbosity=2)
