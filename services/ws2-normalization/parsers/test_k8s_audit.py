"""Unit tests for the k8s_audit parser (v0.5 Track A4).

Fixtures are SPEC-DERIVED from the k8s audit-event schema
(https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/), not captured
from a live cluster -- same discipline as opcua_audit.py.

Run with:
    python services/ws2-normalization/parsers/test_k8s_audit.py
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
from parsers.k8s_audit import K8sAuditParser  # noqa: E402
from parsers import resolve  # noqa: E402

PARSER = K8sAuditParser()


def _raw(rec, meta=None):
    return {"source_type": "k8s_audit", "raw": rec, "meta": meta or {}}


class TestK8sAuditParser(unittest.TestCase):

    def test_privileged_pod_create_is_api_activity_create(self):
        event = PARSER.parse(_raw({
            "auditID": "abc-123", "verb": "create",
            "user": {"username": "alice"}, "sourceIPs": ["10.0.0.5"],
            "objectRef": {"resource": "pods", "namespace": "default", "name": "x"},
            "requestObject": {"spec": {"securityContext": {"privileged": True}}},
            "responseStatus": {"code": 201},
            "requestReceivedTimestamp": "2026-07-20T10:00:00.000000Z",
        }))
        self.assertIsNotNone(event)
        self.assertEqual(event["class_uid"], 6003)
        self.assertEqual(event["activity_id"], 1)
        self.assertEqual(event["status"], "Success")
        self.assertEqual(event["actor"]["user"]["name"], "alice")
        self.assertEqual(event["src_endpoint"]["ip"], "10.0.0.5")
        self.assertTrue(event["unmapped"]["k8s"]["is_privileged"])
        self.assertEqual(validate(event), [])

    def test_non_privileged_pod_create_is_not_flagged(self):
        event = PARSER.parse(_raw({
            "auditID": "def-456", "verb": "create", "user": {"username": "bob"},
            "objectRef": {"resource": "pods", "namespace": "default"},
            "requestObject": {"spec": {}},
        }))
        self.assertFalse(event["unmapped"]["k8s"]["is_privileged"])

    def test_hostpath_volume_flags_privileged(self):
        event = PARSER.parse(_raw({
            "auditID": "ghi-789", "verb": "create", "user": {"username": "carol"},
            "objectRef": {"resource": "pods"},
            "requestObject": {"spec": {"volumes": [{"hostPath": {"path": "/etc"}}]}},
        }))
        self.assertTrue(event["unmapped"]["k8s"]["is_privileged"])

    def test_delete_verb_maps_to_activity_4_destroy_severity(self):
        event = PARSER.parse(_raw({
            "auditID": "jkl-012", "verb": "delete", "user": {"username": "dave"},
            "objectRef": {"resource": "pods"}, "responseStatus": {"code": 200},
        }))
        self.assertEqual(event["activity_id"], 4)
        self.assertEqual(event["severity_id"], 5)  # SEV_CRITICAL

    def test_unrecognized_verb_returns_none(self):
        self.assertIsNone(PARSER.parse(_raw({"auditID": "x", "verb": "connect"})))

    def test_non_dict_raw_returns_none(self):
        self.assertIsNone(PARSER.parse(_raw("not a dict")))

    def test_content_sniff_routes_by_audit_id(self):
        parser = resolve({"source_type": "", "raw": {"auditID": "x", "verb": "get"}, "meta": {}})
        self.assertIs(type(parser), K8sAuditParser)


if __name__ == "__main__":
    unittest.main()
