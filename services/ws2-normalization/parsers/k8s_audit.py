"""Kubernetes audit-log parser: k8s audit webhook events -> OCSF API Activity (6003).

v0.5 Track A4. Kubernetes audit events (https://kubernetes.io/docs/tasks/debug/
debug-cluster/audit/) are a publicly documented, structured JSON event emitted
by the API server for every request -- the same "spec-derived fixture, real
schema" discipline as opcua_audit.py, not captured from a live cluster.

Mapping (Contract A / ocsf-classes.md): class 6003 API Activity. ``verb`` ->
activity_id: create->1, get/list/watch->2, update/patch->3, delete->4 (the
same Create/Read/Update/Delete table every other 6003 producer uses).

Raw bus payload ``raw`` is one k8s audit Event JSON record, e.g.::

    {"kind": "Event", "apiVersion": "audit.k8s.io/v1", "auditID": "...",
     "verb": "create", "user": {"username": "alice"},
     "sourceIPs": ["10.0.0.5"],
     "objectRef": {"resource": "pods", "namespace": "default", "name": "x"},
     "requestObject": {"spec": {"securityContext": {"privileged": true}}},
     "responseStatus": {"code": 201},
     "requestReceivedTimestamp": "2026-07-20T10:00:00.000000Z"}

``unmapped.k8s.is_privileged`` is a documented heuristic (privileged flag,
hostNetwork, or a hostPath volume in the pod spec), not a full admission-
control equivalent -- consumed by contracts/rules/dc_privileged_container.yml.
"""
from __future__ import annotations

import time
from typing import Optional

from .base import Parser, SEV_BY_CATEGORY, status_from_outcome
from shared.ocsf import valid_ip

_CLASS = 6003  # API Activity

_VERB_TO_ACTIVITY = {
    "create": 1, "get": 2, "list": 2, "watch": 2,
    "update": 3, "patch": 3, "delete": 4, "deletecollection": 4,
}
_VERB_TO_CATEGORY = {
    "create": "write", "get": "read", "list": "read", "watch": "read",
    "update": "modify", "patch": "modify",
    "delete": "destroy", "deletecollection": "destroy",
}


def _is_privileged_pod(request_object) -> bool:
    if not isinstance(request_object, dict):
        return False
    spec = request_object.get("spec")
    if not isinstance(spec, dict):
        return False
    sec_ctx = spec.get("securityContext")
    if isinstance(sec_ctx, dict) and sec_ctx.get("privileged") is True:
        return True
    for container in spec.get("containers", []) if isinstance(spec.get("containers"), list) else []:
        if isinstance(container, dict):
            csc = container.get("securityContext")
            if isinstance(csc, dict) and csc.get("privileged") is True:
                return True
    if spec.get("hostNetwork") is True or spec.get("hostPID") is True:
        return True
    for vol in spec.get("volumes", []) if isinstance(spec.get("volumes"), list) else []:
        if isinstance(vol, dict) and "hostPath" in vol:
            return True
    return False


class K8sAuditParser(Parser):
    SOURCE_TYPE = "k8s_audit"
    SECTOR = "datacenter"
    ORIGINAL_FORMAT = "json"
    PRODUCT = {"name": "Kubernetes API Server", "vendor_name": "CNCF"}

    def parse(self, raw: dict) -> Optional[dict]:
        rec = raw.get("raw")
        if not isinstance(rec, dict):
            return None
        meta = raw.get("meta") or {}

        verb = str(rec.get("verb") or "").lower()
        activity_id = _VERB_TO_ACTIVITY.get(verb)
        if activity_id is None:
            return None  # an audit stage/verb we don't model (e.g. "connect")
        severity_id = SEV_BY_CATEGORY[_VERB_TO_CATEGORY[verb]]

        status = status_from_outcome(rec.get("responseStatus") or {}, keys=("code",))
        _obj_ref_raw = rec.get("objectRef")
        obj_ref: dict = _obj_ref_raw if isinstance(_obj_ref_raw, dict) else {}
        _user_raw = rec.get("user")
        user: dict = _user_raw if isinstance(_user_raw, dict) else {}

        event = self.base_event(
            class_uid=_CLASS,
            activity_id=activity_id,
            severity_id=severity_id,
            time_ms=self._time_ms(rec, meta),
            ingest_id=meta.get("ingest_id") or rec.get("auditID"),
            status=status,
            message=f"k8s {verb} {obj_ref.get('resource', '?')}/{obj_ref.get('name', '?')}",
            meta=meta,
            sector=self.resolve_sector(meta),
        )

        username = user.get("username")
        if username:
            event["actor"] = {"user": {"name": username}}

        source_ips = rec.get("sourceIPs")
        if isinstance(source_ips, list) and source_ips and valid_ip(source_ips[0]):
            event["src_endpoint"] = {"ip": source_ips[0]}

        event["unmapped"] = {
            "k8s": {
                "namespace": obj_ref.get("namespace"),
                "resource": obj_ref.get("resource"),
                "verb": verb,
                "is_privileged": _is_privileged_pod(rec.get("requestObject")),
            }
        }
        return event

    @staticmethod
    def _time_ms(rec: dict, meta: dict) -> int:
        # requestReceivedTimestamp is a real RFC3339 field on every k8s audit
        # event; fall back to meta.received_at, then now -- same layered
        # fallback every other parser uses.
        ts = rec.get("requestReceivedTimestamp")
        if isinstance(ts, str) and ts:
            from .timeutil import to_epoch_ms
            parsed = to_epoch_ms(ts)
            if parsed is not None:
                return parsed
        ra = meta.get("received_at")
        if isinstance(ra, (int, float)):
            return int(ra * 1000) if ra < 1e12 else int(ra)
        return int(time.time() * 1000)
