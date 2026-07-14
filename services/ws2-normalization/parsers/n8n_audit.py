"""n8n audit/execution-log parser: automation-platform events -> OCSF.

v0.4 Track P3 (opportunistic niche -- 100k+ internet-facing n8n instances per
the market analysis, governance features paywalled in n8n's paid tiers,
self-hosters otherwise unwatched). n8n emits structured audit/execution log
events; this parser accepts a JSON shape following n8n's own event-type
naming (`workflow.created`, `workflow.updated`, `workflow.activated`,
`credentials.accessed`, `webhook.created`) plus login events.

Mapping (Contract A / ocsf-classes.md):
    workflow.*/webhook.*/credentials.* -> 6003 API Activity
        (activity 1 Create, 2 Read, 3 Update per event-type verb)
    user login/logout                 -> 3002 Authentication

Raw bus payload ``raw`` is one JSON audit event, e.g.::

    {"eventType": "webhook.created", "user": "alice",
     "ip": "203.0.113.9", "workflowId": "wf-42",
     "path": "/webhook/incoming-order", "ts": 1751500000000}
"""
from __future__ import annotations

import json
import time
from typing import Optional

from .base import Parser, SEV_HIGH, SEV_INFO, SEV_MEDIUM, status_from_outcome

_CLASS_API = 6003
_CLASS_AUTH = 3002

_LOGIN_EVENTS = {"user.login", "login"}
_LOGOUT_EVENTS = {"user.logout", "logout"}

# eventType verb -> (activity_id, severity)
_VERB_MAP = {
    "created": (1, SEV_MEDIUM),
    "activated": (1, SEV_MEDIUM),
    "read": (2, SEV_INFO),
    "viewed": (2, SEV_INFO),
    "updated": (3, SEV_MEDIUM),
    "accessed": (3, SEV_HIGH),   # credential access -- treated as sensitive
    "deleted": (4, SEV_MEDIUM),
}


def _pick(rec: dict, *keys):
    for k in keys:
        if k in rec and rec[k] is not None:
            return rec[k]
    return None


class N8nAuditParser(Parser):
    SOURCE_TYPE = "n8n_audit"
    SECTOR = "common"
    ORIGINAL_FORMAT = "json"
    PRODUCT = {"name": "n8n", "vendor_name": "n8n GmbH"}

    def parse(self, raw: dict) -> Optional[dict]:
        rec = raw.get("raw")
        if isinstance(rec, str):
            try:
                rec = json.loads(rec)
            except (ValueError, TypeError):
                return None
        if not isinstance(rec, dict):
            return None
        meta = raw.get("meta") or {}

        event_type = _pick(rec, "eventType", "event_type", "type")
        if not event_type:
            return None

        user = _pick(rec, "user", "userEmail", "username")
        src_ip = _pick(rec, "ip", "src_ip") or meta.get("ip")
        time_ms = self._time_ms(rec, meta)

        if event_type in _LOGIN_EVENTS or event_type in _LOGOUT_EVENTS:
            return self._auth_event(event_type, user, src_ip, time_ms, rec, meta)
        return self._api_event(event_type, user, src_ip, time_ms, rec, meta)

    def _auth_event(self, event_type, user, src_ip, time_ms, rec, meta) -> dict:
        activity_id = 1 if event_type in _LOGIN_EVENTS else 2
        # A failed login MUST NOT be recorded as a successful authentication --
        # that would suppress the brute-force/credential rules this feeds.
        status = status_from_outcome(rec)
        message = f"n8n {event_type} for {user or 'unknown user'}"
        event = self.base_event(
            class_uid=_CLASS_AUTH,
            activity_id=activity_id,
            severity_id=SEV_HIGH if status == "Failure" else SEV_INFO,
            time_ms=time_ms,
            ingest_id=meta.get("ingest_id"),
            logged_time=self._logged_time(rec, meta),
            status=status,
            message=message,
        )
        if src_ip:
            event["src_endpoint"] = {"ip": src_ip}
        if user:
            event["actor"] = {"user": {"name": user}}
        return event

    def _api_event(self, event_type, user, src_ip, time_ms, rec, meta) -> Optional[dict]:
        verb = str(event_type).rsplit(".", 1)[-1].lower()
        activity_id, severity_id = _VERB_MAP.get(verb, (2, SEV_INFO))

        workflow_id = _pick(rec, "workflowId", "workflow_id")
        webhook_path = _pick(rec, "path", "webhookPath")

        message = f"n8n {event_type} by {user or 'unknown user'}"
        event = self.base_event(
            class_uid=_CLASS_API,
            activity_id=activity_id,
            severity_id=severity_id,
            time_ms=time_ms,
            ingest_id=meta.get("ingest_id"),
            logged_time=self._logged_time(rec, meta),
            status=status_from_outcome(rec),
            message=message,
        )
        event["api"] = {"operation": str(event_type)}
        if src_ip:
            event["src_endpoint"] = {"ip": src_ip}
        if user:
            event["actor"] = {"user": {"name": user}}
        unmapped: dict = {"n8n": {}}
        if workflow_id:
            unmapped["n8n"]["workflow_id"] = workflow_id
        if webhook_path:
            unmapped["n8n"]["webhook_path"] = webhook_path
        if unmapped["n8n"]:
            event["unmapped"] = unmapped
        return event

    @staticmethod
    def _time_ms(rec: dict, meta: dict) -> int:
        ts = rec.get("ts") or rec.get("timestamp") or meta.get("received_at")
        if isinstance(ts, (int, float)):
            return int(ts * 1000) if ts < 1e12 else int(ts)
        return int(time.time() * 1000)

    @staticmethod
    def _logged_time(rec: dict, meta: dict) -> Optional[int]:
        lt = meta.get("received_at")
        if isinstance(lt, (int, float)):
            return int(lt * 1000) if lt < 1e12 else int(lt)
        return None
