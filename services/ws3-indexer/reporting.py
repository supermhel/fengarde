"""WS-3 Incident-Report hook (v0.4 Track R).

Implements the open side of contracts/reporting.md: an alert becomes a
structured incident-report draft via the builtin template backend (zero
paid dependency), or via an external `argiem-sec`-style HTTP backend when
configured -- with the builtin template as the automatic fallback.

Endpoints (wired into triage_api.py's dispatcher):
  POST /alerts/{alert_id}/report   -> generate (or re-generate) + store
  GET  /alerts/{alert_id}/report   -> return the stored report, 404 if none

Storage: `reports-YYYY.MM.DD`, deterministic `report_id` (f"{alert_id}:report")
so re-generation is idempotent under retry -- same discipline as alert_id.

NOTE on scope: v0.4 assembles the report from the alert document + its triage
state. Pulling the full set of contributing normalized events (event_ids on
the alert) into the request payload is deferred -- it needs a generic
cross-index event lookup this adapter doesn't have yet (find_alert/
find_report are alert/report-specific). The template renders correctly with
alert-level facts alone; a richer "events" section is a straightforward
follow-up once that lookup exists.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

_DISCLAIMER = ("DRAFT — automatically generated. Not legal advice. "
               "Review before any regulatory submission.")
_REQUEST_TIMEOUT = float(os.getenv("REPORT_BACKEND_TIMEOUT", "5"))


def _report_index(now: float | None = None) -> str:
    return time.strftime("reports-%Y.%m.%d", time.gmtime(now))


def _default_triage() -> dict:
    return {"status": "new", "note": "", "updated_at": None}


def _render_template(alert: dict, triage: dict) -> str:
    """Builtin, open, generic incident-report markdown. Zero regulatory
    claims -- no NIS2/DORA article references here; that content is the paid
    argiem-sec backend's asset (contracts/reporting.md)."""
    rule_title = alert.get("rule_title", "(unknown rule)")
    level = alert.get("level", "unknown")
    score = alert.get("score", "unknown")
    when = alert.get("time", "(unknown time)")
    sector = alert.get("sector") or "(unspecified)"
    src = alert.get("src_endpoint") or {}
    actor = alert.get("actor") or {}
    status = triage.get("status", "new")
    note = triage.get("note") or "(none)"

    lines = [
        f"# Incident Report Draft — {rule_title}",
        "",
        f"**Severity:** {level} (score {score})",
        f"**Detected:** {when}",
        f"**Sector:** {sector}",
        "",
        "## Source / Actor",
        f"- Source endpoint: {src.get('ip', '(unknown)')}"
        f"{' / ' + src['location']['country'] if isinstance(src.get('location'), dict) and src['location'].get('country') else ''}",
        f"- Actor: {actor.get('user', {}).get('name', '(unknown)') if isinstance(actor.get('user'), dict) else '(unknown)'}",
        "",
        "## Triage state",
        f"- Status: {status}",
        f"- Analyst note: {note}",
        "",
        "## Fields an analyst must still provide",
        "- [ANALYST MUST PROVIDE: business impact assessment]",
        "- [ANALYST MUST PROVIDE: containment/remediation actions taken]",
        "- [ANALYST MUST PROVIDE: regulatory notification obligations, if any]",
        "",
        f"_{_DISCLAIMER}_",
    ]
    return "\n".join(lines)


def _template_backend(alert: dict, triage: dict, requested_at: float) -> dict:
    return {
        "report_id": f"{alert.get('alert_id')}:report",
        "alert_id": alert.get("alert_id"),
        "format": "markdown",
        "body": _render_template(alert, triage),
        "status": "draft",
        "disclaimer": _DISCLAIMER,
        "generated_at": int(requested_at * 1000),
        "backend": "template",
        "backend_degraded": False,
        "citations": [],
    }


def _validate_backend_response(resp: dict) -> bool:
    """Enforce contracts/reporting.md's hard rules. Anything that fails is
    treated as a backend failure -- caller falls back to the template."""
    if not isinstance(resp, dict):
        return False
    if resp.get("status") != "draft":
        return False
    if not resp.get("disclaimer"):
        return False
    if not isinstance(resp.get("body"), str) or not resp["body"]:
        return False
    citations = resp.get("citations", [])
    if not isinstance(citations, list):
        return False
    return True


def _call_http_backend(alert: dict, triage: dict, events: list, requested_at: float) -> dict | None:
    url = os.getenv("ARGIEM_SEC_REPORT_URL")
    if not url:
        return None
    payload = json.dumps({
        "alert": alert, "triage": triage, "events": events,
        "requested_at": requested_at,
    }).encode()
    req = urllib.request.Request(
        url, data=payload, method="POST",
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT) as resp:  # noqa: S310
            body = json.loads(resp.read().decode())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError):
        return None
    if not _validate_backend_response(body):
        return None
    body.setdefault("backend", "argiem-sec")
    body.setdefault("backend_degraded", False)
    return body


def generate_report(alert: dict, triage: dict) -> dict:
    """Produce a report per contracts/reporting.md. Tries the configured
    backend seam (REPORT_BACKEND=http -> ARGIEM_SEC_REPORT_URL), falls back to
    the builtin template on any failure/invalid response -- a report is
    always produced (fail-open)."""
    requested_at = time.time()
    backend = os.getenv("REPORT_BACKEND", "template").lower()
    if backend == "http":
        result = _call_http_backend(alert, triage, [], requested_at)
        if result is not None:
            return result
        degraded = _template_backend(alert, triage, requested_at)
        degraded["backend_degraded"] = True
        return degraded
    return _template_backend(alert, triage, requested_at)
