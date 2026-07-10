"""WS-3 Triage HTTP API (v0.3, C1).

The dashboard renders alert rows with no way to act on them. This is the
minimal real workflow: a status + analyst note per alert, persisted.

Endpoints:
  GET  /alerts/{alert_id}/triage        -> current triage state (default "new")
  POST /alerts/{alert_id}/triage        -> {status, note?} -> updates + returns it

Mirrors services/ws6-inventory/app.py's stdlib http.server discipline exactly
(input validation, body-size cap, clean 4xx on malformed input, handler thread
never crashes) rather than introducing a new framework/dependency.

Storage: the `triage` field is added to the EXISTING alert document (OCSF-
additive -- an old alert doc without it defaults to status "new", tolerant
reader). Uses `store.find_alert(alert_id)` (added to both MemoryStore and
OpenSearchStore) since the client only holds alert_id, not which daily index
it landed in.
"""
from __future__ import annotations

import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

_HERE = Path(__file__).resolve().parent
for _p in (str(_HERE), str(_HERE.parent)):
    if _p not in sys.path:
        sys.path.insert(0, _p)
from shared.authz import check_api_key, warn_if_disabled  # noqa: E402
import reporting  # noqa: E402

_MAX_BODY_BYTES = 4096  # a triage update is a status enum + a short note.
_MAX_NOTE_CHARS = 2000
_STATUSES = {"new", "triaged", "closed", "false_positive", "true_positive"}
_CAS_MAX_RETRIES = 5  # optimistic-concurrency retry bound (see _route_post)


class _BadRequest(Exception):
    """Malformed client input; mapped to a 400 by the dispatcher."""


def _default_triage() -> dict:
    return {"status": "new", "note": "", "updated_at": None}


def make_handler(store):
    """Returns a Handler class bound to the given store (closure, matches the
    pattern main.py already uses for the bus handler)."""
    # ThreadingHTTPServer runs one thread per connection. A triage update is a
    # read (find_alert) -> modify (merge triage dict) -> write (store.index)
    # sequence across several Python statements; two concurrent POSTs to the
    # SAME alert_id can interleave and silently lose one side's change (a
    # classic lost-update race -- e.g. one analyst's status change and
    # another's note both intended to persist, only the later store.index()
    # survives). Triage writes are rare and cheap, so one process-wide lock
    # serializing the read-modify-write section is the simplest correct fix;
    # it does not block concurrent GETs or POSTs to DIFFERENT alerts in any
    # way that matters at this volume.
    write_lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def _send(self, code: int, payload):
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):  # quiet
            pass

        def _alert_id_from_path(self, path: str, resource: str = "triage") -> str | None:
            # /alerts/{alert_id}/{resource}  (resource: "triage" | "report")
            parts = path.strip("/").split("/")
            if len(parts) == 3 and parts[0] == "alerts" and parts[2] == resource:
                return parts[1]
            return None

        def _check_auth(self) -> bool:
            if check_api_key(self.headers):
                return True
            self._send(401, {"error": "unauthorized"})
            return False

        def do_GET(self):
            try:
                if not self._check_auth():
                    return
                self._route_get()
            except _BadRequest as e:
                self._send(400, {"error": str(e)})
            except Exception:  # noqa: BLE001 - never let a handler crash the thread
                self._send(500, {"error": "internal error"})

        def _route_get(self):
            u = urlparse(self.path)
            report_alert_id = self._alert_id_from_path(u.path, "report")
            if report_alert_id is not None:
                if not report_alert_id:
                    raise _BadRequest("alert_id required")
                report = store.find_report(report_alert_id)
                if report is None:
                    return self._send(404, {"error": "report not found"})
                return self._send(200, report)

            alert_id = self._alert_id_from_path(u.path)
            if alert_id is None:
                return self._send(404, {"error": "no such path"})
            if not alert_id:
                raise _BadRequest("alert_id required")
            found = store.find_alert(alert_id)
            if found is None:
                return self._send(404, {"error": "alert not found"})
            _, doc = found
            return self._send(200, doc.get("triage") or _default_triage())

        def do_POST(self):
            try:
                if not self._check_auth():
                    return
                self._route_post()
            except _BadRequest as e:
                self._send(400, {"error": str(e)})
            except Exception:  # noqa: BLE001 - never let a handler crash the thread
                self._send(500, {"error": "internal error"})

        def _route_post(self):
            u = urlparse(self.path)

            report_alert_id = self._alert_id_from_path(u.path, "report")
            if report_alert_id is not None:
                # Drain any request body (the client may send one, even
                # though this endpoint takes none) so the connection doesn't
                # get reset with unread bytes still buffered.
                try:
                    length = int(self.headers.get("Content-Length", 0))
                except (TypeError, ValueError):
                    length = 0
                if length > 0:
                    self.rfile.read(min(length, _MAX_BODY_BYTES))
                if not report_alert_id:
                    raise _BadRequest("alert_id required")
                found = store.find_alert(report_alert_id)
                if found is None:
                    return self._send(404, {"error": "alert not found"})
                _, alert_doc = found
                triage = alert_doc.get("triage") or _default_triage()
                report = reporting.generate_report(alert_doc, triage)
                report_index = reporting._report_index()
                store.index(report_index, report["report_id"], report)
                return self._send(200, report)

            alert_id = self._alert_id_from_path(u.path)
            if alert_id is None:
                return self._send(404, {"error": "no such path"})
            if not alert_id:
                raise _BadRequest("alert_id required")

            try:
                length = int(self.headers.get("Content-Length", 0))
            except (TypeError, ValueError):
                raise _BadRequest("invalid Content-Length")
            if length < 0:
                raise _BadRequest("invalid Content-Length")
            if length > _MAX_BODY_BYTES:
                raise _BadRequest("request body too large")
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except (json.JSONDecodeError, UnicodeDecodeError):
                raise _BadRequest("body must be valid JSON")
            if not isinstance(body, dict):
                raise _BadRequest("body must be a JSON object")

            status = body.get("status")
            if status is not None and status not in _STATUSES:
                raise _BadRequest(f"status must be one of {sorted(_STATUSES)}")
            # PARTIAL UPDATE: "note" absent from the body must PRESERVE the
            # existing note, not clear it -- symmetric with how "status" only
            # updates when provided. Distinguish "key absent" from "key present
            # with an empty string" (an analyst clearing the note on purpose is
            # a legitimate, different action from not mentioning note at all).
            note_present = "note" in body
            note = body.get("note")
            if note_present:
                if not isinstance(note, str):
                    raise _BadRequest("note must be a string")
                note = note[:_MAX_NOTE_CHARS]

            # Two layers of lost-update protection:
            # - write_lock serializes read-modify-write WITHIN this process
            #   (covers MemoryStore and single-replica deployments outright).
            # - index_cas (optimistic concurrency) covers writers this lock
            #   can't see -- another ws3 replica against a shared OpenSearch.
            #   A stale write comes back as a conflict; re-read and retry.
            #   Retries are bounded; exhaustion surfaces as 409 to the client
            #   (retryable), never a silently dropped update.
            with write_lock:
                for _attempt in range(_CAS_MAX_RETRIES):
                    found = store.find_alert_versioned(alert_id)
                    if found is None:
                        return self._send(404, {"error": "alert not found"})
                    index, doc, version = found

                    triage = dict(doc.get("triage") or _default_triage())
                    if status is not None:
                        triage["status"] = status
                    if note_present:
                        triage["note"] = note
                    triage["updated_at"] = int(time.time() * 1000)

                    doc = dict(doc)
                    doc["triage"] = triage
                    if store.index_cas(index, alert_id, doc, version):
                        return self._send(200, triage)
                    # conflict: another writer landed between our read and
                    # write -- loop re-reads the fresh doc and re-applies.
            return self._send(409, {"error": "conflicting concurrent updates, retry"})

    return Handler


def serve(store, host="0.0.0.0", port=8013):
    warn_if_disabled("ws3-indexer-triage")
    handler_cls = make_handler(store)
    srv = ThreadingHTTPServer((host, port), handler_cls)
    print(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                      "level": "info", "service": "ws3-indexer-triage",
                      "msg": "listening", "url": f"http://{host}:{port}"}), flush=True)
    srv.serve_forever()
