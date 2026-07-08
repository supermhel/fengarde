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
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

_MAX_BODY_BYTES = 4096  # a triage update is a status enum + a short note.
_MAX_NOTE_CHARS = 2000
_STATUSES = {"new", "triaged", "closed", "false_positive", "true_positive"}


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

        def _alert_id_from_path(self, path: str) -> str | None:
            # /alerts/{alert_id}/triage
            parts = path.strip("/").split("/")
            if len(parts) == 3 and parts[0] == "alerts" and parts[2] == "triage":
                return parts[1]
            return None

        def do_GET(self):
            try:
                self._route_get()
            except _BadRequest as e:
                self._send(400, {"error": str(e)})
            except Exception:  # noqa: BLE001 - never let a handler crash the thread
                self._send(500, {"error": "internal error"})

        def _route_get(self):
            u = urlparse(self.path)
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
                self._route_post()
            except _BadRequest as e:
                self._send(400, {"error": str(e)})
            except Exception:  # noqa: BLE001 - never let a handler crash the thread
                self._send(500, {"error": "internal error"})

        def _route_post(self):
            u = urlparse(self.path)
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

            with write_lock:
                found = store.find_alert(alert_id)
                if found is None:
                    return self._send(404, {"error": "alert not found"})
                index, doc = found

                triage = dict(doc.get("triage") or _default_triage())
                if status is not None:
                    triage["status"] = status
                if note_present:
                    triage["note"] = note
                triage["updated_at"] = int(time.time() * 1000)

                doc = dict(doc)
                doc["triage"] = triage
                store.index(index, alert_id, doc)  # idempotent overwrite, same doc_id
            return self._send(200, triage)

    return Handler


def serve(store, host="0.0.0.0", port=8013):
    handler_cls = make_handler(store)
    srv = ThreadingHTTPServer((host, port), handler_cls)
    print(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                      "level": "info", "service": "ws3-indexer-triage",
                      "msg": "listening", "url": f"http://{host}:{port}"}), flush=True)
    srv.serve_forever()
