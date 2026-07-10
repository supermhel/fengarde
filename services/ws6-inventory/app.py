"""WS-6 Inventory HTTP API (Contract C).

Implements the OpenAPI paths from contracts/inventory-api.yaml. The handler logic
lives here on a stdlib http.server so it runs with zero dependencies (the contract
test exercises it live). For production, the same `InventoryStore` is trivially
wrapped by FastAPI + uvicorn (see requirements.txt); routing is identical.

Endpoints:
  GET  /assets                 list/search (ip, mac, sector, status, limit)
  GET  /assets/resolve         ?ip=&at=  -> historically-correct asset
  GET  /assets/{mac}           one asset by MAC
  POST /assets/upsert          upsert from an Observation
"""
from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from store import InventoryStore  # noqa: E402
from authz import check_api_key, warn_if_disabled  # noqa: E402

STORE = InventoryStore(os.getenv("INVENTORY_DB", ":memory:"))

# Bounds on client-controlled inputs. `limit` is clamped so a hostile/typo value
# can't ask SQLite for an unbounded scan; the POST body is capped so an oversized
# upload can't be buffered into memory (a naive rfile.read(Content-Length) would).
_MAX_LIMIT = 1000
_DEFAULT_LIMIT = 50
_MAX_BODY_BYTES = 1_048_576  # 1 MiB — an Observation is a few hundred bytes.


class _BadRequest(Exception):
    """Raised on malformed client input; mapped to a 400 by the dispatcher."""


def _parse_limit(raw) -> int:
    """Coerce ?limit= to an int in [1, _MAX_LIMIT]. Raises _BadRequest on garbage."""
    if raw is None:
        return _DEFAULT_LIMIT
    try:
        n = int(raw)
    except (TypeError, ValueError):
        raise _BadRequest("limit must be an integer")
    if n < 1:
        raise _BadRequest("limit must be >= 1")
    return min(n, _MAX_LIMIT)


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

    def _check_auth(self) -> bool:
        if check_api_key(self.headers):
            return True
        self._send(401, {"error": "unauthorized"})
        return False

    def do_GET(self):
        # Any malformed input (bad ?at=, bad ?limit=) becomes a clean 4xx/5xx JSON
        # response instead of an unhandled exception that drops the connection and
        # leaks a stack trace to the client.
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
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path == "/assets/resolve":
            if "ip" not in q or "at" not in q:
                return self._send(400, {"error": "ip and at required"})
            try:
                asset = STORE.resolve(q["ip"], q["at"])
            except ValueError:
                # datetime.fromisoformat() on a malformed `at` -> 400, not a 500.
                raise _BadRequest("at must be an ISO-8601 timestamp")
            return self._send(200, asset) if asset else self._send(404, {"error": "not found"})
        if u.path == "/assets":
            return self._send(200, STORE.list(
                ip=q.get("ip"), mac=q.get("mac"), sector=q.get("sector"),
                status=q.get("status"), limit=_parse_limit(q.get("limit"))))
        if u.path.startswith("/assets/"):
            mac = u.path[len("/assets/"):]
            asset = STORE.get(mac)
            return self._send(200, asset) if asset else self._send(404, {"error": "not found"})
        return self._send(404, {"error": "no such path"})

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
        if u.path == "/assets/upsert":
            asset = STORE.upsert(body)
            return self._send(200, asset) if asset else self._send(400, {"error": "mac required"})
        return self._send(404, {"error": "no such path"})


def serve(host="0.0.0.0", port=8000):
    warn_if_disabled("ws6-inventory")
    srv = ThreadingHTTPServer((host, port), Handler)
    # ws6 is a standalone service; its image does NOT bundle `shared`, so emit a
    # structured JSON log line inline rather than importing shared.log.
    import json as _json
    import time as _time
    print(_json.dumps({"ts": _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
                       "level": "info", "service": "ws6-inventory",
                       "msg": "listening", "url": f"http://{host}:{port}"}), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    serve(port=int(os.getenv("PORT", "8000")))
