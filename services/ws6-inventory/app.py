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
from urllib.parse import urlparse, parse_qs, unquote

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from store import InventoryStore, InvalidTenantId  # noqa: E402
from keystore import (  # noqa: E402
    SCOPE_READ_ONLY, TenantKeyStore, ensure_legacy_keys_migrated,
    warn_if_legacy_env_now_ignored, warn_missing_pepper,
)
from authz import warn_if_disabled  # noqa: E402

STORE = InventoryStore(os.getenv("INVENTORY_DB", ":memory:"))
# Same file as STORE by default (one DB to back up), separate connection --
# TenantKeyStore owns its own table/schema, see keystore.py.
KEYSTORE = TenantKeyStore(os.getenv("INVENTORY_KEYSTORE_DB", os.getenv("INVENTORY_DB", ":memory:")))
MIGRATED_TENANTS = ensure_legacy_keys_migrated(KEYSTORE)

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
    # Slowloris guard: drop a client that stalls mid-request instead of pinning
    # this connection's thread indefinitely.
    timeout = 15

    def _send(self, code: int, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):  # quiet
        pass

    def _check_auth(self):
        """Returns (True, bound_tenant, scope) on success, or sends 401 and
        returns (False, None, None). An empty keystore means auth is fully
        disabled -- the zero-infra/quickstart default, unchanged since
        before F1. Otherwise every request must present a key that
        verifies against KEYSTORE (hashed at rest, see keystore.py).
        bound_tenant is None for the '*' admin key (unrestricted, this
        request's own ?tenant_id= trusted as-is) or a specific tenant_id
        for a tenant-scoped key -- every tenant_id this request touches
        must then be forced to it, regardless of what the caller asked
        for. scope is SCOPE_READ_ONLY/SCOPE_READ_WRITE -- do_POST rejects
        a read-only key before it can write anything."""
        if KEYSTORE.count() == 0:
            return True, None, None
        ok, bound, scope = KEYSTORE.verify(self.headers.get("X-Api-Key", ""))
        if not ok:
            self._send(401, {"error": "unauthorized"})
            return False, None, None
        return True, bound, scope

    def do_GET(self):
        # Any malformed input (bad ?at=, bad ?limit=) becomes a clean 4xx/5xx JSON
        # response instead of an unhandled exception that drops the connection and
        # leaks a stack trace to the client.
        try:
            ok, bound_tenant, _scope = self._check_auth()
            if not ok:
                return
            self._route_get(bound_tenant)
        except _BadRequest as e:
            self._send(400, {"error": str(e)})
        except InvalidTenantId as e:
            self._send(400, {"error": str(e)})
        except Exception:  # noqa: BLE001 - never let a handler crash the thread
            self._send(500, {"error": "internal error"})

    def _route_get(self, bound_tenant: str | None = None):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        # F1 (2026-07-29 audit): every read is scoped to ?tenant_id=, defaulting
        # to "default" -- the pre-fix, single-tenant behavior -- when absent,
        # so an existing caller (WS-2 enrichment, WS-7 dashboard) that never
        # sends tenant_id keeps seeing exactly what it saw before this fix.
        # F1 follow-up (2026-07-30): a per-tenant-key caller (bound_tenant is
        # not None) has ITS OWN tenant_id forced here, silently overriding
        # whatever ?tenant_id= it asked for -- same convention as WS-3's
        # triage_api.py::_list_tenant_filter (scope narrowing, never a
        # rejection that would confirm/deny another tenant's existence).
        tenant_id = bound_tenant if bound_tenant is not None else q.get("tenant_id")
        if u.path == "/assets/resolve":
            if "ip" not in q or "at" not in q:
                return self._send(400, {"error": "ip and at required"})
            try:
                asset = STORE.resolve(q["ip"], q["at"], tenant_id=tenant_id)
            except InvalidTenantId:
                raise  # let do_GET's own handler report the real (tenant) problem
            except ValueError:
                # datetime.fromisoformat() on a malformed `at` -> 400, not a 500.
                raise _BadRequest("at must be an ISO-8601 timestamp")
            return self._send(200, asset) if asset else self._send(404, {"error": "not found"})
        if u.path == "/assets":
            return self._send(200, STORE.list(
                ip=q.get("ip"), mac=q.get("mac"), sector=q.get("sector"),
                status=q.get("status"), limit=_parse_limit(q.get("limit")),
                tenant_id=tenant_id))
        if u.path.startswith("/assets/"):
            # unquote: a raw path segment is never URL-decoded by urlparse
            # -- without this, a %-encoded MAC (e.g. "%3A" for ":") never
            # matches the decoded value stored by upsert(), silently
            # always 404ing instead of finding the real (tenant-scoped)
            # asset.
            mac = unquote(u.path[len("/assets/"):])
            asset = STORE.get(mac, tenant_id=tenant_id)
            return self._send(200, asset) if asset else self._send(404, {"error": "not found"})
        return self._send(404, {"error": "no such path"})

    def do_POST(self):
        try:
            ok, bound_tenant, scope = self._check_auth()
            if not ok:
                return
            if scope == SCOPE_READ_ONLY:
                self._send(403, {"error": "this key is read-only"})
                return
            self._route_post(bound_tenant)
        except _BadRequest as e:
            self._send(400, {"error": str(e)})
        except InvalidTenantId as e:
            self._send(400, {"error": str(e)})
        except Exception:  # noqa: BLE001 - never let a handler crash the thread
            self._send(500, {"error": "internal error"})

    def _route_post(self, bound_tenant: str | None = None):
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
            # F1 follow-up: a per-tenant-key caller (bound_tenant is not
            # None) has its own tenant_id forced into the body, silently
            # overriding whatever tenant_id it tried to upsert as -- a
            # scoped key must not be able to WRITE into another tenant's
            # inventory any more than it can read one.
            if bound_tenant is not None:
                body = {**body, "tenant_id": bound_tenant}
            asset, is_new_device = STORE.upsert_with_diff(body)
            if not asset:
                return self._send(400, {"error": "mac required"})
            # M7 Track Y: an alertable first-ever sighting for this tenant.
            # Additive field -- existing callers that ignore it are unaffected.
            # This is the SIGNAL only; nothing publishes it to `raw.events`
            # yet, because WS-6 is deliberately stdlib-only (see
            # requirements.txt: the redis dep for the bus is documented and
            # intentionally deferred). Until that lands, the
            # `ot_new_device_on_segment` rule has no live producer.
            return self._send(200, {**asset, "new_device": is_new_device})
        return self._send(404, {"error": "no such path"})


def serve(host="0.0.0.0", port=8000):
    warn_if_disabled("ws6-inventory", KEYSTORE)
    warn_missing_pepper()
    if not MIGRATED_TENANTS and KEYSTORE.count() > 0:
        # Nothing migrated on THIS boot, yet the keystore is non-empty --
        # it was already seeded by an earlier boot. If a legacy env var is
        # still set, editing it now does nothing; say so.
        warn_if_legacy_env_now_ignored()
    srv = ThreadingHTTPServer((host, port), Handler)
    # ws6 is a standalone service; its image does NOT bundle `shared`, so emit a
    # structured JSON log line inline rather than importing shared.log.
    import json as _json
    import time as _time
    if MIGRATED_TENANTS:
        # Never the key values -- see keystore.py::ensure_legacy_keys_migrated.
        print(_json.dumps({"level": "info", "service": "ws6-inventory",
                           "msg": "migrated legacy API key(s) into the hashed keystore",
                           "tenants": MIGRATED_TENANTS}), flush=True)
    print(_json.dumps({"ts": _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
                       "level": "info", "service": "ws6-inventory",
                       "msg": "listening", "url": f"http://{host}:{port}"}), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    serve(port=int(os.getenv("PORT", "8000")))
