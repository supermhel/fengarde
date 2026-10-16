"""POST /inventory/assets (inventory_write.py): admin-only manual device add.

Real HTTP against a real WS-3 handler, with a tiny fake WS-6 (local HTTP server
standing in for POST /assets/upsert, reached via INVENTORY_URL).

Run: python services/ws3-indexer/test_inventory_write.py
"""
from __future__ import annotations

import json
import os
import socket
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from storage.memory import MemoryStore  # noqa: E402
from shared.users import UserStore  # noqa: E402
import inventory_write  # noqa: E402
import triage_api  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


class _FakeWS6(BaseHTTPRequestHandler):
    received: list = []
    reject_with_400 = False

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        type(self).received.append((self.path, body))
        if type(self).reject_with_400:
            payload, code = {"error": "mac collides with a retired asset"}, 400
        else:
            payload, code = {**body, "status": "active", "new_device": True}, 200
        raw = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *_):
        pass


class _Audit:
    def __init__(self):
        self.entries: list[dict] = []

    def record(self, event, actor, tenant_id=None, detail=None):
        self.entries.append({"event": event, "actor": actor, "tenant_id": tenant_id, "detail": detail})

    def recent(self, limit=None):
        return list(self.entries)


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _request(port, method, path, body=None, cookie=None, csrf=None):
    headers = {"Content-Type": "application/json"}
    if cookie:
        headers["Cookie"] = cookie
    if csrf is not None:
        headers["X-CSRF-Token"] = csrf
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}",
                                 data=json.dumps(body).encode() if body is not None else None,
                                 method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def _login(port, username, password):
    req = urllib.request.Request(f"http://127.0.0.1:{port}/auth/login", method="POST",
                                 data=json.dumps({"username": username, "password": password}).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.headers["Set-Cookie"].split(";")[0], json.loads(resp.read().decode())["csrf_token"]


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_normalize_mac():
    for raw in ("aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", "aabbccddeeff", " Aa:bB:cc:DD:ee:FF "):
        check(inventory_write.normalize_mac(raw) == "AA:BB:CC:DD:EE:FF", f"normalize_mac({raw!r}) wrong")
    for raw in ("aa:bb-cc:dd:ee:ff", "aa:bb:cc:dd:ee", "gg:bb:cc:dd:ee:ff", 42, None, ""):
        check(inventory_write.normalize_mac(raw) is None, f"normalize_mac({raw!r}) must reject")


def test_add_device_over_http():
    ws6, ws6_port = _serve(_FakeWS6)
    users = UserStore(":memory:")
    users.create_user("root", "admin-password-1", role="admin", tenant_id="default")
    users.create_user("ana", "analyst-password-1", role="analyst", tenant_id="acme")
    audit = _Audit()
    srv, port = _serve(triage_api.make_handler(MemoryStore(), users_db=users, audit_log=audit))
    os.environ["INVENTORY_URL"] = f"http://127.0.0.1:{ws6_port}"
    try:
        ck, cs = _login(port, "root", "admin-password-1")
        body = {"mac": "aa-bb-cc-dd-ee-01", "hostname": "plc-01", "ip": "10.0.0.5",
                "sector": "datacenter", "type": "plc"}
        code, _ = _request(port, "POST", "/inventory/assets", body, cookie=ck)
        check(code == 403, f"no X-CSRF-Token must 403, got {code}")
        code, resp = _request(port, "POST", "/inventory/assets", body, cookie=ck, csrf=cs)
        check(code == 200 and resp.get("new_device") is True, f"admin add must 200, got {code} {resp}")
        sent = _FakeWS6.received[-1] if _FakeWS6.received else (None, {})
        check(sent[0] == "/assets/upsert" and sent[1].get("mac") == "AA:BB:CC:DD:EE:01"
              and sent[1].get("tenant_id") == "default" and sent[1].get("sector") == "datacenter",
              f"WS-6 must get the normalised MAC + admin's tenant, got {sent}")
        ev = [e for e in audit.entries if e["event"] == "inventory_asset_upsert"]
        check(len(ev) == 1 and ev[0]["actor"] == "root" and ev[0]["detail"]["mac"] == "AA:BB:CC:DD:EE:01",
              f"one inventory_asset_upsert audit entry expected, got {ev}")

        for bad, why in (({**body, "owner": "x"}, "unknown field"), ({**body, "mac": "nope"}, "bad mac"),
                         ({**body, "ip": "999.1.1.1"}, "bad ip"), ({**body, "sector": "ot"}, "bad sector"),
                         ({"hostname": "x"}, "missing mac")):
            code, _ = _request(port, "POST", "/inventory/assets", bad, cookie=ck, csrf=cs)
            check(code == 400, f"{why} must 400, got {code}")

        ac, acs = _login(port, "ana", "analyst-password-1")
        n_before = len(_FakeWS6.received)
        code, _ = _request(port, "POST", "/inventory/assets", body, cookie=ac, csrf=acs)
        check(code == 404 and len(_FakeWS6.received) == n_before,
              f"analyst must be refused (404) without reaching WS-6, got {code}")

        _FakeWS6.reject_with_400 = True
        code, resp = _request(port, "POST", "/inventory/assets", body, cookie=ck, csrf=cs)
        check(code == 400 and "retired" in resp.get("error", ""), f"WS-6 400 must surface as 400 + reason, got {code} {resp}")
        _FakeWS6.reject_with_400 = False

        os.environ["INVENTORY_URL"] = f"http://127.0.0.1:{_free_port()}"
        code, resp = _request(port, "POST", "/inventory/assets", body, cookie=ck, csrf=cs)
        check(code == 502 and resp.get("error") == "inventory service unreachable",
              f"WS-6 down must 502, got {code} {resp}")
        check(len([e for e in audit.entries if e["event"] == "inventory_asset_upsert"]) == 1,
              "failed upserts must not be audited as successes")
    finally:
        os.environ.pop("INVENTORY_URL", None)
        srv.shutdown(); srv.server_close()
        ws6.shutdown(); ws6.server_close()


def test_rbac_off_unroutable():
    srv, port = _serve(triage_api.make_handler(MemoryStore()))
    try:
        code, body = _request(port, "POST", "/inventory/assets", {"mac": "aa:bb:cc:dd:ee:ff"})
        check(code == 404 and body.get("error") == "no such path",
              f"RBAC off: POST /inventory/assets must be unroutable, got {code} {body}")
    finally:
        srv.shutdown(); srv.server_close()


def main():
    test_normalize_mac()
    test_add_device_over_http()
    test_rbac_off_unroutable()
    if FAILS:
        print(f"[FAIL] inventory add-device: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] POST /inventory/assets: admin-only (analyst 404, never reaches WS-6), CSRF required, "
          "MAC normalised to AA:BB:.. before WS-6, strict 400s (unknown field/mac/ip/sector), WS-6 400 "
          "relayed, WS-6 down -> 502, success audited once, unroutable with RBAC off -- real HTTP + fake WS-6")


if __name__ == "__main__":
    main()
