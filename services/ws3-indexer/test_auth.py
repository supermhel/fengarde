"""WS-3 triage API auth tests (v0.4 Track S1).

Same opt-in FENGARDE_API_KEY discipline as WS-6 (services/shared/authz.py).
"""
from __future__ import annotations

import json
import os
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from storage.memory import MemoryStore  # noqa: E402
import triage_api  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _serve(store):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), triage_api.make_handler(store))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _get(port, alert_id, api_key=None):
    headers = {"X-Api-Key": api_key} if api_key else {}
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/alerts/{alert_id}/triage", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:  # 20s: loaded-host flake
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def test_auth_disabled_by_default():
    os.environ.pop("FENGARDE_API_KEY", None)
    store = MemoryStore()
    store.index("alerts-2026.07.10", "a1", {"alert_id": "a1"})
    srv, port = _serve(store)
    try:
        code, _ = _get(port, "a1")
        check(code == 200, f"auth disabled: unauthenticated GET should be 200, got {code}")
    finally:
        srv.shutdown(); srv.server_close()


def test_auth_enforced_when_key_set():
    os.environ["FENGARDE_API_KEY"] = "s3cr3t"
    try:
        store = MemoryStore()
        store.index("alerts-2026.07.10", "a1", {"alert_id": "a1"})
        srv, port = _serve(store)
        try:
            code, _ = _get(port, "a1")
            check(code == 401, f"missing key should be 401, got {code}")
            code, _ = _get(port, "a1", api_key="wrong")
            check(code == 401, f"wrong key should be 401, got {code}")
            code, _ = _get(port, "a1", api_key="s3cr3t")
            check(code == 200, f"correct key should be 200, got {code}")
        finally:
            srv.shutdown(); srv.server_close()
    finally:
        os.environ.pop("FENGARDE_API_KEY", None)


def _get_check(port, api_key=None):
    """GET /auth/check -- the nginx auth_request guard (WP-6.1 option C)."""
    headers = {"X-Api-Key": api_key} if api_key else {}
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/auth/check", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def test_auth_check_default_open():
    os.environ.pop("FENGARDE_API_KEY", None)
    store = MemoryStore()
    srv, port = _serve(store)
    try:
        code, body = _get_check(port)
        check(code == 200, f"/auth/check auth-disabled should be 200, got {code}")
        check(body.get("ok") is True, "/auth/check must carry ok:true")
    finally:
        srv.shutdown(); srv.server_close()


def test_auth_check_key_gate():
    os.environ["FENGARDE_API_KEY"] = "s3cr3t"
    try:
        store = MemoryStore()
        srv, port = _serve(store)
        try:
            code, _ = _get_check(port)
            check(code == 401, f"/auth/check without key should be 401, got {code}")
            code, _ = _get_check(port, api_key="wrong")
            check(code == 401, f"/auth/check with wrong key should be 401, got {code}")
            code, _ = _get_check(port, api_key="s3cr3t")
            check(code == 200, f"/auth/check with correct key should be 200, got {code}")
        finally:
            srv.shutdown(); srv.server_close()
    finally:
        os.environ.pop("FENGARDE_API_KEY", None)


def test_auth_check_rbac_on_never_open():
    """PR #175 review: this file only covered RBAC off, so a fail-open
    `_principal` (anonymous accepted while RBAC is on) stayed green here.
    With RBAC on, /auth/check is sessions-or-key only, key set or not."""
    from shared.users import UserStore
    for key in (None, "s3cr3t"):
        os.environ.pop("FENGARDE_API_KEY", None)
        if key:
            os.environ["FENGARDE_API_KEY"] = key
        users = UserStore(":memory:")
        users.create_user("ana", "pw-ana-123", role="analyst", tenant_id="default")
        srv = ThreadingHTTPServer(("127.0.0.1", 0),
                                  triage_api.make_handler(MemoryStore(), users_db=users))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        port = srv.server_address[1]
        try:
            label = f"rbac on, key {'set' if key else 'unset'}"
            check(_get_check(port)[0] == 401, f"/auth/check anonymous ({label}) must be 401")
            req = urllib.request.Request(f"http://127.0.0.1:{port}/auth/check",
                                         headers={"Cookie": "fengarde_session=bogus"})
            try:
                urllib.request.urlopen(req, timeout=20)
                check(False, f"/auth/check bogus cookie ({label}) must be 401")
            except urllib.error.HTTPError as e:
                check(e.code == 401, f"/auth/check bogus cookie ({label}) -> {e.code}")
            login = urllib.request.Request(
                f"http://127.0.0.1:{port}/auth/login", method="POST",
                data=json.dumps({"username": "ana", "password": "pw-ana-123"}).encode(),
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(login, timeout=20) as resp:
                cookie = resp.headers.get("Set-Cookie", "").split(";")[0]
            req = urllib.request.Request(f"http://127.0.0.1:{port}/auth/check",
                                         headers={"Cookie": cookie})
            with urllib.request.urlopen(req, timeout=20) as resp:
                check(resp.status == 200, f"/auth/check valid session ({label}) -> {resp.status}")
        finally:
            srv.shutdown(); srv.server_close()
            os.environ.pop("FENGARDE_API_KEY", None)


def main():
    test_auth_disabled_by_default()
    test_auth_enforced_when_key_set()
    test_auth_check_default_open()
    test_auth_check_key_gate()
    test_auth_check_rbac_on_never_open()
    if FAILS:
        print(f"[FAIL] ws3 auth: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WS-3 auth: opt-in X-Api-Key, default-open, enforced when set")


if __name__ == "__main__":
    main()
