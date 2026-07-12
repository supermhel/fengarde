"""WS-3 triage API auth tests (v0.4 Track S1).

Same opt-in ARGIEM_API_KEY discipline as WS-6 (services/shared/authz.py).
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
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def test_auth_disabled_by_default():
    os.environ.pop("ARGIEM_API_KEY", None)
    store = MemoryStore()
    store.index("alerts-2026.07.10", "a1", {"alert_id": "a1"})
    srv, port = _serve(store)
    try:
        code, _ = _get(port, "a1")
        check(code == 200, f"auth disabled: unauthenticated GET should be 200, got {code}")
    finally:
        srv.shutdown(); srv.server_close()


def test_auth_enforced_when_key_set():
    os.environ["ARGIEM_API_KEY"] = "s3cr3t"
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
        os.environ.pop("ARGIEM_API_KEY", None)


def main():
    test_auth_disabled_by_default()
    test_auth_enforced_when_key_set()
    if FAILS:
        print(f"[FAIL] ws3 auth: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WS-3 auth: opt-in X-Api-Key, default-open, enforced when set")


if __name__ == "__main__":
    main()
