"""WS-6 inventory API auth tests (v0.4 Track S1).

Auth is opt-in via ARGIEM_API_KEY. Zero-infra default (unset) must stay open
so existing contract tests/quickstart are unaffected; set it here to prove
the enforced path too.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _serve():
    import app as ws6
    srv = ThreadingHTTPServer(("127.0.0.1", 0), ws6.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _get(port, path, api_key=None):
    headers = {"X-Api-Key": api_key} if api_key else {}
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def test_auth_disabled_by_default():
    os.environ.pop("ARGIEM_API_KEY", None)
    srv, port = _serve()
    try:
        code, _ = _get(port, "/assets")
        check(code == 200, f"auth disabled: unauthenticated GET should be 200, got {code}")
    finally:
        srv.shutdown(); srv.server_close()


def test_auth_enforced_when_key_set():
    os.environ["ARGIEM_API_KEY"] = "s3cr3t"
    try:
        srv, port = _serve()
        try:
            code, body = _get(port, "/assets")
            check(code == 401, f"missing key should be 401, got {code}")
            code, body = _get(port, "/assets", api_key="wrong")
            check(code == 401, f"wrong key should be 401, got {code}")
            code, body = _get(port, "/assets", api_key="s3cr3t")
            check(code == 200, f"correct key should be 200, got {code}")
        finally:
            srv.shutdown(); srv.server_close()
    finally:
        os.environ.pop("ARGIEM_API_KEY", None)


def main():
    test_auth_disabled_by_default()
    test_auth_enforced_when_key_set()
    if FAILS:
        print(f"[FAIL] ws6 auth: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WS-6 auth: opt-in X-Api-Key, default-open, enforced when set")


if __name__ == "__main__":
    main()
