"""WS-6 inventory API auth tests (v0.4 Track S1).

Auth is opt-in via FENGARDE_API_KEY. Zero-infra default (unset) must stay open
so existing contract tests/quickstart are unaffected; set it here to prove
the enforced path too.
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


def _post(port, path, body, api_key=None):
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-Api-Key"] = api_key
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}",
                                  data=json.dumps(body).encode(), headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def test_auth_disabled_by_default():
    os.environ.pop("FENGARDE_API_KEY", None)
    srv, port = _serve()
    try:
        code, _ = _get(port, "/assets")
        check(code == 200, f"auth disabled: unauthenticated GET should be 200, got {code}")
    finally:
        srv.shutdown(); srv.server_close()


def test_auth_enforced_when_key_set():
    os.environ["FENGARDE_API_KEY"] = "s3cr3t"
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
        os.environ.pop("FENGARDE_API_KEY", None)


def test_tenant_scoped_key_cannot_read_another_tenant():
    """F1 follow-up (2026-07-30, independent_review_of_fixes.md): before this,
    any caller holding the ONE shared key could enumerate every tenant just by
    guessing ?tenant_id= values -- the F1 data-model fix scoped storage/routes
    but left auth undifferentiated. A tenant-scoped key must not be able to
    read another tenant's data even when it explicitly asks for it."""
    os.environ["FENGARDE_API_KEYS"] = "acme:acme-key,globex:globex-key"
    try:
        srv, port = _serve()
        try:
            import app as ws6
            ws6.STORE.upsert({"mac": "10:00:00:00:00:01", "ip": "10.1.1.1",
                              "hostname": "acme-box", "seen_at": "2026-06-16T08:00:00+00:00",
                              "tenant_id": "acme"})
            ws6.STORE.upsert({"mac": "10:00:00:00:00:02", "ip": "10.1.1.2",
                              "hostname": "globex-box", "seen_at": "2026-06-16T08:00:00+00:00",
                              "tenant_id": "globex"})

            code, body = _get(port, "/assets", api_key="unknown-key")
            check(code == 401, f"a key matching no configured tenant should 401, got {code}")

            # acme's key, no ?tenant_id= at all -> its own tenant, not "default"
            code, body = _get(port, "/assets", api_key="acme-key")
            check(code == 200 and len(body) == 1 and body[0]["hostname"] == "acme-box",
                  f"acme's key with no tenant_id must see only acme's asset, got {body}")

            # acme's key EXPLICITLY asking for globex -> silently forced back to acme,
            # never globex's data and never a 403 that would confirm globex exists
            code, body = _get(port, "/assets?tenant_id=globex", api_key="acme-key")
            check(code == 200 and len(body) == 1 and body[0]["hostname"] == "acme-box",
                  f"acme's key asking for tenant_id=globex must still get only acme's data, got {body}")

            code, body = _get(port, "/assets/10:00:00:00:00:02?tenant_id=globex", api_key="acme-key")
            check(code == 404,
                  f"acme's key must not read globex's asset even by exact mac+tenant_id, got {code} {body}")
        finally:
            srv.shutdown(); srv.server_close()
    finally:
        os.environ.pop("FENGARDE_API_KEYS", None)


def test_tenant_scoped_key_cannot_write_another_tenant():
    """The write half of the same gap: a scoped key upserting with a spoofed
    tenant_id in the request body must land in ITS OWN tenant, not the one it
    named -- otherwise a compromised acme key could plant/overwrite data in
    globex's inventory."""
    os.environ["FENGARDE_API_KEYS"] = "acme:acme-key,globex:globex-key"
    try:
        srv, port = _serve()
        try:
            import app as ws6
            ws6.STORE = ws6.InventoryStore(":memory:")

            code, body = _post(port, "/assets/upsert",
                               {"mac": "10:00:00:00:00:09", "ip": "10.1.1.9",
                                "hostname": "spoofed", "seen_at": "2026-06-16T08:00:00+00:00",
                                "tenant_id": "globex"},
                               api_key="acme-key")
            check(code == 200, f"acme's upsert should succeed, got {code}")
            check(body["tenant_id"] == "acme",
                  f"acme's key must force tenant_id='acme' regardless of the body, got {body.get('tenant_id')}")

            globex_asset = ws6.STORE.get("10:00:00:00:00:09", tenant_id="globex")
            check(globex_asset is None,
                  f"globex's inventory must be untouched by acme's spoofed-tenant_id write, got {globex_asset}")
        finally:
            srv.shutdown(); srv.server_close()
    finally:
        os.environ.pop("FENGARDE_API_KEYS", None)


def test_admin_key_is_unrestricted():
    """The '*' entry is the escape hatch for an operator/ops-tool caller that
    legitimately needs cross-tenant access -- same trust level as the legacy
    single shared key, just under the new opt-in mechanism."""
    os.environ["FENGARDE_API_KEYS"] = "acme:acme-key,*:admin-key"
    try:
        srv, port = _serve()
        try:
            import app as ws6
            ws6.STORE.upsert({"mac": "10:00:00:00:00:05", "ip": "10.1.1.5",
                              "hostname": "globex-box", "seen_at": "2026-06-16T08:00:00+00:00",
                              "tenant_id": "globex"})
            code, body = _get(port, "/assets?tenant_id=globex", api_key="admin-key")
            check(code == 200 and any(a["hostname"] == "globex-box" for a in body),
                  f"admin key must be able to read any tenant it explicitly asks for, got {body}")
        finally:
            srv.shutdown(); srv.server_close()
    finally:
        os.environ.pop("FENGARDE_API_KEYS", None)


def test_legacy_key_unaffected_when_tenant_keys_unset():
    """FENGARDE_API_KEYS absent -> byte-for-byte the pre-existing single-key
    behavior (this is the same case test_auth_enforced_when_key_set already
    covers end-to-end; this test only pins that the tenant-scoped code path
    is a true no-op, not merely "also happens to pass")."""
    os.environ.pop("FENGARDE_API_KEYS", None)
    from authz import check_tenant_scoped_auth
    check(check_tenant_scoped_auth({}) is None,
          "check_tenant_scoped_auth must return None (inactive) when FENGARDE_API_KEYS is unset")


def main():
    test_auth_disabled_by_default()
    test_auth_enforced_when_key_set()
    test_tenant_scoped_key_cannot_read_another_tenant()
    test_tenant_scoped_key_cannot_write_another_tenant()
    test_admin_key_is_unrestricted()
    test_legacy_key_unaffected_when_tenant_keys_unset()
    if FAILS:
        print(f"[FAIL] ws6 auth: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WS-6 auth: opt-in X-Api-Key, default-open, enforced when set, "
          "per-tenant keys isolate read+write and reject unknown/cross-tenant use, "
          "admin key unrestricted")


if __name__ == "__main__":
    main()
