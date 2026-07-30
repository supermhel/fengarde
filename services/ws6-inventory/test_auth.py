"""WS-6 inventory API auth tests (HTTP layer).

Auth is opt-in: an empty keystore (services/ws6-inventory/keystore.py) means
every request is allowed, the zero-infra/quickstart default. Once any key is
provisioned (directly via TenantKeyStore.provision, or auto-migrated from a
legacy FENGARDE_API_KEY/FENGARDE_API_KEYS env var -- see keystore.py's
ensure_legacy_keys_migrated), every request must present a key that verifies
against it. See test_keystore.py for store-level (non-HTTP) coverage of the
hashing/rotation/migration mechanics themselves; this file proves the same
guarantees hold over real HTTP requests against the actual Handler.
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
    """Fresh STORE + fresh, EMPTY KEYSTORE for every test -- state from one
    test (provisioned keys, asset rows) must never leak into the next."""
    import app as ws6
    ws6.STORE = ws6.InventoryStore(":memory:")
    ws6.KEYSTORE = ws6.TenantKeyStore(":memory:")
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
    srv, port = _serve()
    try:
        code, _ = _get(port, "/assets")
        check(code == 200, f"empty keystore: unauthenticated GET should be 200, got {code}")
    finally:
        srv.shutdown(); srv.server_close()


def test_auth_enforced_once_a_key_is_provisioned():
    srv, port = _serve()
    try:
        import app as ws6
        ws6.KEYSTORE.provision("default", "s3cr3t")

        code, _ = _get(port, "/assets")
        check(code == 401, f"missing key should be 401, got {code}")
        code, _ = _get(port, "/assets", api_key="wrong")
        check(code == 401, f"wrong key should be 401, got {code}")
        code, _ = _get(port, "/assets", api_key="s3cr3t")
        check(code == 200, f"correct key should be 200, got {code}")
    finally:
        srv.shutdown(); srv.server_close()


def test_tenant_scoped_key_cannot_read_another_tenant():
    """The core new guarantee: a caller holding tenant A's key must not be
    able to read tenant B's data, even when it explicitly asks for tenant B
    by id -- request is silently re-scoped to A, never rejected in a way
    that would confirm/deny B's existence."""
    srv, port = _serve()
    try:
        import app as ws6
        ws6.KEYSTORE.provision("acme", "acme-key")
        ws6.KEYSTORE.provision("globex", "globex-key")
        ws6.STORE.upsert({"mac": "10:00:00:00:00:01", "ip": "10.1.1.1",
                          "hostname": "acme-box", "seen_at": "2026-06-16T08:00:00+00:00",
                          "tenant_id": "acme"})
        ws6.STORE.upsert({"mac": "10:00:00:00:00:02", "ip": "10.1.1.2",
                          "hostname": "globex-box", "seen_at": "2026-06-16T08:00:00+00:00",
                          "tenant_id": "globex"})

        code, body = _get(port, "/assets", api_key="unknown-key")
        check(code == 401, f"a key matching no provisioned tenant should 401, got {code}")

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


def test_tenant_scoped_key_cannot_write_another_tenant():
    """The write half of the same guarantee: a scoped key upserting with a
    spoofed tenant_id in the request body must land in ITS OWN tenant, not
    the one it named -- otherwise a compromised acme key could plant/
    overwrite data in globex's inventory."""
    srv, port = _serve()
    try:
        import app as ws6
        ws6.KEYSTORE.provision("acme", "acme-key")
        ws6.KEYSTORE.provision("globex", "globex-key")

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


def test_admin_key_is_unrestricted():
    """The '*' entry is the escape hatch for an operator/ops-tool caller
    that legitimately needs cross-tenant access -- same trust level as the
    old single shared key."""
    srv, port = _serve()
    try:
        import app as ws6
        ws6.KEYSTORE.provision("*", "admin-key")
        ws6.STORE.upsert({"mac": "10:00:00:00:00:05", "ip": "10.1.1.5",
                          "hostname": "globex-box", "seen_at": "2026-06-16T08:00:00+00:00",
                          "tenant_id": "globex"})
        code, body = _get(port, "/assets?tenant_id=globex", api_key="admin-key")
        check(code == 200 and any(a["hostname"] == "globex-box" for a in body),
              f"admin key must be able to read any tenant it explicitly asks for, got {body}")
    finally:
        srv.shutdown(); srv.server_close()


def test_rotated_key_stops_working_over_http():
    srv, port = _serve()
    try:
        import app as ws6
        ws6.KEYSTORE.provision("acme", "old-key")
        code, _ = _get(port, "/assets", api_key="old-key")
        check(code == 200, "the original key must work before rotation")

        ws6.KEYSTORE.provision("acme", "new-key")
        code, _ = _get(port, "/assets", api_key="old-key")
        check(code == 401, f"the OLD key must 401 immediately after rotation, got {code}")
        code, _ = _get(port, "/assets", api_key="new-key")
        check(code == 200, f"the NEW key must work, got {code}")
    finally:
        srv.shutdown(); srv.server_close()


def test_legacy_single_key_migrates_and_keeps_working_over_http():
    """An operator upgrading from the original single FENGARDE_API_KEY must
    keep using that exact value with zero reconfiguration -- proven here by
    actually running the migration function against a live server, not just
    the store-level unit test in test_keystore.py."""
    os.environ["FENGARDE_API_KEY"] = "the-operators-original-key"
    try:
        srv, port = _serve()
        try:
            import app as ws6
            migrated = ws6.ensure_legacy_keys_migrated(ws6.KEYSTORE)
            check(migrated == ["default"], f"expected migration of 'default' only, got {migrated}")

            code, _ = _get(port, "/assets", api_key="the-operators-original-key")
            check(code == 200, f"the operator's existing key must keep working after migration, got {code}")
            code, _ = _get(port, "/assets", api_key="some-other-guess")
            check(code == 401, f"a different key must still be rejected, got {code}")
        finally:
            srv.shutdown(); srv.server_close()
    finally:
        os.environ.pop("FENGARDE_API_KEY", None)


def main():
    test_auth_disabled_by_default()
    test_auth_enforced_once_a_key_is_provisioned()
    test_tenant_scoped_key_cannot_read_another_tenant()
    test_tenant_scoped_key_cannot_write_another_tenant()
    test_admin_key_is_unrestricted()
    test_rotated_key_stops_working_over_http()
    test_legacy_single_key_migrates_and_keeps_working_over_http()
    if FAILS:
        print(f"[FAIL] ws6 auth: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WS-6 auth: disabled by default, enforced once a key is provisioned, "
          "per-tenant keys isolate read+write, admin key unrestricted, rotation takes "
          "effect immediately, legacy single-key migration keeps existing callers working "
          "-- all over real HTTP")


if __name__ == "__main__":
    main()
