"""WS-6 inventory API auth tests (HTTP layer).

Auth is opt-in: an empty keystore (services/ws6-inventory/keystore.py) means
every request is allowed, the zero-infra/quickstart default. Once any key is
provisioned (directly via TenantKeyStore.provision, or auto-migrated from a
legacy FENGARDE_API_KEY/FENGARDE_API_KEYS env var), every request must present
a key that verifies against it. See test_keystore.py for store-level coverage
of the hashing/rotation/scope/migration mechanics; this file proves the same
guarantees hold over real HTTP requests against the actual Handler, including
scope enforcement on writes and URL-decoded MAC lookups.
"""
from __future__ import annotations

import json
import os
import subprocess
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
    test (provisioned keys, asset rows) must never leak into the next. Also
    resets the module-level `_AUTH_WAS_ENABLED` latch and the auth-fail
    counters, so each test starts from a clean, never-enabled auth state."""
    import app as ws6
    ws6.STORE = ws6.InventoryStore(":memory:")
    ws6.KEYSTORE = ws6.TenantKeyStore(":memory:")
    ws6._AUTH_WAS_ENABLED = False
    ws6._auth_fail_calls = 0
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

        code, body = _get(port, "/assets", api_key="acme-key")
        check(code == 200 and len(body) == 1 and body[0]["hostname"] == "acme-box",
              f"acme's key with no tenant_id must see only acme's asset, got {body}")

        code, body = _get(port, "/assets?tenant_id=globex", api_key="acme-key")
        check(code == 200 and len(body) == 1 and body[0]["hostname"] == "acme-box",
              f"acme's key asking for tenant_id=globex must still get only acme's data, got {body}")

        code, body = _get(port, "/assets/10:00:00:00:00:02?tenant_id=globex", api_key="acme-key")
        check(code == 404,
              f"acme's key must not read globex's asset even by exact mac+tenant_id, got {code} {body}")
    finally:
        srv.shutdown(); srv.server_close()


def test_url_encoded_mac_lookup_works_within_own_tenant():
    """A MAC path segment is %-encoded by clients (':' -> '%3A'); the route
    must URL-decode it so a scoped key can fetch its OWN asset by MAC.
    Before the decode fix this always 404'd (encoded string never matched
    the stored decoded MAC)."""
    srv, port = _serve()
    try:
        import app as ws6
        ws6.KEYSTORE.provision("acme", "acme-key")
        ws6.STORE.upsert({"mac": "AA:BB:CC:00:11:22", "ip": "10.1.1.7",
                          "hostname": "acme-encoded", "seen_at": "2026-06-16T08:00:00+00:00",
                          "tenant_id": "acme"})
        code, body = _get(port, "/assets/AA%3ABB%3ACC%3A00%3A11%3A22", api_key="acme-key")
        check(code == 200 and body.get("hostname") == "acme-encoded",
              f"a %-encoded MAC must decode and resolve to the stored asset, got {code} {body}")
    finally:
        srv.shutdown(); srv.server_close()


def test_tenant_scoped_key_cannot_write_another_tenant():
    """A scoped key upserting with a spoofed tenant_id in the request body
    must land in ITS OWN tenant, not the one it named."""
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


def test_read_only_key_can_read_but_not_write():
    """A read_only-scoped key must GET fine but be rejected (403) on any
    write, before it can touch the store -- a leaked read key must not be
    able to poison inventory (which feeds enrichment/detection)."""
    srv, port = _serve()
    try:
        import app as ws6
        ws6.KEYSTORE.provision("acme", "ro-key", scope=ws6.SCOPE_READ_ONLY)

        code, _ = _get(port, "/assets", api_key="ro-key")
        check(code == 200, f"a read_only key must still be able to GET, got {code}")

        code, body = _post(port, "/assets/upsert",
                           {"mac": "10:00:00:00:00:11", "ip": "10.1.1.11",
                            "seen_at": "2026-06-16T08:00:00+00:00"},
                           api_key="ro-key")
        check(code == 403, f"a read_only key must be 403 on a write, got {code} {body}")
        check(ws6.STORE.get("10:00:00:00:00:11", tenant_id="acme") is None,
              "a read_only key's rejected write must not have reached the store")
    finally:
        srv.shutdown(); srv.server_close()


def test_admin_key_is_unrestricted():
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


def test_keys_route_never_leaks_material_and_is_tenant_scoped():
    """2026-08-20: GET /keys had no HTTP route at all (CLI-only via
    manage_keys.py) -- the dashboard couldn't show key metadata even though
    TenantKeyStore.list_keys() has always computed it. Proves: (1) it never
    returns key material, hashed or otherwise; (2) a tenant-scoped key sees
    only its own tenant's keys, same isolation every other GET route holds."""
    srv, port = _serve()
    try:
        import app as ws6
        ws6.KEYSTORE.provision("acme", "acme-key")
        ws6.KEYSTORE.provision("globex", "globex-key")

        code, body = _get(port, "/keys", api_key="acme-key")
        check(code == 200, f"a provisioned key should be able to list keys, got {code}")
        keys = body["keys"]
        check(len(keys) == 1 and keys[0]["tenant_id"] == "acme",
              f"acme's key must see only acme's own key metadata, got {keys}")
        check(set(keys[0]) == {"key_id", "tenant_id", "scope", "source", "created_at", "last_used_at"},
              f"unexpected key metadata shape (material leak?): {set(keys[0])}")
        check("acme-key" not in json.dumps(keys) and "globex-key" not in json.dumps(keys),
              "raw key material must never appear in the /keys response")

        code, body = _get(port, "/keys", api_key="globex-key")
        check(code == 200 and len(body["keys"]) == 1 and body["keys"][0]["tenant_id"] == "globex",
              f"globex's key must see only globex's own key, got {body}")
    finally:
        srv.shutdown(); srv.server_close()


def test_keys_route_unrestricted_for_admin_and_when_auth_disabled():
    srv, port = _serve()
    try:
        import app as ws6
        code, body = _get(port, "/keys")
        check(code == 200 and body["keys"] == [],
              f"auth disabled (empty keystore): /keys should be 200 with an empty list, got {code} {body}")

        ws6.KEYSTORE.provision("acme", "acme-key")
        ws6.KEYSTORE.provision("*", "admin-key")
        code, body = _get(port, "/keys", api_key="admin-key")
        check(code == 200 and len(body["keys"]) == 2,
              f"the unrestricted '*' key must see every tenant's keys, got {body}")
    finally:
        srv.shutdown(); srv.server_close()


def test_rotation_both_keys_live_then_old_revoked_over_http():
    srv, port = _serve()
    try:
        import app as ws6
        old_id = ws6.KEYSTORE.provision("acme", "old-key")
        ws6.KEYSTORE.provision("acme", "new-key")
        check(_get(port, "/assets", api_key="old-key")[0] == 200, "old key live during rotation")
        check(_get(port, "/assets", api_key="new-key")[0] == 200, "new key live during rotation")

        ws6.KEYSTORE.revoke(old_id)
        check(_get(port, "/assets", api_key="old-key")[0] == 401, "revoked old key must 401")
        check(_get(port, "/assets", api_key="new-key")[0] == 200, "surviving new key must still work")
    finally:
        srv.shutdown(); srv.server_close()


def test_legacy_single_key_migrates_and_keeps_working_over_http():
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


# -- Gap-hunt finding (2026-08-23): require_auth_or_die -----------------------
# shared/authz.py::require_auth_or_die's own docstring claimed to cover
# "WS-3/WS-6," but ws6-inventory never called it -- FENGARDE_REQUIRE_AUTH=1
# refused to boot ws3-indexer open, but ws6-inventory booted open regardless
# with nothing louder than a log line. authz.py (this service's OWN module,
# not shared/authz.py) now has its own require_auth_or_die wired into
# app.py::serve(). Subprocess-based since it calls sys.exit(1), same
# pattern as ws3-indexer/test_fix_security.py's equivalent tests.

def test_require_auth_or_die_empty_keystore_exits_1():
    """R2-#6: this previously drove a DIRECT call to require_auth_or_die and
    asserted rc==1 only -- not mutation-sound, since a mutation that removed
    the call from serve() would still pass. Now it drives the real serve()
    entry point (same discipline as
    test_serve_actually_calls_require_auth_or_die_before_listening) and
    asserts BOTH the exit code AND that the process dies BEFORE ever logging
    "listening" -- i.e. the gate really stops the service, not just the
    helper."""
    env = dict(os.environ)
    env.pop("FENGARDE_API_KEY", None)
    env.pop("FENGARDE_API_KEYS", None)
    env.update({"FENGARDE_REQUIRE_AUTH": "1", "INVENTORY_DB": ":memory:",
                "INVENTORY_KEYSTORE_DB": ":memory:"})
    code = "from app import serve; serve(host='127.0.0.1', port=0)"
    try:
        proc = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True,
                              text=True, cwd=str(HERE), timeout=5)
    except subprocess.TimeoutExpired:
        check(False, "serve() did not exit with an empty keystore + REQUIRE_AUTH=1 -- "
                     "it reached serve_forever() instead of dying (the gate regressed)")
        return
    check(proc.returncode == 1,
          f"require_auth_or_die must exit 1 with an empty keystore, got {proc.returncode} "
          f"stderr={proc.stderr!r}")
    check('"msg": "listening"' not in proc.stdout,
          f'serve() must die BEFORE logging "listening" -- got stdout={proc.stdout!r}')


def test_require_auth_or_die_noop_without_env():
    env = dict(os.environ)
    env.pop("FENGARDE_REQUIRE_AUTH", None)
    code = ("import authz; from app import KEYSTORE; "
            "authz.require_auth_or_die('ws6-inventory', KEYSTORE); print('ok')")
    proc = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True,
                          text=True, cwd=str(HERE))
    check(proc.returncode == 0 and "ok" in proc.stdout,
          f"require_auth_or_die must be a no-op when FENGARDE_REQUIRE_AUTH is unset, "
          f"got rc={proc.returncode} out={proc.stdout!r} err={proc.stderr!r}")


def test_require_auth_or_die_provisioned_keystore_is_noop():
    """A REQUIRE_AUTH=1 deployment with a real key provisioned must boot
    normally -- this gate only refuses an EMPTY keystore, never a
    populated one."""
    env = dict(os.environ)
    env.pop("FENGARDE_API_KEY", None)
    env.pop("FENGARDE_API_KEYS", None)
    env.update({"FENGARDE_REQUIRE_AUTH": "1",
                "INVENTORY_DB": ":memory:", "KEYSTORE_DB": ":memory:"})
    code = ("import authz; from app import KEYSTORE; "
            "KEYSTORE.provision('acme', 'a-real-key-123'); "
            "authz.require_auth_or_die('ws6-inventory', KEYSTORE); print('ok')")
    proc = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True,
                          text=True, cwd=str(HERE))
    check(proc.returncode == 0 and "ok" in proc.stdout,
          f"require_auth_or_die must not block a deployment with a provisioned key, "
          f"got rc={proc.returncode} out={proc.stdout!r} err={proc.stderr!r}")


def test_serve_actually_calls_require_auth_or_die_before_listening():
    """Drives the REAL `serve()` entry point, not a direct call to
    `require_auth_or_die` -- proves the wiring itself, same discipline as
    WS-3's `test_normalized_topic_is_wired_create_only`. If a future edit
    removes the call from `serve()`, the direct-call tests above would keep
    passing while this one catches the regression: the process must exit(1)
    BEFORE ever reaching `srv.serve_forever()` (never prints "listening")."""
    env = dict(os.environ)
    env.pop("FENGARDE_API_KEY", None)
    env.pop("FENGARDE_API_KEYS", None)
    env.update({"FENGARDE_REQUIRE_AUTH": "1", "INVENTORY_DB": ":memory:",
                "KEYSTORE_DB": ":memory:"})
    code = "from app import serve; serve(host='127.0.0.1', port=0)"
    try:
        proc = subprocess.run([sys.executable, "-c", code], env=env,
                              capture_output=True, text=True, cwd=str(HERE), timeout=5)
    except subprocess.TimeoutExpired:
        check(False, "serve() did not exit -- it reached serve_forever() instead of "
                     "dying on require_auth_or_die (the wiring regressed)")
        return
    check(proc.returncode == 1,
          f"serve() with an empty keystore + REQUIRE_AUTH=1 must exit 1, got {proc.returncode}")
    check('"msg": "listening"' not in proc.stdout,
          f"serve() must die BEFORE logging \"listening\" -- got stdout={proc.stdout!r}")


def test_failed_auth_is_logged_and_rate_limited():
    """Gap-hunt #3: failed API-key attempts used to produce zero telemetry and
    were never rate-limited. Now: a monotonic slow-fail counter, a log line per
    failure, and a small per-IP rate limit (over budget -> 429)."""
    srv, port = _serve()
    try:
        import app as ws6
        ws6.KEYSTORE.provision("acme", "correct-key")
        # Deterministic test: clear the shared per-IP window state (earlier
        # tests in this same process fail auth from loopback too) and shrink
        # the budget far below the default 25.
        with ws6._auth_fail_lock:
            ws6._auth_fail_by_ip.clear()
            ws6._auth_fail_total = 0
        old_limit = ws6._AUTH_FAIL_LIMIT
        ws6._AUTH_FAIL_LIMIT = 3
        try:
            codes = [_get(port, "/assets", api_key="wrong-key")[0] for _ in range(5)]
            check(codes == [401, 401, 401, 429, 429],
                  f"per-IP rate limit should 401 until the budget then 429, got {codes}")
        finally:
            ws6._AUTH_FAIL_LIMIT = old_limit
        check(ws6.auth_fail_total() == 5,
              f"the slow-fail counter must record all 5 failures, got {ws6.auth_fail_total()}")
        # The limiter must never lock out a legitimate key.
        check(_get(port, "/assets", api_key="correct-key")[0] == 200,
              "a correct key must still succeed after rate-limited failures")
        # The counter is monotonic: another failure keeps counting.
        _get(port, "/assets", api_key="wrong-key")
        check(ws6.auth_fail_total() == 6,
              f"the slow-fail counter must keep counting, got {ws6.auth_fail_total()}")
    finally:
        srv.shutdown(); srv.server_close()


def test_revoking_last_key_does_not_reopen_service():
    """R2-#4: `_check_auth` used to treat KEYSTORE.count()==0 at REQUEST time
    as "auth disabled", so revoking the LAST key mid-session silently reopened
    the service to unauthenticated traffic. With the `_AUTH_WAS_ENABLED` latch,
    once auth has EVER been enabled (a key was provisioned/observed) it stays
    on for the process lifetime -- an empty keystore must still 401 every
    request instead of serving open."""
    srv, port = _serve()
    try:
        import app as ws6
        # Baseline: empty keystore + never-enabled latch = auth disabled.
        check(_get(port, "/assets")[0] == 200,
              "baseline: a never-enabled, empty keystore must be auth-disabled")
        key_id = ws6.KEYSTORE.provision("acme", "the-only-key")
        check(_get(port, "/assets")[0] == 401,
              "provisioning a key must enable auth (401 without a key)")
        check(_get(port, "/assets", api_key="the-only-key")[0] == 200,
              "the provisioned key itself must work")
        ws6.KEYSTORE.revoke(key_id)
        check(ws6.KEYSTORE.count() == 0,
              "sanity: the keystore is now empty after revoking the last key")
        code, _ = _get(port, "/assets")
        check(code == 401,
              f"revoking the LAST key must NOT reopen the service, got {code}")
        code, _ = _get(port, "/assets", api_key="the-only-key")
        check(code == 401,
              f"the revoked key must still be rejected, got {code}")
    finally:
        srv.shutdown(); srv.server_close()


def test_auth_fail_by_ip_is_swept_periodically():
    """NEW-hunt read-plane #4: `_auth_fail_by_ip` buckets (one per failing IP)
    were pruned ONLY on the next failure from the SAME IP -- a "deceased" IP's
    bucket (and its stale timestamps) lingered in the dict for the process
    lifetime: unbounded memory, one entry per distinct hostile IP ever seen. A
    periodic sweep (mirroring ws3-indexer/triage_api.py::_rate_buckets) now
    drops stale buckets every _AUTH_FAIL_SWEEP_EVERY-th failure."""
    srv, port = _serve()
    try:
        import app as ws6
        ws6.KEYSTORE.provision("acme", "correct-key")
        with ws6._auth_fail_lock:
            ws6._auth_fail_by_ip.clear()
            ws6._auth_fail_total = 0
            ws6._auth_fail_calls = 0
        old_every, old_stale = ws6._AUTH_FAIL_SWEEP_EVERY, ws6._AUTH_FAIL_STALE_S
        ws6._AUTH_FAIL_SWEEP_EVERY = 2  # sweep on every 2nd failure
        ws6._AUTH_FAIL_STALE_S = 0      # any recorded hit is immediately stale
        try:
            _get(port, "/assets", api_key="wrong-key")  # failure 1: records the bucket
            with ws6._auth_fail_lock:
                check(len(ws6._auth_fail_by_ip) == 1,
                      "a failed attempt must record/stage its IP bucket")
            _get(port, "/assets", api_key="wrong-key")  # failure 2: triggers the sweep
            with ws6._auth_fail_lock:
                check(len(ws6._auth_fail_by_ip) == 0,
                      f"the periodic sweep must drop the stale IP bucket, got {ws6._auth_fail_by_ip}")
        finally:
            ws6._AUTH_FAIL_SWEEP_EVERY = old_every
            ws6._AUTH_FAIL_STALE_S = old_stale
    finally:
        srv.shutdown(); srv.server_close()


def test_inventory_read_accepts_caller_presented_key_like_nginx_forwards():
    """NEW-hunt read-plane #2 (ws6 half): nginx's /api/inventory/ proxy now
    forwards the browser's caller-PRESENTED X-Api-Key upstream
    ($http_x_api_key; see ws7-dashboard/templates/default.conf.template). ws6
    must accept exactly that header against its keystore -- the same contract
    every other proxied route relies on. Pins the common deployment where the
    browser's FENGARDE_API_KEY migrated into the ws6 keystore
    (ensure_legacy_keys_migrated), so enabling ws6 auth must NOT blank the
    dashboard's Inventory reads again."""
    srv, port = _serve()
    try:
        import app as ws6
        # ensure_legacy_keys_migrated provisions FENGARDE_API_KEY under
        # 'default' -- simulate the outcome of that migration + a first read.
        ws6.KEYSTORE.provision("default", "the-browser-key",
                               source="migrated_legacy_shared_key")
        code, body = _get(port, "/assets", api_key="the-browser-key")
        check(code == 200,
              f"a caller-presented key that verifies against the keystore must be accepted (as nginx now forwards it), got {code} {body}")
        code, _ = _get(port, "/assets")
        check(code == 401,
              f"with auth enabled, a missing key must still be 401 (nginx forwards an empty X-Api-Key), got {code}")
    finally:
        srv.shutdown(); srv.server_close()


def main():
    test_auth_disabled_by_default()
    test_auth_enforced_once_a_key_is_provisioned()
    test_tenant_scoped_key_cannot_read_another_tenant()
    test_url_encoded_mac_lookup_works_within_own_tenant()
    test_tenant_scoped_key_cannot_write_another_tenant()
    test_read_only_key_can_read_but_not_write()
    test_admin_key_is_unrestricted()
    test_keys_route_never_leaks_material_and_is_tenant_scoped()
    test_keys_route_unrestricted_for_admin_and_when_auth_disabled()
    test_rotation_both_keys_live_then_old_revoked_over_http()
    test_legacy_single_key_migrates_and_keeps_working_over_http()
    test_failed_auth_is_logged_and_rate_limited()
    test_revoking_last_key_does_not_reopen_service()
    test_auth_fail_by_ip_is_swept_periodically()
    test_inventory_read_accepts_caller_presented_key_like_nginx_forwards()
    test_require_auth_or_die_empty_keystore_exits_1()
    test_require_auth_or_die_noop_without_env()
    test_require_auth_or_die_provisioned_keystore_is_noop()
    test_serve_actually_calls_require_auth_or_die_before_listening()
    if FAILS:
        print(f"[FAIL] ws6 auth: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WS-6 auth: disabled by default, enforced once provisioned, per-tenant keys isolate "
          "read+write, URL-decoded MAC lookup, read_only scope blocks writes (403), admin key "
          "unrestricted, GET /keys never leaks material and is tenant-scoped, zero-downtime "
          "rotation + revoke, legacy single-key migration, slow-fail counter + per-IP rate limit "
          "with periodic bucket sweep on failed keys, revoking the last key stays enforced, "
          "caller-presented X-Api-Key forwarded from nginx accepted on reads -- all over real HTTP")


if __name__ == "__main__":
    main()
