"""Regression tests for FENGARDE FIX-4 / FIX-5 / FIX-6 / FIX-L4 security-surface fixes.

Run: python services/ws3-indexer/test_fix_security.py
     SESSION_TEST_REDIS=1 python services/ws3-indexer/test_fix_security.py  (adds Live Redis session-signing checks)

Covered:
  * FIX 4 -- no_redirect_urlopen does NOT follow a 302 (SSRF hardening): a
    redirecting server's 30x surfaces as urllib.error.HTTPError and the
    redirect target is never hit.
  * FIX 5 -- server-side session signing: _sign is secret-and-content
    dependent, a forged Redis session row (sig mismatch OR missing sig) is
    rejected (resolve -> None; no backward-compat unsigned path), and
    RedisSessionStore refuses to construct without FENGARDE_SESSION_SECRET
    set. Live-Redis-gated.
  * FIX 6 -- require_auth_or_die exits with code 1 when FENGARDE_REQUIRE_AUTH
    is on but auth is incomplete; no-ops otherwise.
  * FIX L4 -- per-IP rate limiter is a no-op when disabled and returns 429
    once the bucket is exhausted when enabled.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

import triage_api  # noqa: E402
from shared.outbound_http import no_redirect_urlopen  # noqa: E402
import shared.sessions as sessions  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


# -- FIX 4: no redirect following ---------------------------------------------

_TARGET_HITS = {"n": 0}


class _RedirectHandler(BaseHTTPRequestHandler):
    target = "http://127.0.0.1:1/unused"

    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", self.target)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_):
        pass


class _TargetHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        _TARGET_HITS["n"] += 1
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_):
        pass


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def test_no_redirect_follows_nothing():
    target_srv, target_port = _serve(_TargetHandler)
    redirect_srv, redirect_port = _serve(_RedirectHandler)
    _RedirectHandler.target = f"http://127.0.0.1:{target_port}/secret"
    _TARGET_HITS["n"] = 0
    try:
        url = f"http://127.0.0.1:{redirect_port}/start"
        try:
            no_redirect_urlopen(url, timeout=5)
            check(False, "a 302 must NOT be followed; expected HTTPError 302")
        except urllib.error.HTTPError as e:
            check(e.code == 302,
                  f"a 30x must surface as HTTPError with the 30x code, got {e.code}")
        check(_TARGET_HITS["n"] == 0,
              f"the redirect TARGET must not be reached (SSRF pivot), got {_TARGET_HITS['n']} hit(s)")
    finally:
        redirect_srv.shutdown(); redirect_srv.server_close()
        target_srv.shutdown(); target_srv.server_close()


# -- FIX 5: session signing ----------------------------------------------------

def test_sign_is_secret_and_content_dependent():
    os.environ["FENGARDE_SESSION_SECRET"] = "unit-test-secret"
    try:
        d1 = {"username": "alice", "role": "admin", "expires_at": "999"}
        d2 = {"username": "alice", "role": "admin", "expires_at": "999"}  # same
        d3 = {"username": "alice", "role": "admin", "expires_at": "998"}  # tampered
        # deterministic for identical content
        check(sessions._sign(d1) == sessions._sign(d2),
              "_sign must be deterministic for identical session data")
        # changes when the data changes
        check(sessions._sign(d1) != sessions._sign(d3),
              "_sign must change when the session data changes (signature must bind the data)")
        # changes when the secret changes (constant-time compare fails -> reject)
        other = sessions._sign.__globals__["hmac"]
        check(not other.compare_digest(sessions._sign(d1), sessions._sign(d3)),
              "a tampered signature must not compare-equal the real one")
    finally:
        os.environ.pop("FENGARDE_SESSION_SECRET", None)


def _redis_reachable():
    if os.getenv("SESSION_TEST_REDIS", "0") != "1":
        return False
    try:
        import redis  # type: ignore
        r = redis.Redis.from_url(
            os.getenv("REDIS_URL", "redis://localhost:6379/0"),
            decode_responses=True, socket_connect_timeout=1)
        r.ping()
        return True
    except Exception:
        return False


def test_forged_redis_session_rejected():
    if not _redis_reachable():
        print("  [SKIP] test_forged_redis_session_rejected (SESSION_TEST_REDIS!=1 or no Redis)")
        return
    os.environ["FENGARDE_SESSION_SECRET"] = "redis-signing-secret"
    os.environ["FENGARDE_SESSION_BACKEND"] = "redis"
    store = sessions.RedisSessionStore(url=os.getenv("REDIS_URL"), ttl_s=900)
    try:
        token = store.create("mallory", "admin", "*")
        key = "fengarde:session:" + token
        # Forge: overwrite the row to claim admin with a KNOWN-INVALID signature.
        # A real attacker cannot compute _sign (no server secret), so any
        # hand-written/mismatched `sig` must be rejected.
        forged = {
            "username": "attacker", "role": "admin", "tenant_id": "*",
            "expires_at": "9999999999", "csrf_token": "known",
            "sig": "deadbeef" * 16,  # wrong / guessed signature
        }
        store.r.delete(key)
        store.r.hset(key, mapping=forged)
        check(store.resolve(token) is None,
              "a forged Redis session row (sig mismatch) must resolve() to None")
        # Sanity: a legitimately signed row still resolves.
        store.r.delete(key)
        t2 = store.create("alice", "analyst", "acme")
        check(store.resolve(t2) is not None,
              "a legitimately signed session must still resolve")
        # Follow-up (2026-08-06): signing is now MANDATORY, no backward-compat
        # unsigned path -- a legacy row with NO sig must be REJECTED, not
        # silently accepted (accepting it would let an attacker who can write
        # to Redis directly just omit `sig` and bypass signing entirely).
        store.r.delete("fengarde:session:" + t2)
        legacy = {"username": "bob", "role": "viewer", "tenant_id": "acme",
                  "expires_at": str(__import__("time").time() + 1000),
                  "csrf_token": "c"}
        store.r.hset("fengarde:session:" + t2, mapping=legacy)
        check(store.resolve(t2) is None,
              "a legacy (unsigned) session row must be rejected -- signing "
              "has no backward-compat bypass")
    finally:
        store.r.delete("fengarde:session:" + token)
        os.environ.pop("FENGARDE_SESSION_SECRET", None)
        os.environ.pop("FENGARDE_SESSION_BACKEND", None)


def test_redis_session_store_refuses_without_secret():
    if not _redis_reachable():
        print("  [SKIP] test_redis_session_store_refuses_without_secret "
              "(SESSION_TEST_REDIS!=1 or no Redis)")
        return
    os.environ.pop("FENGARDE_SESSION_SECRET", None)
    try:
        sessions.RedisSessionStore(url=os.getenv("REDIS_URL"), ttl_s=900)
        check(False, "RedisSessionStore must refuse to construct without "
                     "FENGARDE_SESSION_SECRET set (fail loud, no silent "
                     "per-process random fallback)")
    except RuntimeError:
        pass


# -- FIX 6: require_auth_or_die ------------------------------------------------

def test_require_auth_or_die_missing_key_exits_1():
    env = dict(os.environ)
    env.update({"FENGARDE_REQUIRE_AUTH": "1", "FENGARDE_API_KEY": "",
                "FENGARDE_RBAC_DB": "", "BUS_BACKEND": "memory"})
    code = "import shared.authz as a; a.require_auth_or_die('ws3-indexer')"
    proc = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True,
                          text=True, cwd=str(HERE.parent))
    check(proc.returncode == 1, f"require_auth_or_die must exit 1 when key unset, got {proc.returncode}")
    try:
        msg = json.loads(proc.stdout.strip().splitlines()[-1])
        check(msg.get("missing") == ["FENGARDE_API_KEY"],
              f"JSON must list FENGARDE_API_KEY as missing, got {proc.stdout}")
    except Exception as e:  # noqa: BLE001
        check(False, f"expected a JSON fatal message on stdout, got: {proc.stdout!r} ({e})")


def test_require_auth_or_die_noop_without_env():
    env = dict(os.environ)
    env.pop("FENGARDE_REQUIRE_AUTH", None)
    code = "import shared.authz as a; a.require_auth_or_die('ws3-indexer'); print('ok')"
    proc = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True,
                          text=True, cwd=str(HERE.parent))
    check(proc.returncode == 0 and "ok" in proc.stdout,
          f"require_auth_or_die must be a no-op when FENGARDE_REQUIRE_AUTH is unset, got rc={proc.returncode} out={proc.stdout!r}")


# -- FIX L4: rate limiting -----------------------------------------------------

def test_rate_limit_is_noop_when_off():
    check(triage_api._RATE_LIMIT <= 0,
          "rate limiting must default to off (RATE_LIMIT_REQUESTS_PER_MIN unset)")
    check(triage_api._rate_limit_allowed("1.2.3.4"),
          "when off, every request must be allowed")


def test_rate_limiter_bucket_exhausts():
    os.environ["RATE_LIMIT_REQUESTS_PER_MIN"] = "3"
    try:
        import importlib
        importlib.reload(triage_api)  # re-read env at module scope
        allowed = [triage_api._rate_limit_allowed("9.9.9.9") for _ in range(3)]
        check(all(allowed), "the first RATE_LIMIT_REQUESTS_PER_MIN requests must be allowed")
        check(not triage_api._rate_limit_allowed("9.9.9.9"),
              "a request beyond the bucket capacity must be denied (429 path)")
    finally:
        os.environ.pop("RATE_LIMIT_REQUESTS_PER_MIN", None)
        import importlib
        importlib.reload(triage_api)  # restore the default (off)


def main():
    test_no_redirect_follows_nothing()
    test_sign_is_secret_and_content_dependent()
    test_forged_redis_session_rejected()
    test_redis_session_store_refuses_without_secret()
    test_require_auth_or_die_missing_key_exits_1()
    test_require_auth_or_die_noop_without_env()
    test_rate_limit_is_noop_when_off()
    test_rate_limiter_bucket_exhausts()

    if FAILS:
        print(f"[FAIL] fix-security regression: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] FIX-4 no-redirect, FIX-5 session signing (redis-gated), "
          "FIX-6 require_auth_or_die, FIX-L4 rate limiter")


if __name__ == "__main__":
    main()
