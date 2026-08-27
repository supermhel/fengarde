"""Session-store lifecycle tests, parametrized over memory (always) + redis
(when reachable) -- same pattern as services/shared/test_runner.py's
_BACKENDS. Proves SessionStore and RedisSessionStore agree on behavior:
create/resolve round-trip, csrf_token presence, expiry, invalidate, count.

The memory half runs in the default zero-infra gate. The redis half is
opt-in (SESSION_TEST_REDIS=1 + a reachable broker) and joins `make test-live`.

Run: python services/shared/test_sessions.py
     SESSION_TEST_REDIS=1 python services/shared/test_sessions.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from shared.sessions import SessionStore, RedisSessionStore, make_session_store  # noqa: E402
from shared import sessions as _sessions_mod  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


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


_BACKENDS: list[tuple[str, Callable[..., Any] | None]] = [
    ("memory", lambda ttl_s=None: SessionStore(**({"ttl_s": ttl_s} if ttl_s is not None else {}))),
]
if _redis_reachable():
    _BACKENDS.append(("redis", lambda ttl_s=None: RedisSessionStore(**({"ttl_s": ttl_s} if ttl_s is not None else {}))))
else:
    _BACKENDS.append(("redis", None))


def _body_create_resolve_roundtrip(make_store):
    store = make_store()
    token = store.create("alice", "admin", "acme")
    session = store.resolve(token)
    check(session is not None, "resolve() must find a just-created session")
    check(session.username == "alice" and session.role == "admin"
          and session.tenant_id == "acme", f"session fields wrong: {session}")
    check(bool(session.csrf_token), "csrf_token must be present and non-empty")


def _body_unknown_token_resolves_none(make_store):
    store = make_store()
    check(store.resolve("not-a-real-token") is None, "unknown token must resolve to None")
    check(store.resolve("") is None, "empty token must resolve to None")


def _body_expiry(make_store):
    store = make_store(0)  # immediate expiry
    token = store.create("bob", "viewer", "acme")
    check(store.resolve(token) is None, "a 0-ttl session must already be expired")


def _test_redis_resolve_enforces_stored_expiry():
    """R3-60 regression (2026-08-26/27): resolve() must reject a row whose
    stored `expires_at` is in the past even when the Redis key's own TTL
    has NOT yet evicted it (e.g. a TTL that was set wrong, or a replica
    lag/clock-skew scenario where the key outlives its logical deadline).

    The existing `_body_expiry` test (ttl_s=0) does NOT exercise this: on
    RedisSessionStore, ttl_s<=0 makes create() return a token WITHOUT ever
    writing a row (`if self.ttl_s <= 0: return token`), so resolve()==None
    there proves "no such key", not "stored expires_at enforced". This test
    creates a REAL row with a long TTL, then rewrites its `expires_at`
    field directly (re-signed, matching a real tampered/stale row) to be
    in the past while leaving the Redis TTL alone, and asserts resolve()
    still rejects it -- proving the explicit expires_at comparison this
    finding added, not the TTL, is what closes the request.
    """
    if not _redis_reachable():
        print("  [SKIP] test_redis_resolve_enforces_stored_expiry (SESSION_TEST_REDIS!=1 or no reachable Redis)")
        return
    store = RedisSessionStore(ttl_s=3600)  # long TTL: the key itself must NOT have expired
    token = store.create("eve", "viewer", "acme")
    check(store.resolve(token) is not None, "sanity: freshly-created session must resolve")

    key = _sessions_mod._REDIS_KEY_PREFIX + token
    data = store.r.hgetall(key)
    data.pop("sig", None)
    data["expires_at"] = str(0.0)  # 1970 -- unambiguously in the past
    data["sig"] = _sessions_mod._sign(data)
    store.r.hset(key, mapping=data)

    ttl_before = store.r.ttl(key)
    check(ttl_before > 0, f"sanity: the Redis key TTL must still be live (got {ttl_before}) -- "
          "otherwise this test proves nothing about the expires_at check specifically")
    check(store.resolve(token) is None,
          "resolve() must reject a row with a past expires_at even though the "
          "Redis key's own TTL has not evicted it yet")
    check(store.r.exists(key) == 0,
          "resolve() must best-effort tombstone (delete) a row it rejected for "
          "expiry, so a repeated stale resolve doesn't re-read the same dead row")


def _body_invalidate(make_store):
    store = make_store()
    token = store.create("carol", "admin", "acme")
    check(store.resolve(token) is not None, "sanity: session exists before invalidate")
    store.invalidate(token)
    check(store.resolve(token) is None, "invalidate() must make the token unresolvable")


def _body_count(make_store):
    store = make_store()
    before = store.count()
    t1 = store.create("d1", "viewer", "acme")
    store.create("d2", "viewer", "acme")
    check(store.count() == before + 2, f"count() must reflect both created sessions, got {store.count()}")
    store.invalidate(t1)
    check(store.count() == before + 1, f"count() must drop after invalidate, got {store.count()}")


def _run_parametrized(name, body):
    for backend_label, make_store in _BACKENDS:
        qualified = f"{name}[{backend_label}]"
        if make_store is None:
            print(f"  [SKIP] {qualified} (SESSION_TEST_REDIS!=1 or no reachable Redis)")
            continue
        try:
            body(make_store)
            print(f"  . {qualified}")
        except Exception as e:
            FAILS.append(f"{qualified} raised: {e!r}")
            print(f"  X {qualified}: {e!r}")


def _test_make_session_store_factory():
    os.environ.pop("FENGARDE_SESSION_BACKEND", None)
    check(isinstance(make_session_store(), SessionStore),
          "default backend (unset env) must be SessionStore")
    os.environ["FENGARDE_SESSION_BACKEND"] = "memory"
    check(isinstance(make_session_store(), SessionStore),
          "explicit 'memory' must be SessionStore")
    os.environ["FENGARDE_SESSION_BACKEND"] = "bogus"
    try:
        make_session_store()
        check(False, "an unknown backend name must raise, not silently fall back")
    except ValueError:
        pass
    finally:
        os.environ.pop("FENGARDE_SESSION_BACKEND", None)


def main():
    _test_make_session_store_factory()
    for name, body in [
        ("test_create_resolve_roundtrip", _body_create_resolve_roundtrip),
        ("test_unknown_token_resolves_none", _body_unknown_token_resolves_none),
        ("test_expiry", _body_expiry),
        ("test_invalidate", _body_invalidate),
        ("test_count", _body_count),
    ]:
        _run_parametrized(name, body)
    _test_redis_resolve_enforces_stored_expiry()

    if FAILS:
        print(f"\n[FAIL] sessions: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("\n[OK] session store lifecycle PASS (memory" +
          (" + redis" if _redis_reachable() else ", redis skipped") + ")")


if __name__ == "__main__":
    main()
