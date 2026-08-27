"""M4.2 RBAC: session tokens -- in-memory (default) or Redis-backed (opt-in).

A session is an opaque, cryptographically-random token (`secrets.token_urlsafe`,
not a guessable/incrementing id) mapped to (username, role, tenant_id,
expires_at). Issued by the login endpoint as an HttpOnly cookie so the
browser's JS never holds it (same discipline the dashboard already applies
to X-Api-Key -- nginx injects it server-side, the browser never sees it).

Two backends, selected by ``make_session_store()`` via
``FENGARDE_SESSION_BACKEND``:

- ``memory`` (default, byte-for-byte the pre-2026-07-21 behavior):
  in-process dict; a service restart logs everyone out; correct for a
  single replica.
- ``redis``: one Redis hash per token with a native ``EXPIRE`` TTL, so
  every WS-3 replica sees the same sessions and logout/expiry is global.
  Uses the stack's existing ``REDIS_URL``.

**Fail-loud, deliberately.** If ``redis`` is requested and unreachable,
``make_session_store()`` raises at startup instead of falling back to
memory. Sessions are a security boundary: a silent fallback would quietly
turn "logout everywhere" into "logout on one replica" -- the exact bug the
Redis backend exists to prevent. (Contrast the bus, which does fall back:
a degraded transport is visible in /health; a degraded session store is
invisible.)

**Redis session rows are HMAC-signed and the signature is MANDATORY (FIX 5,
follow-up 2026-08-06).** Any process that can write to Redis can otherwise
forge an admin session with a raw HSET. ``RedisSessionStore.__init__``
refuses to start unless ``FENGARDE_SESSION_SECRET`` is set (fail loud, same
posture as the unreachable-Redis case above -- a silent per-process random
fallback would sign sessions with a key no OTHER replica shares, so every
replica but the one that minted a session would reject it as unsigned,
which is just as broken as no signing at all). ``resolve()`` then requires
every row to carry a valid ``sig``; a row with no ``sig`` (legacy data, or a
forged row that omits it) is rejected outright -- there is no backward-
compatible unsigned path, because leaving one open is exactly the gap FIX 5
closes.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Optional

DEFAULT_SESSION_TTL_S = 8 * 3600  # 8-hour session, a work-day

_REDIS_KEY_PREFIX = "fengarde:session:"


# -- FIX 5: server-side HMAC signing of the Redis-held session hash --------
# Without a signature, any process that can write to Redis can forge an
# admin session (raw HGETALL with no integrity check). We HMAC-SHA256-sign
# the stored data with a server key so only a process holding the same key
# can mint sessions that `resolve()` will accept. MANDATORY, not opt-in:
# RedisSessionStore.__init__ refuses to construct without
# FENGARDE_SESSION_SECRET set (see its docstring) -- a prior version fell
# back to a random per-process secret with a warning, which silently
# defeated cross-replica signing (each replica would sign with its own
# unshared key, so every replica's sessions would look "forged" -- i.e.
# unsigned -- to every other replica) instead of refusing to start.


def _session_secret() -> bytes:
    """The mandatory HMAC key, from FENGARDE_SESSION_SECRET.

    Only ever called after RedisSessionStore.__init__ has already verified
    the env var is set (see there) -- this raises instead of silently
    degrading if that invariant is somehow violated (e.g. a future call
    site added before construction).
    """
    s = os.getenv("FENGARDE_SESSION_SECRET", "")
    if not s:
        raise RuntimeError(
            "FENGARDE_SESSION_SECRET is not set; session signing has no key. "
            "RedisSessionStore.__init__ should have refused to start before "
            "this was ever called.")
    return s.encode("utf-8")


def _sign(data: dict) -> str:
    """Deterministic HMAC-SHA256 hexdigest over the sorted-keys JSON of the
    session data dict (sort_keys=True so create()/resolve() agree)."""
    payload = json.dumps(data, sort_keys=True)
    return hmac.new(_session_secret(), payload.encode(), hashlib.sha256).hexdigest()


@dataclass
class Session:
    username: str
    role: str
    tenant_id: str
    expires_at: float
    csrf_token: str


class SessionStore:
    def __init__(self, ttl_s: int = DEFAULT_SESSION_TTL_S):
        self.ttl_s = ttl_s
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def create(self, username: str, role: str, tenant_id: str) -> str:
        """Returns the session token (unchanged signature/behavior for
        existing callers). A second, independent random value --
        `csrf_token`, readable via resolve(token).csrf_token -- is minted
        alongside it; the HTTP layer hands that to the browser in a
        response BODY (never the cookie itself) and requires it echoed
        back on state-changing requests. See triage_api.py's `_check_csrf`
        docstring for why this is a second, independent layer on top of
        the cookie's own SameSite=Strict."""
        token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        # 0/non-positive TTL = immediate expiry, never stored. Deliberately
        # deterministic (not `expires_at = now + 0`): a coarse clock can make
        # that resolve() as NOT-yet-expired, and the Redis store already
        # special-cases ttl_s <= 0 -- parity here keeps both backends honoring
        # the same contract that test_sessions.py `_body_expiry` asserts.
        if self.ttl_s <= 0:
            return token  # already expired; matches redis-store resolve() -> None
        with self._lock:
            self._sessions[token] = Session(
                username=username, role=role, tenant_id=tenant_id,
                expires_at=time.time() + self.ttl_s, csrf_token=csrf_token,
            )
        return token

    def resolve(self, token: str) -> Optional[Session]:
        """Return the Session if `token` is valid and not expired, else
        None. An expired session is evicted on lookup (lazy cleanup -- no
        background sweep thread needed for a bounded, low-cardinality
        session set)."""
        if not token:
            return None
        with self._lock:
            session = self._sessions.get(token)
            if session is None:
                return None
            if session.expires_at < time.time():
                del self._sessions[token]
                return None
            return session

    def invalidate(self, token: str) -> None:
        with self._lock:
            self._sessions.pop(token, None)

    def count(self) -> int:
        with self._lock:
            return len(self._sessions)


class RedisSessionStore:
    """Same 4-method API as SessionStore, state in Redis.

    One hash per token under ``fengarde:session:<token>`` with a native
    ``EXPIRE`` TTL -- no lazy-eviction code needed, Redis ages sessions out
    itself, and every replica sharing the URL sees the same session set.
    ``ttl_s <= 0`` mirrors the memory store's immediate-expiry semantics
    (used by tests): the session is never stored.
    """

    def __init__(self, url: Optional[str] = None, ttl_s: int = DEFAULT_SESSION_TTL_S):
        import redis  # lazy, same idiom as shared/bus.py
        # FIX 5 follow-up (2026-08-06): fail loud, at construction, if no
        # signing secret is configured -- checked BEFORE the Redis connection
        # so a missing-secret misconfiguration surfaces as its own clear error
        # rather than being masked by (or confused with) a connectivity
        # failure. See the module docstring's "Redis session rows are
        # HMAC-signed" section for why this can't silently fall back.
        if not os.getenv("FENGARDE_SESSION_SECRET"):
            raise RuntimeError(
                "FENGARDE_SESSION_SECRET must be set to use "
                "FENGARDE_SESSION_BACKEND=redis. It HMAC-signs every session "
                "row so a process that can write to Redis directly (but "
                "doesn't hold this secret) cannot forge an authenticated "
                "session. Refusing to start without it.")
        self.ttl_s = ttl_s
        self.r = redis.Redis.from_url(
            url or os.getenv("REDIS_URL") or "redis://localhost:6379/0",
            decode_responses=True, socket_connect_timeout=2)
        self.r.ping()  # fail-loud at construction, not on first request

    def create(self, username: str, role: str, tenant_id: str) -> str:
        token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        if self.ttl_s <= 0:
            return token  # already expired; matches memory-store resolve() -> None
        key = _REDIS_KEY_PREFIX + token
        data = {
            "username": username, "role": role, "tenant_id": tenant_id,
            "expires_at": str(time.time() + self.ttl_s), "csrf_token": csrf_token,
        }
        pipe = self.r.pipeline()
        mapping = dict(data)
        mapping["sig"] = _sign(data)
        pipe.hset(key, mapping=mapping)  # type: ignore[arg-type]  # redis-py stubs union-broaden str->bytes; str-only is safe at runtime
        pipe.expire(key, self.ttl_s)
        pipe.execute()
        return token

    def resolve(self, token: str) -> Optional[Session]:
        if not token:
            return None
        data = self.r.hgetall(_REDIS_KEY_PREFIX + token)
        if not data:
            return None
        # FIX 5 follow-up: signing is MANDATORY for this backend (enforced at
        # __init__ -- a live RedisSessionStore always has a configured
        # secret), so a row with NO `sig`, or one whose `sig` doesn't verify,
        # is rejected outright. No backward-compat unsigned path: leaving one
        # open would let an attacker who can write to Redis directly (the
        # exact threat FIX 5 exists for) just omit `sig` and resolve
        # unchecked, same as before FIX 5 shipped.
        sig = data.pop("sig", None)
        if not sig or not hmac.compare_digest(str(sig), _sign(data)):
            return None
        # Gap-hunt (2026-08-26) R3-60: expiry rested entirely on the Redis key
        # TTL; resolve() never compared expires_at against now. A TTL that was
        # missed/failed to set (or a Redis-backed row living past its bound for
        # any reason) resolved as a live session indefinitely. Enforce the
        # stored expiry explicitly, mirroring the MemoryStore contract.
        expires_at = float(data["expires_at"])
        # Review finding (2026-08-27): `if expires_at and ...` treated
        # expires_at == 0.0 (unambiguously expired: epoch 1970) as falsy and
        # SKIPPED the check entirely -- a row somehow written or tampered
        # with expires_at=0.0 would resolve as valid forever, the exact
        # failure this fix exists to close. expires_at is always a real
        # float on every row this store writes (create() always sets it),
        # so there's no "missing" case to guard against here.
        if time.time() > expires_at:
            # best-effort tombstone so a repeated stale resolve doesn't re-read
            # the same dead row
            try:
                self.r.delete(_REDIS_KEY_PREFIX + token)
            except Exception:
                pass
            return None
        return Session(
            username=str(data["username"]), role=str(data["role"]),
            tenant_id=str(data["tenant_id"]),
            expires_at=expires_at,
            csrf_token=str(data["csrf_token"]),
        )

    def invalidate(self, token: str) -> None:
        if token:
            self.r.delete(_REDIS_KEY_PREFIX + token)

    def count(self) -> int:
        n = 0
        for _ in self.r.scan_iter(match=_REDIS_KEY_PREFIX + "*", count=100):
            n += 1
        return n


def make_session_store(ttl_s: int = DEFAULT_SESSION_TTL_S):
    """Backend factory: FENGARDE_SESSION_BACKEND = memory (default) | redis.

    Unknown values and an unreachable Redis both raise -- see the module
    docstring for why there is no silent fallback here.
    """
    backend = os.getenv("FENGARDE_SESSION_BACKEND", "memory").strip().lower()
    if backend == "memory":
        return SessionStore(ttl_s=ttl_s)
    if backend == "redis":
        return RedisSessionStore(ttl_s=ttl_s)
    raise ValueError(
        f"FENGARDE_SESSION_BACKEND={backend!r} is not a session backend "
        "(expected 'memory' or 'redis')")
