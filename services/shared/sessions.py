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
"""
from __future__ import annotations

import os
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Optional

DEFAULT_SESSION_TTL_S = 8 * 3600  # 8-hour session, a work-day

_REDIS_KEY_PREFIX = "fengarde:session:"


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
        self.ttl_s = ttl_s
        self.r = redis.Redis.from_url(
            url or os.getenv("REDIS_URL", "redis://localhost:6379/0"),
            decode_responses=True, socket_connect_timeout=2)
        self.r.ping()  # fail-loud at construction, not on first request

    def create(self, username: str, role: str, tenant_id: str) -> str:
        token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        if self.ttl_s <= 0:
            return token  # already expired; matches memory-store resolve() -> None
        key = _REDIS_KEY_PREFIX + token
        pipe = self.r.pipeline()
        pipe.hset(key, mapping={
            "username": username, "role": role, "tenant_id": tenant_id,
            "expires_at": str(time.time() + self.ttl_s), "csrf_token": csrf_token,
        })
        pipe.expire(key, self.ttl_s)
        pipe.execute()
        return token

    def resolve(self, token: str) -> Optional[Session]:
        if not token:
            return None
        data = self.r.hgetall(_REDIS_KEY_PREFIX + token)
        if not data:
            return None
        return Session(
            username=data["username"], role=data["role"],
            tenant_id=data["tenant_id"],
            expires_at=float(data["expires_at"]),
            csrf_token=data["csrf_token"],
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
