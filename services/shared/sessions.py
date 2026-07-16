"""M4.2 RBAC: session tokens (in-memory, stdlib-only).

A session is an opaque, cryptographically-random token (`secrets.token_urlsafe`,
not a guessable/incrementing id) mapped to (username, role, tenant_id,
expires_at). Issued by the login endpoint as an HttpOnly cookie so the
browser's JS never holds it (same discipline the dashboard already applies
to X-Api-Key -- nginx injects it server-side, the browser never sees it).

In-memory, not persisted: a service restart logs everyone out. Acceptable
for a single-process API (the same scope this project's other stdlib HTTP
services already operate at -- see triage_api.py's in-process triage lock);
a multi-replica deployment would need a shared session store (Redis, which
is already a hard dependency of this stack) -- noted as a follow-up, not
built this pass since it needs a live Redis to test against.
"""
from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass
from typing import Optional

DEFAULT_SESSION_TTL_S = 8 * 3600  # 8-hour session, a work-day


@dataclass
class Session:
    username: str
    role: str
    tenant_id: str
    expires_at: float


class SessionStore:
    def __init__(self, ttl_s: int = DEFAULT_SESSION_TTL_S):
        self.ttl_s = ttl_s
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def create(self, username: str, role: str, tenant_id: str) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._sessions[token] = Session(
                username=username, role=role, tenant_id=tenant_id,
                expires_at=time.time() + self.ttl_s,
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
