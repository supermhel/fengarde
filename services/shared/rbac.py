"""M4.2 RBAC: role permission model + login rate limiting.

Three roles, each a strict superset of the one before:
  read_only < analyst < admin

read_only  : GET-only, own tenant's data only.
analyst    : read_only + triage writes (status/note) + report generation,
             own tenant only.
admin      : analyst + user management + cross-tenant visibility.

Tenant scoping is enforced SEPARATELY from role (see `can_access_tenant`) --
a role says WHAT a user can do, tenant scoping says WHICH data they can do
it to. An admin's role doesn't imply cross-tenant access by itself; it's the
one role this module grants that exception to, matching "admin manages the
whole deployment" being the only role with an MSP-wide view.
"""
from __future__ import annotations

import threading
import time
from typing import Optional

# How often (in calls into the limiter) it sweeps stale username keys. Same
# amortized-O(1) idea and same default cadence as
# services/ws4-detection/window.py::DequeWindowCounter's _SWEEP_EVERY --
# this dict has the identical unbounded-growth shape (one key per distinct
# username ever attempted) and the identical fix.
_SWEEP_EVERY = 256

_ROLE_RANK = {"read_only": 0, "analyst": 1, "admin": 2}


def role_at_least(role: str, minimum: str) -> bool:
    """True if `role` has at least the privilege of `minimum`. An unknown
    role fails closed (False) -- never treat an unrecognized role string as
    implicitly privileged."""
    return _ROLE_RANK.get(role, -1) >= _ROLE_RANK.get(minimum, 999)


def can_access_tenant(user_role: str, user_tenant: str, resource_tenant: Optional[str]) -> bool:
    """True if a user may access a resource belonging to `resource_tenant`.

    admin: any tenant (including a resource with no tenant_id at all --
    pre-M4 data, or a malformed doc missing the field, is deployment-wide
    housekeeping, not a specific tenant's private data).
    Everyone else: only their OWN tenant. A resource with tenant_id=None is
    treated as "default" (pre-M4 data) so a non-admin default-tenant user
    can still see it, but a non-admin user of a DIFFERENT tenant cannot.
    """
    if user_role == "admin":
        return True
    resource_tenant = resource_tenant or "default"
    return user_tenant == resource_tenant


class LoginRateLimiter:
    """Fixed-window lockout per username: N failed attempts within a
    window locks that username out for the rest of the window. Keyed on
    username, not source IP -- a shared-NAT office trying one real user's
    password shouldn't get every OTHER user in the office locked out too,
    and username-keying is what actually stops a credential-stuffing run
    against one account. In-memory (see sessions.py's same scope note --
    single-process API, restart clears it).

    Thread-safe (a lock around all three methods): `is_locked_out` is a
    read-modify-write on `_attempts` (it prunes stale timestamps as a side
    effect), so without a lock a concurrent `record_failure` on the same
    username from another handler thread can interleave and drop a
    failure record, letting a few extra guesses slip past the limit.

    Bounded (periodic sweep, mirrors `window.py::DequeWindowCounter`'s
    `_SWEEP_EVERY` -- same unbounded-dict-growth shape, same fix):
    `is_locked_out` is called for EVERY login attempt, not just failed
    ones (see triage_api.py's login route), so without eviction an
    attacker spraying distinct random usernames grows `_attempts` (and,
    before this fix, created an entry on the very first lookup even for a
    username that never actually failed) without bound -- a memory-
    exhaustion DoS reachable pre-authentication."""

    def __init__(self, max_attempts: int = 5, window_s: int = 300):
        self.max_attempts = max_attempts
        self.window_s = window_s
        self._attempts: dict[str, list[float]] = {}
        self._last: dict[str, float] = {}  # username -> most recent attempt (for sweeping)
        self._lock = threading.Lock()
        self._calls = 0

    def _sweep_locked(self, now: float) -> None:
        """Caller must hold `self._lock`. Drop usernames whose newest
        recorded attempt has aged out of the window."""
        self._calls += 1
        if self._calls % _SWEEP_EVERY:
            return
        horizon = now - self.window_s
        stale = [u for u, ts in self._last.items() if ts < horizon]
        for u in stale:
            self._attempts.pop(u, None)
            self._last.pop(u, None)

    def is_locked_out(self, username: str) -> bool:
        now = time.time()
        with self._lock:
            recent = [t for t in self._attempts.get(username, []) if t > now - self.window_s]
            if recent:
                self._attempts[username] = recent
                self._last[username] = recent[-1]
            else:
                # No real (in-window) history for this username -- don't
                # plant an empty-list entry just because it was looked up;
                # that alone was the pre-authentication growth vector.
                self._attempts.pop(username, None)
                self._last.pop(username, None)
            self._sweep_locked(now)
            return len(recent) >= self.max_attempts

    def record_failure(self, username: str) -> None:
        now = time.time()
        with self._lock:
            self._attempts.setdefault(username, []).append(now)
            self._last[username] = now
            self._sweep_locked(now)

    def record_success(self, username: str) -> None:
        with self._lock:
            self._attempts.pop(username, None)
            self._last.pop(username, None)
