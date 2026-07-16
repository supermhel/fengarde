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

import time
from typing import Optional

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
    single-process API, restart clears it)."""

    def __init__(self, max_attempts: int = 5, window_s: int = 300):
        self.max_attempts = max_attempts
        self.window_s = window_s
        self._attempts: dict[str, list[float]] = {}

    def is_locked_out(self, username: str) -> bool:
        now = time.time()
        recent = [t for t in self._attempts.get(username, []) if t > now - self.window_s]
        self._attempts[username] = recent
        return len(recent) >= self.max_attempts

    def record_failure(self, username: str) -> None:
        self._attempts.setdefault(username, []).append(time.time())

    def record_success(self, username: str) -> None:
        self._attempts.pop(username, None)
