"""API-key check for the WS-6 inventory API (v0.4 Track S1; F1 follow-up
2026-07-30: per-tenant keys).

Standalone copy of services/shared/authz.py's logic: ws6's Docker image does
NOT bundle services/shared (see Dockerfile), so this stays self-contained
rather than importing across that packaging boundary. Keep both in sync if
the check logic ever changes.
"""
from __future__ import annotations

import hmac
import os

ADMIN_TENANT_MARKER = "*"


def check_api_key(headers, env_var: str = "FENGARDE_API_KEY") -> bool:
    expected = os.getenv(env_var)
    if not expected:
        return True
    got = headers.get("X-Api-Key", "")
    return hmac.compare_digest(got, expected)


def _parse_tenant_keys(raw: str | None) -> dict[str, str]:
    """`FENGARDE_API_KEYS='acme:key1,globex:key2,*:adminkey'` -> {tenant: key}.
    A malformed entry (no ':', empty tenant, empty key) is skipped rather
    than raising -- a typo'd extra entry must never crash the whole service;
    the entries that DO parse still enforce real per-tenant auth."""
    if not raw:
        return {}
    out: dict[str, str] = {}
    for pair in raw.split(","):
        tenant, sep, key = pair.strip().partition(":")
        tenant, key = tenant.strip(), key.strip()
        if sep and tenant and key:
            out[tenant] = key
    return out


def check_tenant_scoped_auth(headers, env_var: str = "FENGARDE_API_KEYS"):
    """Per-tenant auth (F1 follow-up: closes the "any caller with the one
    shared key can enumerate every tenant" gap independent_review_of_fixes.md
    flagged -- the F1 fix scoped data/routes to tenant_id but left auth a
    single undifferentiated secret).

    Returns:
      * None -- FENGARDE_API_KEYS is not configured; per-tenant auth is
        INACTIVE and the caller falls back to the legacy check_api_key()
        (single shared key, request's own ?tenant_id= trusted as-is) --
        byte-for-byte pre-fix behavior for any deployment that hasn't
        opted into this.
      * (True, None) -- configured, and the caller authenticated with the
        `*` admin key: unrestricted, same trust level as the legacy key.
      * (True, tenant_id) -- configured, and the caller authenticated with
        that tenant's own key: every tenant_id this request touches must be
        forced to this value, regardless of what the caller asked for.
      * (False, None) -- configured, and the presented key matches none of
        the configured entries.
    """
    keys = _parse_tenant_keys(os.getenv(env_var))
    if not keys:
        return None
    got = headers.get("X-Api-Key", "")
    # Constant-time compare against every candidate (not early-exit on the
    # first mismatch) -- cardinality is one entry per tenant, small by
    # construction, so this isn't a scaling concern, and it keeps timing
    # identical to a single check_api_key() call regardless of which (if
    # any) tenant's key was presented.
    matched: str | None = None
    for tenant, key in keys.items():
        if hmac.compare_digest(got, key):
            matched = tenant
    if matched is None:
        return False, None
    return True, (None if matched == ADMIN_TENANT_MARKER else matched)


def warn_if_disabled(service: str, env_var: str = "FENGARDE_API_KEY") -> None:
    if not os.getenv(env_var) and not os.getenv("FENGARDE_API_KEYS"):
        print(f'{{"level": "warning", "service": "{service}", '
              f'"msg": "auth disabled: {env_var} not set"}}', flush=True)
