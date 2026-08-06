"""Shared API-key check for WS-3/WS-6 HTTP write surfaces (v0.4 Track S1).

No authentication existed on any service before v0.4 (SECURITY.md, documented
v0.1/v0.2 limitation). This is deliberately minimal: one shared secret via
`X-Api-Key`, not an identity/role system. Auth is OPT-IN — when the env var
is unset, every request is allowed and one warning is logged at import time,
so the zero-infra test gate and the homelab quickstart keep working
unchanged. A real deployment sets `FENGARDE_API_KEY`.
"""
from __future__ import annotations

import hmac
import json
import os
import sys


def check_api_key(headers, env_var: str = "FENGARDE_API_KEY") -> bool:
    """Return True if the request is authorized.

    Auth disabled (env var unset/empty) -> always True (documented default).
    Auth enabled -> requires header `X-Api-Key` to match via constant-time
    compare (no early-exit timing signal on a partial match).
    """
    expected = os.getenv(env_var)
    if not expected:
        return True
    got = headers.get("X-Api-Key", "")
    return hmac.compare_digest(got, expected)


def warn_if_disabled(service: str, env_var: str = "FENGARDE_API_KEY") -> None:
    if not os.getenv(env_var):
        print(f'{{"level": "warning", "service": "{service}", '
              f'"msg": "auth disabled: {env_var} not set"}}', flush=True)


def require_auth_or_die(service: str) -> None:
    """FIX 6: exit(1) with a clear JSON message when FENGARDE_REQUIRE_AUTH is
    1/true/yes but the configured auth surface is incomplete.

    A no-op by default (env unset) so the existing opt-in path --
    ``check_api_key``/``warn_if_disabled`` tolerating an unset key -- is
    byte-for-byte unchanged. Deployments that REQUIRE auth set
    ``FENGARDE_REQUIRE_AUTH=1`` and this refuses to boot rather than silently
    running default-open.
    """
    if os.getenv("FENGARDE_REQUIRE_AUTH", "").strip().lower() not in ("1", "true", "yes"):
        return
    missing = []
    if not os.getenv("FENGARDE_API_KEY"):
        missing.append("FENGARDE_API_KEY")
    if os.getenv("FENGARDE_RBAC_DB") and not os.getenv("FENGARDE_ADMIN_PASSWORD"):
        missing.append("FENGARDE_ADMIN_PASSWORD (RBAC DB set, no admin)")
    if os.getenv("BUS_BACKEND") in ("redis", "redis-sentinel") and not os.getenv("REDIS_PASSWORD"):
        missing.append("REDIS_PASSWORD (Redis bus with no auth)")
    if missing:
        print(json.dumps({
            "level": "fatal", "service": service,
            "msg": "FENGARDE_REQUIRE_AUTH=1 but auth is incomplete",
            "missing": missing,
        }), flush=True)
        sys.exit(1)
