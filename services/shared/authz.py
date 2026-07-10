"""Shared API-key check for WS-3/WS-6 HTTP write surfaces (v0.4 Track S1).

No authentication existed on any service before v0.4 (SECURITY.md, documented
v0.1/v0.2 limitation). This is deliberately minimal: one shared secret via
`X-Api-Key`, not an identity/role system. Auth is OPT-IN — when the env var
is unset, every request is allowed and one warning is logged at import time,
so the zero-infra test gate and the homelab quickstart keep working
unchanged. A real deployment sets `ARGUS_API_KEY`.
"""
from __future__ import annotations

import hmac
import os


def check_api_key(headers, env_var: str = "ARGUS_API_KEY") -> bool:
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


def warn_if_disabled(service: str, env_var: str = "ARGUS_API_KEY") -> None:
    if not os.getenv(env_var):
        print(f'{{"level": "warning", "service": "{service}", '
              f'"msg": "auth disabled: {env_var} not set"}}', flush=True)
