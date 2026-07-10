"""API-key check for the WS-6 inventory API (v0.4 Track S1).

Standalone copy of services/shared/authz.py's logic: ws6's Docker image does
NOT bundle services/shared (see Dockerfile), so this stays self-contained
rather than importing across that packaging boundary. Keep both in sync if
the check logic ever changes.
"""
from __future__ import annotations

import hmac
import os


def check_api_key(headers, env_var: str = "ARGUS_API_KEY") -> bool:
    expected = os.getenv(env_var)
    if not expected:
        return True
    got = headers.get("X-Api-Key", "")
    return hmac.compare_digest(got, expected)


def warn_if_disabled(service: str, env_var: str = "ARGUS_API_KEY") -> None:
    if not os.getenv(env_var):
        print(f'{{"level": "warning", "service": "{service}", '
              f'"msg": "auth disabled: {env_var} not set"}}', flush=True)
