"""WS-6 inventory API auth: startup-warning helper.

The actual per-tenant credential check moved to keystore.py::TenantKeyStore
(F1 second follow-up, 2026-07-30: hashed-at-rest per-tenant keys). This file
used to also hold the live plaintext FENGARDE_API_KEY/FENGARDE_API_KEYS
compare logic; both env vars are now consulted only once, as migration
input, by keystore.py::ensure_legacy_keys_migrated -- the keystore, once
seeded, is the sole runtime source of truth (see app.py::_check_auth). This
one function survives here because it only needs to know whether ANY auth
is configured, not how to check it.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Make `shared` resolvable regardless of how this module is imported -- same
# fix as keystore.py/store.py's identical comment (2026-08-07, Task K).
_SERVICES_DIR = Path(__file__).resolve().parent.parent
if str(_SERVICES_DIR) not in sys.path:
    sys.path.insert(0, str(_SERVICES_DIR))

from shared.log import get_logger  # noqa: E402


def warn_if_disabled(service: str, keystore) -> None:
    if keystore.count() == 0:
        get_logger(service).warn(
            "auth disabled: no keys provisioned (FENGARDE_API_KEY / "
            "FENGARDE_API_KEYS / manage_keys.py never configured)"
        )


def require_auth_or_die(service: str, keystore) -> None:
    """Gap-hunt finding (2026-08-23): shared/authz.py::require_auth_or_die's
    own module docstring claimed to cover "WS-3/WS-6 HTTP write surfaces,"
    but ws6-inventory never imported or called it -- it has always used its
    own keystore-based auth (this module), which `require_auth_or_die`
    knows nothing about. An operator setting FENGARDE_REQUIRE_AUTH=1
    expecting a deployment-wide "refuse to boot open" guarantee got it for
    ws3-indexer only; ws6-inventory booted open regardless, with nothing
    louder than warn_if_disabled's log line.

    Same fail-loud contract as the shared version: a no-op unless
    FENGARDE_REQUIRE_AUTH is 1/true/yes, in which case an empty keystore
    (no key ever provisioned) exits(1) with a clear message instead of
    silently serving every request unauthenticated.
    """
    if os.getenv("FENGARDE_REQUIRE_AUTH", "").strip().lower() not in ("1", "true", "yes"):
        return
    if keystore.count() == 0:
        get_logger(service).error(
            "FENGARDE_REQUIRE_AUTH=1 but no keys are provisioned "
            "(FENGARDE_API_KEY / FENGARDE_API_KEYS / manage_keys.py never configured)"
        )
        sys.exit(1)
