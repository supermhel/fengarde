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


def warn_if_disabled(service: str, keystore) -> None:
    if keystore.count() == 0:
        print(f'{{"level": "warning", "service": "{service}", '
              f'"msg": "auth disabled: no keys provisioned (FENGARDE_API_KEY / '
              f'FENGARDE_API_KEYS / manage_keys.py never configured)"}}', flush=True)
