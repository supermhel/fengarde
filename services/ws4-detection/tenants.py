"""M4 multi-tenancy: per-tenant rule enablement.

A tenant config (`contracts/tenants/<tenant_id>.yml`) lists rule ids
DISABLED for that tenant. Missing file, missing `disabled_rules` key, or an
unrecognized tenant -> empty disabled set -> every global rule still
evaluates for that tenant's events. This mirrors the allowlist convention in
engine.py (`load_allowlist`): a MISSING config must never silently reduce
detection coverage, only an explicit, present entry does.

This is deliberately an ENABLEMENT list, not a full per-tenant rule-pack
system (each tenant gets a subset of the same global rules, not their own
custom conditions) -- the simplest mechanism that satisfies the M4 ask
("per-tenant rule enablement/allowlists") without forking the rule engine's
single global rule set per tenant.
"""
from __future__ import annotations

from pathlib import Path

import yaml

DEFAULT_TENANT = "default"

_CACHE: dict[str, frozenset] = {}


def tenant_of(event: dict) -> str:
    """The tenant_id an event/alert belongs to (envelope v1's siem.tenant,
    or the alert's own tenant_id field). Absent -> "default", matching every
    pre-M4 producer (services/shared/envelope.py::default_tenant())."""
    if "tenant_id" in event:  # alert shape
        return event.get("tenant_id") or DEFAULT_TENANT
    return (event.get("siem") or {}).get("tenant") or DEFAULT_TENANT


def load_disabled_rules(tenants_dir: Path, tenant_id: str) -> frozenset:
    """Load (and cache) the set of rule ids disabled for one tenant."""
    cache_key = f"{Path(tenants_dir).resolve()}::{tenant_id}"
    if cache_key in _CACHE:
        return _CACHE[cache_key]

    path = Path(tenants_dir) / f"{tenant_id}.yml"
    disabled: frozenset
    if not path.exists():
        disabled = frozenset()
    else:
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            entries = raw.get("disabled_rules") if isinstance(raw, dict) else None
            disabled = frozenset(e for e in (entries or []) if isinstance(e, str))
        except Exception as exc:  # bad YAML/shape -> fail open (nothing disabled)
            print(f"[tenants] WARNING: tenant config '{tenant_id}' failed to "
                  f"load ({exc}); no rules disabled for this tenant (fail open).")
            disabled = frozenset()

    _CACHE[cache_key] = disabled
    return disabled
