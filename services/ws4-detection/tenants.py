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

from collections import OrderedDict
from pathlib import Path

import yaml

from shared.envelope import valid_tenant_id

DEFAULT_TENANT = "default"

# P2-1 (2026-07-21 audit): tenant_id comes straight from event data
# (siem.tenant), so an external producer stuffing many DISTINCT tenant
# strings into events grows this cache once per distinct value seen --
# unbounded before this fix. Two-part mitigation:
#   1. An INVALID tenant_id (fails valid_tenant_id()) is never cached at
#      all -- re-validating a malformed string is a cheap regex match, and
#      caching it would let an attacker grow the dict for free with
#      arbitrary garbage (the cheapest possible exploit of this bug).
#   2. Even VALID-shaped tenant strings are capped at _CACHE_MAXSIZE via
#      simple LRU eviction (OrderedDict.move_to_end + popitem(last=False)):
#      an attacker could still spray many distinct VALID-shaped strings
#      (regex compliance doesn't bound cardinality), so the cache itself
#      needs a hard ceiling, not just a garbage filter.
_CACHE_MAXSIZE = 1000
_CACHE: "OrderedDict[str, frozenset]" = OrderedDict()


def _cache_get(key: str):
    if key not in _CACHE:
        return None
    _CACHE.move_to_end(key)  # LRU: most-recently-used moves to the end
    return _CACHE[key]


def _cache_put(key: str, value: frozenset) -> None:
    _CACHE[key] = value
    _CACHE.move_to_end(key)
    while len(_CACHE) > _CACHE_MAXSIZE:
        _CACHE.popitem(last=False)  # evict least-recently-used


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
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    disabled: frozenset
    # F3 (adversarial repo-wide bug hunt, 2026-07-16): tenant_id used to
    # flow straight into this filename with no validation -- a malformed
    # value (e.g. "../../../etc/passwd" without the trailing ".yml" this
    # still requires, or simply something containing "/") could construct
    # a path outside contracts/tenants/ entirely. Treat an invalid
    # tenant_id exactly like a missing config file: fail open (nothing
    # disabled, full detection still runs) rather than ever attempting the
    # file lookup -- same "a bad/missing config never silently reduces
    # detection coverage" convention this function already documents,
    # and it never even constructs the unsafe path.
    if tenant_id != DEFAULT_TENANT and not valid_tenant_id(tenant_id):
        return frozenset()  # invalid tenant_id never cached (see module note above)

    path = Path(tenants_dir) / f"{tenant_id}.yml"
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

    _cache_put(cache_key, disabled)
    return disabled
