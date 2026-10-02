"""M4 multi-tenancy: per-tenant rule enablement.

A tenant config (`contracts/tenants/<tenant_id>.yml`) lists rule ids
DISABLED for that tenant (`disabled_rules`) and, optionally, rule ids the
tenant OPTS IN to (`enabled_rules`; only meaningful for rules shipped with
`siem.default_enabled: false`, see load_enabled_rules). If a rule is in both
lists, disabled wins. Missing file, missing `disabled_rules` key, or an
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

import sys
from collections import OrderedDict
from pathlib import Path

import yaml

# Make `shared` resolvable regardless of how tenants.py is imported -- same
# fix as engine.py's identical comment (2026-08-07).
_SERVICES_DIR = Path(__file__).resolve().parent.parent
if str(_SERVICES_DIR) not in sys.path:
    sys.path.insert(0, str(_SERVICES_DIR))

from shared.envelope import valid_tenant_id  # noqa: E402
from shared.log import get_logger  # noqa: E402

_log = get_logger("ws4-detection")

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
_CACHE: "OrderedDict[str, tuple[frozenset, frozenset]]" = OrderedDict()


def _cache_get(key: str):
    if key not in _CACHE:
        return None
    _CACHE.move_to_end(key)  # LRU: most-recently-used moves to the end
    return _CACHE[key]


def _cache_put(key: str, value: "tuple[frozenset, frozenset]") -> None:
    _CACHE[key] = value
    _CACHE.move_to_end(key)
    while len(_CACHE) > _CACHE_MAXSIZE:
        _CACHE.popitem(last=False)  # evict least-recently-used


def invalidate_cache() -> None:
    """Drop every cached per-tenant disabled-rules set.

    main.py's hot-reload watcher only ever polled RULES_DIR/ALLOWLISTS_DIR's
    mtime, never TENANTS_DIR -- so an operator editing a tenant config
    on-disk (e.g. re-enabling a rule mid-incident) had no effect until the
    whole process restarted, since `load_disabled_rules` had no TTL/mtime
    check of its own and nothing else ever called this. The watcher now
    polls TENANTS_DIR too and calls this whenever it changes."""
    _CACHE.clear()


def tenant_of(event: dict) -> str:
    """The tenant_id an event/alert belongs to (envelope v1's siem.tenant,
    or the alert's own tenant_id field). Absent -> "default", matching every
    pre-M4 producer (services/shared/envelope.py::default_tenant())."""
    if "tenant_id" in event:  # alert shape
        return event.get("tenant_id") or DEFAULT_TENANT
    return (event.get("siem") or {}).get("tenant") or DEFAULT_TENANT


_EMPTY: "tuple[frozenset, frozenset]" = (frozenset(), frozenset())


def _id_set(raw, key: str) -> frozenset:
    entries = raw.get(key) if isinstance(raw, dict) else None
    if not isinstance(entries, (list, tuple)):
        return frozenset()
    return frozenset(e for e in entries if isinstance(e, str))


def _load_config(tenants_dir: Path, tenant_id: str) -> "tuple[frozenset, frozenset]":
    """Load (and cache) (disabled_rules, enabled_rules) for one tenant.

    ONE file read and ONE cache entry serve both lists, so the two public
    loaders can never disagree about which version of the file they saw and
    invalidate_cache() drops both together.

    Fail-safe direction for every failure (invalid tenant_id, missing file,
    bad YAML, wrong shape): BOTH sets empty. Empty `disabled` means a
    default-on rule is never turned off by a broken config; empty `enabled`
    means a default-off rule is never turned ON by one (opt-in is explicit)."""
    cache_key = f"{Path(tenants_dir).resolve()}::{tenant_id}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    # F3 (adversarial repo-wide bug hunt, 2026-07-16): tenant_id used to
    # flow straight into this filename with no validation -- a malformed
    # value (e.g. one containing "/") could construct a path outside
    # contracts/tenants/ entirely. Treat an invalid tenant_id exactly like a
    # missing config file: fail open (nothing disabled, nothing opted in)
    # rather than ever attempting the file lookup. Never cached (see the
    # module note above).
    if tenant_id != DEFAULT_TENANT and not valid_tenant_id(tenant_id):
        return _EMPTY

    path = Path(tenants_dir) / f"{tenant_id}.yml"
    if not path.exists():
        cfg = _EMPTY
    else:
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            cfg = (_id_set(raw, "disabled_rules"), _id_set(raw, "enabled_rules"))
        except Exception as exc:  # bad YAML/shape -> fail open (nothing disabled, nothing opted in)
            _log.warn(
                f"tenant config '{tenant_id}' failed to load ({exc}); "
                f"no rules disabled and no default-off rules opted in for this tenant (fail open)."
            )
            cfg = _EMPTY

    _cache_put(cache_key, cfg)
    return cfg


def load_disabled_rules(tenants_dir: Path, tenant_id: str) -> frozenset:
    """Load (and cache) the set of rule ids disabled for one tenant."""
    return _load_config(tenants_dir, tenant_id)[0]


def load_enabled_rules(tenants_dir: Path, tenant_id: str) -> frozenset:
    """Load (and cache) the set of rule ids a tenant has OPTED IN to.

    Only rules shipped with `siem.default_enabled: false` need this; listing a
    default-on rule is a harmless no-op. Same shape/validation/caching rules as
    load_disabled_rules. A missing or broken config yields the empty set, so
    it can never switch a default-off rule on. `disabled_rules` always wins
    over `enabled_rules` (enforced by Detector.process)."""
    return _load_config(tenants_dir, tenant_id)[1]
