"""Per-tenant identity alias map (finding F2, owner decision 2026-10-21).

WS-4 groups accounts by ``strip().casefold()``. A Windows source also treats
``CORP\\jdoe``, ``jdoe@corp.example`` and (inside one realm) ``jdoe`` as ONE principal, so an
attacker could keep each spelling under a threshold. This module lets an operator DECLARE which
realm spellings are the same realm, per tenant. Without a map nothing is merged: the code never
guesses that two names are the same person (a wrong merge raises false alerts).

File format (``contracts/identity_aliases.yaml`` or ``$FENGARDE_IDENTITY_ALIASES``)::

    version: 1
    tenants:
      acme:                          # a valid tenant id; never "*"
        default_realm: corp          # optional: a bare name belongs to this realm
        realms:
          - [CORP, corp.example]     # spellings of ONE realm (>= 2, case-insensitive)

``CORP\\jdoe`` and ``jdoe@corp.example`` then both canonicalise to ``jdoe@corp`` (the first
spelling of the group). Anything malformed raises :class:`IdentityAliasError` at load time; the
caller must refuse to start / keep the previous map, never run with a half-read map.
"""
from __future__ import annotations

import os
from pathlib import Path

import yaml

from shared.envelope import valid_tenant_id


class IdentityAliasError(ValueError):
    """The alias map is malformed. Fail closed: do not run with a partial map."""


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _no_dup_mapping(loader, node, deep=False):
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise IdentityAliasError(f"duplicate key {key!r} (a tenant or field listed twice)")
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep)


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_dup_mapping)

_TOP_KEYS = {"version", "tenants"}
_TENANT_KEYS = {"realms", "default_realm"}
_BAD_REALM_CHARS = set("\\@:/* \t")


def _realm(value, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise IdentityAliasError(f"{where}: realm must be a non-empty string, got {value!r}")
    if any(c in _BAD_REALM_CHARS for c in value):
        raise IdentityAliasError(
            f"{where}: realm {value!r} must not contain whitespace or any of \\ @ : / * "
            f"(a tenant-qualified or wildcard realm would merge across tenants)")
    return value.casefold()


class TenantMap:
    """realm spelling -> canonical realm, for ONE tenant."""

    def __init__(self, realm_to_canon: dict[str, str], default_realm: str | None):
        self.realm_to_canon = realm_to_canon
        self.default_realm = default_realm

    def match(self, folded: str) -> str | None:
        """``folded`` is already strip().casefold(). The ``name@realm`` form when its realm is listed
        for this tenant, else None (an unlisted spelling is never merged)."""
        if "\\" in folded:
            realm, _, name = folded.partition("\\")
        elif "@" in folded:
            name, _, realm = folded.rpartition("@")
        else:
            realm, name = (self.default_realm or ""), folded
        canon = self.realm_to_canon.get(realm)
        if canon is None or not name or "\\" in name or "@" in name:
            return None
        return f"{name}@{canon}"

    def canonical(self, folded: str) -> str:
        return self.match(folded) or folded


class IdentityAliases:
    def __init__(self, tenants: dict[str, TenantMap] | None = None):
        self._tenants = tenants or {}

    def canonical_account(self, tenant: str, value: str) -> str:
        folded = value.strip().casefold()
        tmap = self._tenants.get(tenant)
        return folded if tmap is None else tmap.canonical(folded)

    def alias_of(self, tenant: str, value: str) -> str | None:
        """The aliased canonical form of ``value`` for ``tenant``, or None when no alias applies (no map for
        the tenant, or the realm is not listed). WS-8 uses this to leave un-aliased alerts byte-identical."""
        tmap = self._tenants.get(tenant)
        return None if tmap is None else tmap.match(value.strip().casefold())

    def __bool__(self) -> bool:
        return bool(self._tenants)


def parse(doc) -> IdentityAliases:
    if doc is None:
        return IdentityAliases()
    if not isinstance(doc, dict) or set(doc) - _TOP_KEYS:
        raise IdentityAliasError(
            f"top level must be a mapping with only {sorted(_TOP_KEYS)}; got "
            f"{sorted(map(str, doc)) if isinstance(doc, dict) else type(doc).__name__} "
            f"(global, non-tenant entries are not allowed)")
    if doc.get("version") != 1:
        raise IdentityAliasError(f"version must be 1, got {doc.get('version')!r}")
    tenants = doc.get("tenants")
    if tenants is None:
        return IdentityAliases()
    if not isinstance(tenants, dict):
        raise IdentityAliasError("'tenants' must be a mapping of tenant id -> map")
    out: dict[str, TenantMap] = {}
    for tid, body in tenants.items():
        if not valid_tenant_id(tid):
            raise IdentityAliasError(f"tenant id {tid!r} is not a valid tenant id (no wildcards)")
        if not isinstance(body, dict) or set(body) - _TENANT_KEYS:
            raise IdentityAliasError(f"tenant {tid!r}: only {sorted(_TENANT_KEYS)} are allowed")
        realms = body.get("realms")
        if not isinstance(realms, list) or not realms:
            raise IdentityAliasError(f"tenant {tid!r}: 'realms' must be a non-empty list of groups")
        mapping: dict[str, str] = {}
        for i, group in enumerate(realms):
            where = f"tenant {tid!r} realms[{i}]"
            if not isinstance(group, list) or len(group) < 2:
                raise IdentityAliasError(f"{where}: a group needs at least 2 spellings of one realm")
            folded = [_realm(r, where) for r in group]
            canon = folded[0]
            for r in folded:
                if r in mapping and mapping[r] != canon:
                    raise IdentityAliasError(
                        f"{where}: realm {r!r} is already in another group of this tenant "
                        f"(groups must be disjoint; chains would merge by transitivity)")
                mapping[r] = canon
        default = body.get("default_realm")
        if default is not None:
            default = _realm(default, f"tenant {tid!r} default_realm")
            if default not in mapping:
                raise IdentityAliasError(f"tenant {tid!r}: default_realm {default!r} is not in any realms group")
        out[tid] = TenantMap(mapping, default)
    return IdentityAliases(out)


def load(path: str | Path) -> IdentityAliases:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise IdentityAliasError(f"cannot read identity alias map {p}: {exc}") from exc
    try:
        doc = yaml.load(text, Loader=_UniqueKeyLoader)  # noqa: S506 - SafeLoader subclass
    except yaml.YAMLError as exc:
        raise IdentityAliasError(f"identity alias map {p} is not valid YAML: {exc}") from exc
    try:
        return parse(doc)
    except IdentityAliasError as exc:
        raise IdentityAliasError(f"identity alias map {p}: {exc}") from exc


# ---- process-wide active map (WS-4 grouping, WS-8 tracks, WS-9 entities all read THIS one) ----
_ACTIVE = IdentityAliases()
#: repo checkout: <root>/services/shared -> <root>/contracts ; container: /app/shared -> /app/contracts
_DEFAULT_FILES = (Path(__file__).resolve().parent.parent / "contracts" / "identity_aliases.yaml",
                  Path(__file__).resolve().parent.parent.parent / "contracts" / "identity_aliases.yaml")


def configure(path=None) -> IdentityAliases:
    """Load the active map: ``path``, else ``$FENGARDE_IDENTITY_ALIASES`` (must exist), else the shipped
    ``contracts/identity_aliases.yaml`` if present. Raises IdentityAliasError and leaves the previous map
    active; never installs a partial map. Every service that keys on an account calls this at start."""
    global _ACTIVE
    env = os.environ.get("FENGARDE_IDENTITY_ALIASES", "").strip()
    chosen = path or env or next((f for f in _DEFAULT_FILES if f.exists()), None)
    _ACTIVE = load(chosen) if chosen else IdentityAliases()
    return _ACTIVE


def canonical_account(tenant: str, value: str) -> str:
    """The one canonical-actor function: strip().casefold() plus the tenant's explicit realm map."""
    return _ACTIVE.canonical_account(tenant, value)


def alias_of(tenant: str, value: str) -> str | None:
    return _ACTIVE.alias_of(tenant, value)
