"""M4.3: read-only rule summaries for the versioned REST API.

Deliberately independent of services/ws4-detection/engine.py: workstreams are
coupled ONLY through the bus (CLAUDE.md), so this does not import ws4's
condition-parsing Rule class. It reads the same frozen contract files
(contracts/rules/*.yml, contracts/tenants/<id>.yml) that ws4 reads, producing
a small summary (id/title/level/sector/scoring) -- never the raw `condition`
string. That is also a deliberate security boundary, not just a layering
one: SECURITY.md SS3 treats rule files as code an operator must review before
trusting; exposing the parsed condition (or any way to write one) over HTTP
would let an API caller inject detection logic without review. This module
is read-only and never touches `detection.condition`.
"""
from __future__ import annotations

import os
from pathlib import Path

import yaml

from shared.envelope import valid_tenant_id

_HERE = Path(__file__).resolve().parent
_SERVICES = _HERE.parent
_ROOT = _SERVICES.parent


def _contracts_dir() -> Path:
    """contracts/ lives at repo/contracts on a host checkout (_HERE =
    repo/services/ws3-indexer, so two parents up) but at /app/contracts in
    the container (Dockerfile COPYs it straight to /app, and _HERE there is
    /app/ws3-indexer -- only ONE parent up). A fixed parent-count breaks one
    of the two layouts; probe both, same pattern as
    services/ws4-detection/main.py::_contracts_dir(). This was a real,
    previously undetected bug: GET /rules returned zero rules on every live
    Docker deployment (silently -- RULES_DIR.is_dir() was False, and
    list_rule_summaries() returns [] for a missing dir, the same fail-open
    convention as a missing tenant config), only masked because the
    zero-infra contract tests run on a host checkout where the old two-
    parents-up math happened to be correct.
    """
    for base in (_SERVICES, _ROOT):
        if (base / "contracts" / "rules").is_dir():
            return base / "contracts"
    return _ROOT / "contracts"


_CONTRACTS = _contracts_dir()
RULES_DIR = _CONTRACTS / "rules"
TENANTS_DIR = _CONTRACTS / "tenants"


def _tenant_rule_lists(tenant_id: str | None) -> tuple[frozenset, frozenset]:
    # Explicitly resolve the None case up-front, before the fail-open path:
    # WS-7's getRules() and triage_api's route send NO tenant_id precisely for
    # the single-tenant admin session that owns the DEFAULT tenant's events, and
    # WS-4's Detector processes every event without siem.tenant against
    # DEFAULT_TENANT ("default"). Reading the default.yml opt-in here is what
    # makes the /rules report agree with the Detector for that path (review
    # finding 2026-10-13: the None branch used to read NO tenant file, so a
    # default.yml opt-in fired in the engine while /rules said enabled=False).
    if tenant_id is None:
        tenant_id = "default"
    # The request-controlled tenant_id NEVER becomes part of a path
    # expression. Instead of building `TENANTS_DIR / f"{tenant_id}.yml"`
    # (a path-traversal primitive -- CodeQL py/path-injection; two earlier
    # attempts at sanitizing the constructed path still left taint reaching
    # resolve()/exists()/read_text()), we enumerate the trusted directory
    # and select by exact stem match. Every path opened comes from
    # TENANTS_DIR.glob() -- untainted by construction -- so escape is
    # structurally impossible, not merely checked for.
    #
    # valid_tenant_id() stays as the first gate: same reject-at-edge,
    # never-normalize convention as router.py / ws4-detection/tenants.py
    # (the F3 adversarial-bug-hunt fix).
    #
    # Returns (disabled_rules, enabled_rules). Every failure path (invalid id,
    # no file, bad YAML, wrong shape) yields EMPTY sets -- same fail-safe
    # direction as ws4-detection/tenants.py: a broken config never turns a
    # default-off rule on and never turns a default-on rule off.
    empty: tuple[frozenset, frozenset] = (frozenset(), frozenset())
    if not valid_tenant_id(tenant_id):
        return empty
    path = next((p for p in TENANTS_DIR.glob("*.yml") if p.stem == tenant_id),
                None)
    if path is None:
        return empty
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:  # YAMLError, UnicodeDecodeError (wrong encoding), PermissionError, OSError...
        # Fail-open contract (matching ws4-detection/tenants.py::_load_config):
        # an unreadable/invalid tenant file must not 500 GET /rules nor silently
        # change any rule's effective state -- it reports like a missing file.
        return empty

    def ids(key: str) -> frozenset:
        entries = raw.get(key) if isinstance(raw, dict) else None
        if not isinstance(entries, (list, tuple)):
            return frozenset()
        return frozenset(e for e in entries if isinstance(e, str))

    return ids("disabled_rules"), ids("enabled_rules")


def _disabled_for_tenant(tenant_id: str) -> frozenset:
    return _tenant_rule_lists(tenant_id)[0]


def _env_opt_in() -> frozenset:
    """FENGARDE_OPT_IN_RULES as WS-3 sees it. The variable is read by WS-4, not
    WS-3: set it on both services (or use a tenant file's enabled_rules) or this
    view cannot know about it."""
    return frozenset(i.strip() for i in os.environ.get("FENGARDE_OPT_IN_RULES", "").split(",")
                     if i.strip())


def _plugin_dirs() -> list[Path]:
    """Plugin rule-pack dirs WS-3 should list alongside RULES_DIR.

    WS-4 discovers rule packs via the ``fengarde.rule_packs`` entry-point group
    (services/ws4-detection/plugins.py). WS-3 must not import WS-4 modules, so
    the /rules view gets them from ``FENGARDE_PLUGIN_RULE_DIRS`` (path-separator
    separated, same variable name a compose overlay can set on both services) --
    the operator keeps the two in sync, exactly like FENGARDE_OPT_IN_RULES."""
    raw = os.environ.get("FENGARDE_PLUGIN_RULE_DIRS", "")
    out: list[Path] = []
    for part in raw.split(os.pathsep):
        part = part.strip()
        if part:
            out.append(Path(part))
    return out


def list_rule_summaries(tenant_id: str | None = None) -> list[dict]:
    """One summary dict per rule file in RULES_DIR, sorted by id.

    ``tenant_id=None`` reads the DEFAULT tenant config (contracts/tenants/
    default.yml) -- the exact config WS-4 applies to every event without a
    ``siem.tenant`` -- so the report agrees with the Detector for the
    single-tenant admin path that sends no tenant_id. A default-off rule
    (``siem.default_enabled: false``) is reported enabled only when it is
    opted in: by that tenant's enabled_rules, or by FENGARDE_OPT_IN_RULES.
    ``default_enabled`` / ``opt_in`` explain why a rule is off. As in WS-4,
    disabled_rules wins over every opt-in. A real tenant id applies that tenant's
    disabled-rules list (contracts/tenants/<id>.yml; missing file or key ->
    nothing disabled, same fail-open convention as ws4-detection/tenants.py).
    Rules shipped in plugin packs (FENGARDE_PLUGIN_RULE_DIRS) are listed too,
    deduplicated by id with the built-in dir winning (same as Detector._load).
    """
    disabled, enabled = _tenant_rule_lists(tenant_id)
    opted_in = enabled | _env_opt_in()
    summaries: list[dict] = []
    if not RULES_DIR.is_dir():
        return summaries
    parsed: list[tuple[dict, dict]] = []
    default_off_ids: set[str] = set()
    seen_ids: set[str] = set()
    rule_dirs = [RULES_DIR] + _plugin_dirs()
    for d in rule_dirs:
        if not Path(d).is_dir():
            continue
        for path in sorted(Path(d).glob("*.yml")):
            try:
                raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            except yaml.YAMLError:
                continue
            if not isinstance(raw, dict):
                continue
            rule_id = raw.get("id")
            if not isinstance(rule_id, str):
                continue
            # same dedup as ws4 Detector._load: first-loaded id wins, a plugin
            # can extend the set but never silently replace a built-in rule.
            if rule_id in seen_ids:
                continue
            seen_ids.add(rule_id)
            siem = raw.get("siem", {}) if isinstance(raw.get("siem"), dict) else {}
            if siem.get("default_enabled", True) is False:   # same literal-False rule as the engine
                default_off_ids.add(rule_id)
            parsed.append((raw, siem))
    for raw, siem in parsed:
        rule_id = raw["id"]
        # Only a non-empty str can name a sibling. A list/dict value (a typo the
        # validator rejects, but this view must not depend on that) is
        # unhashable, and `value in <set>` raised TypeError and took the whole
        # /rules listing down with it.
        companion_of = siem.get("companion_of")
        has_sibling = isinstance(companion_of, str) and bool(companion_of)
        # Effective default: a companion of a default-off sibling is default-off
        # too (mirrors Detector._load in ws4-detection/main.py).
        default_enabled = rule_id not in default_off_ids and not (
            has_sibling and companion_of in default_off_ids)
        opt_in = rule_id in opted_in
        summaries.append({
            "id": rule_id,
            "title": raw.get("title", "untitled"),
            "level": raw.get("level", "medium"),
            "sector": siem.get("sector", "common"),
            "score_weight": siem.get("score_weight", 0),
            "stateful": siem.get("window_seconds") is not None
            and siem.get("threshold") is not None,
            "mitre": raw.get("mitre"),
            # why a rule is off: it ships default-off (default_enabled False) and
            # this tenant has not opted in (opt_in False), or it is disabled.
            "default_enabled": default_enabled,
            "opt_in": opt_in,
            "enabled": (rule_id not in disabled
                        and not (has_sibling and companion_of in disabled)
                        and (default_enabled or opt_in)),
        })
    summaries.sort(key=lambda r: r["id"])
    return summaries
