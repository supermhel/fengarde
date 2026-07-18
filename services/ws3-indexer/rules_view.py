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

from pathlib import Path

import yaml

from shared.envelope import valid_tenant_id

_HERE = Path(__file__).resolve().parent
RULES_DIR = _HERE.parent.parent / "contracts" / "rules"
TENANTS_DIR = _HERE.parent.parent / "contracts" / "tenants"


def _disabled_for_tenant(tenant_id: str) -> frozenset:
    # reject-at-edge, never normalize (same convention as router.py /
    # ws4-detection/tenants.py, from the F3 adversarial-bug-hunt fix): an
    # unvalidated tenant_id here is a path-traversal primitive into
    # TENANTS_DIR (CodeQL py/path-injection, alerts #2/#3).
    if not valid_tenant_id(tenant_id):
        return frozenset()
    path = TENANTS_DIR / f"{tenant_id}.yml"
    if not path.exists():
        return frozenset()
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError:
        return frozenset()
    entries = raw.get("disabled_rules") if isinstance(raw, dict) else None
    return frozenset(e for e in (entries or []) if isinstance(e, str))


def list_rule_summaries(tenant_id: str | None = None) -> list[dict]:
    """One summary dict per rule file in RULES_DIR, sorted by id.

    ``tenant_id=None`` reports every rule as enabled (no tenant context --
    the global rule set). A real tenant id applies that tenant's
    disabled-rules list (contracts/tenants/<id>.yml; missing file or key ->
    nothing disabled, same fail-open convention as ws4-detection/tenants.py).
    """
    disabled = _disabled_for_tenant(tenant_id) if tenant_id else frozenset()
    summaries: list[dict] = []
    if not RULES_DIR.is_dir():
        return summaries
    for path in sorted(RULES_DIR.glob("*.yml")):
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if not isinstance(raw, dict):
            continue
        rule_id = raw.get("id")
        if not isinstance(rule_id, str):
            continue
        siem = raw.get("siem", {}) if isinstance(raw.get("siem"), dict) else {}
        summaries.append({
            "id": rule_id,
            "title": raw.get("title", "untitled"),
            "level": raw.get("level", "medium"),
            "sector": siem.get("sector", "common"),
            "score_weight": siem.get("score_weight", 0),
            "stateful": siem.get("window_seconds") is not None
            and siem.get("threshold") is not None,
            "mitre": raw.get("mitre"),
            "enabled": rule_id not in disabled,
        })
    summaries.sort(key=lambda r: r["id"])
    return summaries
