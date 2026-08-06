from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "contracts" / "rules"
ALLOWLISTS_DIR = ROOT / "contracts" / "allowlists"

# Local operators supported by ws4-detection/engine.py.
_SUPPORTED_OPS = {
    "gt", "gte", "lt", "lte", "ne",
    "in", "contains", "not_in", "outside_hours", "glob",
}

# Sentinel for values that must be dropped from a selection rather than
# propagated as unsupported operators.
_DROP = object()

# Sigma uses arbitrary selection names; the engine tokenizer accepts `[\w.]+`.
# We sanitize names by lowercasing and replacing every non-[a-z0-9_] run.
_NAME_RE = re.compile(r"[^a-z0-9_]+")
_CONDITION_KEYWORDS = {"and", "or", "not"}


def _sanitize_name(name: str) -> str:
    out = _NAME_RE.sub("_", name.lower()).strip("_")
    return out or "_"


def _make_fake_id(title: str) -> str:
    import uuid
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, title))


def _level_from_sigma(level: str | None) -> str:
    mapping = {
        "informational": "informational",
        "low": "low",
        "medium": "medium",
        "high": "high",
        "critical": "critical",
    }
    return mapping.get((level or "").lower(), "medium")


def _safe_glob_from_regex(pattern: str) -> str | None:
    """Best-effort translation of a bounded regex to a glob pattern.

    Supports only anchored literal prefixes/suffixes with a single `.*` in the
    middle, or a fully literal pattern. Anything more complex is rejected to
    keep ADR-005's no-ReDoS guarantee.
    """
    if not isinstance(pattern, str) or not pattern or len(pattern) > 200:
        return None
    pat = pattern.strip()
    if pat.startswith("^"):
        pat = pat[len("^") :]
    if pat.endswith("$"):
        pat = pat[:-1]
    if not pat:
        return None
    if ".*" in pat:
        parts = pat.split(".*", 1)
        if len(parts) != 2 or parts[0].count(".*") or parts[1].count(".*"):
            return None
        if re.search(r"[^a-zA-Z0-9_.\-/ ]", parts[0] + parts[1]):
            return None
        return parts[0] + "*" + parts[1]
    if re.fullmatch(r"[a-zA-Z0-9_.\-/ ]*", pat):
        # A bare '.' (not part of a '.*' wildcard -- that case returned
        # above) is a regex "match any char" operator. Translated to a glob
        # it would become a LITERAL dot, silently narrowing the rule to a
        # subset of what Sigma intended. Reject instead of narrowing.
        if "." in pat:
            return None
        return pat
    return None


def _translate_modifier(field: str, value: Any) -> tuple[str, Any]:
    """Translate a Sigma `field|modifier: value` pair to local field/op/value.

    Supported modifiers: contains, startswith, endswith, re.
    """
    if "|" not in field:
        return field, value
    field_name, modifier = field.split("|", 1)
    field_name = field_name.strip()
    modifier = modifier.lower().strip()
    if modifier == "contains":
        return field_name, {"contains": str(value)}
    if modifier == "startswith":
        return field_name, {"glob": f"{value}*"}
    if modifier == "endswith":
        return field_name, {"glob": f"*{value}"}
    if modifier == "re":
        if not isinstance(value, str) or len(value) > 200:
            return field_name, _DROP
        glob = _safe_glob_from_regex(value)
        if glob is None:
            return field_name, _DROP
        return field_name, {"glob": glob}
    return field_name, _DROP


def _rewrite_selection(
    name: str, value: Any, errors: list[str]
) -> list[tuple[str, dict[str, Any]]]:
    """Rewrite one Sigma selection into one or more sanitized local selections.

    Handles field-list OR shape by flattening each sub-selection into a named
    local selection. Returns a list of (selection_name, field_dict).
    """
    where = f"selection '{name}'"
    if isinstance(value, dict):
        rewritten: dict[str, Any] = {}
        source_suffix: dict[str, int] = {}
        for field, val in value.items():
            local_field, local_value = _translate_modifier(field, val)
            if local_value is _DROP:
                continue
            if isinstance(local_value, dict):
                unknown = sorted(set(local_value) - _SUPPORTED_OPS)
                if unknown:
                    errors.append(f"{where}.{field}: unsupported operator(s) {unknown}")
                    continue
            source_field = field.split("|", 1)[0].strip()
            if source_field in rewritten:
                source_suffix[source_field] = source_suffix.get(source_field, 0) + 1
                local_field = f"{local_field}_{source_suffix[source_field]}"
            rewritten[local_field] = local_value
        sanitized = _sanitize_name(name)
        return [(sanitized, rewritten)]

    if isinstance(value, list):
        items: list[tuple[str, dict[str, Any]]] = []
        for idx, item in enumerate(value, start=1):
            if not isinstance(item, dict):
                errors.append(f"{where}[{idx}]: expected mapping, got {type(item).__name__}")
                continue
            rewritten = {}
            source_suffix = {}
            for field, val in item.items():
                local_field, local_value = _translate_modifier(field, val)
                if local_value is _DROP:
                    continue
                source_field = field.split("|", 1)[0].strip()
                if source_field in rewritten:
                    source_suffix[source_field] = source_suffix.get(source_field, 0) + 1
                    local_field = f"{local_field}_{source_suffix[source_field]}"
                rewritten[local_field] = local_value
            if not rewritten:
                continue
            items.append((f"{_sanitize_name(name)}_{idx}", rewritten))
        if not items:
            errors.append(f"{where}: empty field list")
            return []
        return items

    errors.append(f"{where}: unsupported selection shape {type(value).__name__}")
    return []


def _rewrite_condition(condition: str, rename_map: dict[str, str]) -> str:
    """Substitute original Sigma selection names with their local equivalents.

    Single-pass on purpose: every source token is replaced at most once, so an
    inserted group expression (e.g. `(sel_1 or sel_2)`) is never rescanned and
    re-substituted by a later, differently-named entry in `rename_map`. The
    previous sequential-`re.sub` version could corrupt a condition whenever one
    original selection name was also a substring-token of another's expansion.
    """
    if not isinstance(condition, str) or not condition.strip():
        return ""

    def _sub(match: re.Match[str]) -> str:
        token = match.group(0)
        if token in _CONDITION_KEYWORDS:
            return token
        return rename_map.get(token, token)

    # Match on the ORIGINAL Sigma name charset, not the engine's `[\w.]+`:
    # source selection names are arbitrary (`Special-Name`), which is why
    # `_sanitize_name` exists at all. Tokenizing them with `[\w.]+` would split
    # `Special-Name` into two tokens that match no rename_map key.
    return re.sub(r"[^\s()]+", _sub, condition)


def _unknown_condition_refs(condition: str, known: set[str]) -> set[str]:
    """Identifier tokens in `condition` that name no existing selection.

    Catches both dangling references to selections dropped during import and
    Sigma aggregation syntax this importer does not support (`1 of them`,
    `all of sel*`), either of which would otherwise be emitted as a rule the
    engine cannot evaluate.
    """
    tokens = re.findall(r"[\w.]+", condition or "")
    return {t for t in tokens if t not in _CONDITION_KEYWORDS and t not in known}


def _rewrite_siem(siem: dict[str, Any], errors: list[str]) -> dict[str, Any]:
    allowed = {
        "sector", "score_weight", "window_seconds", "threshold",
        "group_by", "distinct_field", "periodicity", "llm_gate",
    }
    out: dict[str, Any] = {}
    for k, v in siem.items():
        if k not in allowed:
            errors.append(f"siem.{k}: unsupported key for import")
            continue
        if k in {"window_seconds", "threshold"}:
            if isinstance(v, bool) or not isinstance(v, int) or v <= 0:
                errors.append(f"siem.{k}: must be a positive int, got {v!r}")
                continue
        if k in {"group_by", "distinct_field"}:
            if not isinstance(v, str) or not v:
                errors.append(f"siem.{k}: must be a non-empty dotted path, got {v!r}")
                continue
            out[k] = v
            continue
        if k == "llm_gate":
            if not isinstance(v, bool):
                errors.append(f"siem.llm_gate: must be a bool, got {v!r}")
                continue
            out[k] = v
            continue
        out[k] = v
    return out


def import_sigma_rule(
    raw: dict[str, Any], errors: list[str] | None = None
) -> dict[str, Any] | None:
    """Convert a SigmaHQ-style rule dict to the local Contract D shape.

    Returns a converted rule dict, or None if the rule cannot be safely
    imported. The returned dict is meant to be dumped to
    `contracts/rules/<sector>_<name>.yml`.

    Pass a list as `errors` to receive every part of the source rule that was
    dropped, defaulted, or rejected -- an import can succeed while silently
    discarding real detection logic (unsupported modifiers, unsafe regexes),
    and a caller that never sees those has no way to know the imported rule is
    weaker than the Sigma original.
    """
    errors = [] if errors is None else errors
    rule_id = raw.get("id")
    title = raw.get("title") or raw.get("name") or "imported-sigma-rule"
    level = _level_from_sigma(raw.get("level"))
    description = raw.get("description")
    author = raw.get("author")
    tags = raw.get("tags") or []
    mitre_block = None
    if isinstance(tags, list):
        attack = []
        for tag in tags:
            if not isinstance(tag, str):
                continue
            if tag.startswith(("attack.", "attack-ics.", "atlas.")):
                attack.append(tag)
        if attack:
            mitre_block = {"technique": attack[0], "framework": "attack"}

    logsource = raw.get("logsource") or {}
    if not isinstance(logsource, dict):
        errors.append("logsource: must be a mapping")
        logsource = {}
    category = logsource.get("category")
    if not isinstance(category, str) or not category:
        errors.append("logsource.category: required for import")
        category = "common"

    detection = raw.get("detection") or {}
    if not isinstance(detection, dict):
        errors.append("detection: must be a mapping")
        return None

    new_det: dict[str, Any] = {}
    rename_map: dict[str, str] = {}
    groups: list[str] = []
    condition = detection.get("condition") if isinstance(detection, dict) else None

    for name, value in detection.items():
        if name == "condition":
            continue
        if not isinstance(value, (dict, list)):
            errors.append(f"selection '{name}': unsupported selection shape {type(value).__name__}")
            continue
        if _sanitize_name(name) in _CONDITION_KEYWORDS:
            # A selection whose name collides with a boolean keyword is
            # unreferenceable: `_rewrite_condition` must leave `and`/`or`/`not`
            # alone to preserve real operators, so the reference is never
            # substituted and the emitted condition is syntactically invalid.
            # That parses to False at evaluation time -- a rule that imports
            # cleanly and then silently never fires, which is strictly worse
            # than refusing the import.
            errors.append(
                f"selection '{name}': name collides with reserved condition "
                f"keyword '{_sanitize_name(name)}' and cannot be referenced"
            )
            return None
        local_names = []
        for sanitized, fields in _rewrite_selection(name, value, errors):
            if sanitized in new_det:
                sanitized = f"{sanitized}_{len(new_det)}"
            new_det[sanitized] = fields
            local_names.append(sanitized)
        if not local_names:
            continue
        # A Sigma list-selection means OR-of-items, and it expands to several
        # local selections. Every reference to the ORIGINAL name must therefore
        # resolve to the whole OR group: collapsing it to local_names[0] would
        # silently drop the remaining branches and narrow the rule.
        group = local_names[0] if len(local_names) == 1 else "(" + " or ".join(local_names) + ")"
        rename_map[name] = group
        groups.append(group)

    if not new_det:
        return None
    if any(not fields for fields in new_det.values()):
        return None

    if not isinstance(condition, str) or not condition.strip():
        # Sigma requires `detection.condition`; a rule without one is malformed
        # input, so this fallback is announced via `errors` rather than applied
        # silently. AND across distinct selections, but the OR inside a
        # list-selection group is real Sigma semantics and must survive --
        # AND-ing sibling branches of one list (same field, two values) yields
        # a rule that can never fire.
        errors.append("detection.condition: missing, defaulted to AND across selections")
        condition = " and ".join(groups)
    else:
        condition = _rewrite_condition(condition, rename_map)

    unknown_refs = _unknown_condition_refs(condition, set(new_det))
    if unknown_refs:
        errors.append(
            f"detection.condition: references unknown selection(s) {sorted(unknown_refs)}"
        )
        return None

    siem = raw.get("siem") or {}
    if not isinstance(siem, dict):
        errors.append("siem: must be a mapping")
        siem = {}
    siem_out = _rewrite_siem(siem, errors)

    out: dict[str, Any] = {
        "title": title,
        "id": rule_id if isinstance(rule_id, str) else _make_fake_id(title),
        "status": "stable",
        "level": level,
        "logsource": {"category": category},
        "detection": dict(new_det),
        "condition": condition,
        "siem": siem_out,
    }
    if description is not None:
        out["description"] = description
    if author is not None:
        out["author"] = author
    if mitre_block is not None:
        out["mitre"] = mitre_block
    if tags:
        out["tags"] = tags if isinstance(tags, list) else [tags]

    return out


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: python tools/import_sigma_rules.py <sigma-rule.yml> [out.yml]")
        return 2
    src = Path(argv[1])
    if not src.exists():
        print(f"[FAIL] {src} not found")
        return 2
    raw = yaml.safe_load(src.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        print("[FAIL] top-level Sigma rule must be a YAML mapping")
        return 2
    errors: list[str] = []
    rule = import_sigma_rule(raw, errors)
    if rule is None:
        print("[FAIL] rule could not be imported (unsupported shape)")
        for err in errors:
            print(f"   - {err}")
        return 1
    if len(argv) > 2:
        dst = Path(argv[2])
    else:
        dst = RULES_DIR / f"{_sanitize_name(rule['title'])}.yml"
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(
        yaml.safe_dump(rule, sort_keys=False, allow_unicode=True, width=200),
        encoding="utf-8",
    )
    print(f"[OK] imported -> {dst}")
    if errors:
        print(
            f"[WARN] {len(errors)} part(s) of the source rule were dropped or "
            f"defaulted -- the imported rule is NOT equivalent to the Sigma original:"
        )
        for err in errors:
            print(f"   - {err}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
