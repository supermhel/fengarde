"""oracle_provenance -- pin an oracle to the rule text it was authored from.

WHY (2026-10-03). An oracle written from the rules' DOCUMENTED INTENT (before the pipeline is
run against the storyline) is only independent of the system if nobody later edits it to match
what the system did -- or edits the rule and lets the oracle follow. The honest limit: nothing can
PROVE an oracle was authored before a run. What can be proven mechanically is the other half:
the oracle records, per rule it was written against, a digest of that rule's normalised
``description`` + ``detection`` + ``siem`` blocks. If a rule's documented intent or its
selection or its threshold changes, the digest changes, the check FAILS, and the oracle has to be
re-read by a human and re-pinned deliberately. A rule edit can no longer silently re-baseline an
answer key.

The block lives under a top-level ``provenance:`` key of an ``oracle_<name>.yaml``::

    provenance:
      authored: "2026-10-03"
      pipeline_run_before_authoring: false
      basis: "rule description/detection/siem blocks and parser docstrings only"
      rules_read:
        common_beaconing: "<sha256>"

``rules_read`` is keyed by rule FILE STEM. The check also requires every rule id the oracle names
(``expected_rules`` / ``must_not_fire``) to appear in ``rules_read``: an oracle may not lean on a
rule it does not claim to have read.

STDLIB + PyYAML. Deterministic.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = ROOT / "contracts" / "rules"

_WS = re.compile(r"\s+")


def _normalise(value):
    """Whitespace-fold every string so re-wrapping a description does not change the digest;
    keep everything else exactly (a changed threshold must change it)."""
    if isinstance(value, str):
        return _WS.sub(" ", value).strip()
    if isinstance(value, dict):
        return {k: _normalise(v) for k, v in sorted(value.items())}
    if isinstance(value, (list, tuple)):
        return [_normalise(v) for v in value]
    return value


def rule_digest(rule: dict) -> str:
    """sha256 over the normalised ``description`` + ``detection`` + ``siem`` blocks."""
    blob = {k: _normalise(rule.get(k)) for k in ("description", "detection", "siem")}
    return hashlib.sha256(json.dumps(blob, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


def load_rules(rules_dir: Path = RULES_DIR) -> dict:
    """``{file_stem: rule dict}`` for every rule file under ``rules_dir``."""
    out = {}
    for f in sorted(Path(rules_dir).glob("*.yml")):
        d = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        if isinstance(d, dict) and d.get("id"):
            out[f.stem] = d
    return out


def digests_for(stems, rules_dir: Path = RULES_DIR) -> dict:
    rules = load_rules(rules_dir)
    return {s: rule_digest(rules[s]) for s in sorted(stems)}


def rule_ids_named(oracle: dict) -> set:
    """Every rule id the oracle's detection points rely on (expected or forbidden)."""
    out = set()
    for pt in (oracle.get("detection_points") or {}).values():
        out |= {r.get("rule_id") for r in (pt.get("expected_rules") or []) if r.get("rule_id")}
        out |= set(pt.get("must_not_fire") or [])
    return out


def check(oracle: dict, rules_dir: Path = RULES_DIR) -> list:
    """Problems (empty == the oracle still matches the rule text it was authored from).
    An oracle with no ``provenance`` block has nothing to check and returns ``None``."""
    prov = oracle.get("provenance")
    if prov is None:
        return None
    problems = []
    if prov.get("pipeline_run_before_authoring") is not False:
        problems.append("provenance must state pipeline_run_before_authoring: false")
    if not prov.get("authored"):
        problems.append("provenance has no authored date")
    read = prov.get("rules_read") or {}
    if not read:
        problems.append("provenance.rules_read is empty")
    rules = load_rules(rules_dir)
    by_id = {r["id"]: stem for stem, r in rules.items()}
    for stem, want in sorted(read.items()):
        if stem not in rules:
            problems.append(f"rules_read names {stem!r}, which is not a rule file")
        elif rule_digest(rules[stem]) != want:
            problems.append(f"rule {stem!r} changed since this oracle was authored from it "
                            "(description/detection/siem digest differs): re-read the rule, then re-pin")
    for rid in sorted(rule_ids_named(oracle)):
        stem = by_id.get(rid)
        if stem is None:
            problems.append(f"oracle names rule id {rid!r}, which is not a shipped rule")
        elif stem not in read:
            problems.append(f"oracle relies on {stem!r} but provenance.rules_read does not list it")
    return problems


def main(argv=None) -> int:  # pragma: no cover - helper: print the digests for a list of rule stems
    import sys
    stems = list(argv if argv is not None else sys.argv[1:])
    for stem, dig in digests_for(stems).items():
        print(f"{stem}: \"{dig}\"")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
