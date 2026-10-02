"""Technique-label matching for the blind-recall lane (pure; no I/O except
``load_rule_index``).

The blind-recall lane scores the engine against the DATASET AUTHOR's ATT&CK
label, never against anything FENGARDE wrote. This module is the only place
that decides whether "a rule that declares technique R" counts as covering
"a dataset labelled L".

Match semantics (pinned by test_blind_recall.py):

* ``exact``  -- L == R.
* ``family`` -- L and R share a parent technique and AT LEAST ONE of them is
  the parent itself (``T1110.003`` vs a ``T1110`` rule, or ``T1110`` vs a
  ``T1110.004`` rule). A parent-level rule is declared to cover the family,
  and a parent-level label ("sub-technique unspecified") is satisfied by any
  rule in the family.
* ``None``   -- anything else. In particular SIBLING sub-techniques never
  match each other: ``T1110.003`` (password spraying) vs ``T1110.004``
  (credential stuffing). ``contracts/rules/common_password_spray.yml`` is
  deliberately T1110.004 (re-tagged 2026-08-26, many sources against one
  account) and true one-source-many-accounts spraying is a documented gap, so
  crediting that rule for a T1110.003 dataset would re-claim coverage the
  repo disclaims.

Funnel buckets (one per scored unit, assigned in ``classify`` order):

    NOT_FETCHED         declared by the corpus but no readable file is present
                        (absent, or an un-pulled git-lfs pointer)
    READER_UNAVAILABLE  files present but the reader dependency is missing
                        (python-evtx for .evtx); a tooling gap, not a verdict
    UNLABELLED          no usable ATT&CK label could be derived from the
                        dataset's own metadata/path
    NO_PARSER           no shipped WS-2 parser sees any record of the dataset
    NO_RULE             parser exists, but no loaded enterprise-ATT&CK rule is
                        in the label's technique family
    HIT_EXACT           an in-family alert fired whose rule technique == label
    HIT_FAMILY          an in-family alert fired (same parent, not equal)
    MISS                parser AND rule exist, no in-family alert fired

``HIT_TACTIC`` (tactic-level credit via the STIX map) is NOT implemented in
this first merge.
"""
from __future__ import annotations

import re
from pathlib import Path

BUCKETS = ("NOT_FETCHED", "READER_UNAVAILABLE", "UNLABELLED", "NO_PARSER",
           "NO_RULE", "HIT_EXACT", "HIT_FAMILY", "MISS")
HIT_BUCKETS = ("HIT_EXACT", "HIT_FAMILY")
# Buckets in which BOTH a parser and an in-family rule existed: the only
# buckets that say anything about detection quality ("scoreable").
SCOREABLE_BUCKETS = ("HIT_EXACT", "HIT_FAMILY", "MISS")

# Enterprise (and mobile) technique ids all start T1; ICS T0xxx / ATLAS AML.* are rejected.
_TECH_RE = re.compile(r"^T1\d{3}(?:\.\d{3})?$")


def normalize_technique(value) -> str | None:
    """'t1110.003 ' -> 'T1110.003'; anything that is not a well-formed
    enterprise technique id (including ``T1110.xxx`` placeholders and ICS /
    ATLAS ids) -> None. Never guesses."""
    if not isinstance(value, str):
        return None
    v = value.strip().upper()
    return v if _TECH_RE.match(v) else None


def parent(technique: str) -> str:
    """'T1110.003' -> 'T1110'; 'T1110' -> 'T1110'."""
    return technique.split(".", 1)[0]


def is_subtechnique(technique: str) -> bool:
    return "." in technique


def match_level(label: str, rule_technique: str) -> str | None:
    """'exact' | 'family' | None -- see the module docstring."""
    if not label or not rule_technique:
        return None
    if label == rule_technique:
        return "exact"
    if parent(label) != parent(rule_technique):
        return None
    if not is_subtechnique(label) or not is_subtechnique(rule_technique):
        return "family"
    return None  # two different sub-techniques of one parent: siblings


def load_rule_index(rules_dir: Path) -> dict:
    """{rule_id: {technique, tactic, framework, file}} for every rule that
    declares an enterprise-ATT&CK technique.

    A missing ``framework`` key means ``attack`` (the default
    eval/attack/coverage_layer.py applies); ``atlas`` / ``attack-ics`` rules
    and rules with no ``mitre`` block are skipped. Rules are read from
    ``rules_dir`` only -- the same directory the Detector is pointed at, so the
    NO_RULE decision and the replay can never disagree about the rule set.
    """
    import yaml  # local import: keep the pure helpers importable without PyYAML

    index: dict = {}
    for path in sorted(Path(rules_dir).glob("*.yml")):
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(raw, dict):
            continue
        mitre = raw.get("mitre")
        if not isinstance(mitre, dict):
            continue
        framework = mitre.get("framework") or "attack"
        if framework != "attack":
            continue
        tech = normalize_technique(mitre.get("technique"))
        rid = raw.get("id")
        if tech is None or not rid:
            continue
        index[str(rid)] = {"technique": tech, "tactic": mitre.get("tactic"),
                           "framework": framework, "file": path.name}
    return index


def rules_in_family(label: str, index: dict) -> dict:
    """{rule_id: level} for every indexed rule whose technique matches the
    label at 'exact' or 'family' level."""
    out = {}
    for rid, info in index.items():
        lvl = match_level(label, info["technique"])
        if lvl:
            out[rid] = lvl
    return out


def alert_level(label: str, alert: dict) -> str | None:
    """Match level of one WS-4 alert against a label, read from the alert's
    own copied ``mitre`` block. Non-ATT&CK frameworks never match."""
    mitre = alert.get("mitre")
    if not isinstance(mitre, dict):
        return None
    if (mitre.get("framework") or "attack") != "attack":
        return None
    tech = normalize_technique(mitre.get("technique"))
    return match_level(label, tech) if tech else None


def classify(*, fetched: bool, reader_ok: bool = True, label: str | None,
             parsed_records: int, family_rules: dict,
             alert_levels: list) -> str:
    """One funnel bucket for one scored unit (scenario x label).

    ``alert_levels`` is the list of match levels (``'exact'``/``'family'``) of
    the alerts that fired in this label's family; it is only consulted once a
    parser and a rule both exist. Order matters: a unit that is both NO_PARSER
    and NO_RULE is NO_PARSER (the per-technique gap list is built from the row
    fields, not from the bucket, so no coverage-gap information is lost).
    """
    if not fetched:
        return "NOT_FETCHED"
    if not reader_ok:
        return "READER_UNAVAILABLE"
    if label is None:
        return "UNLABELLED"
    if parsed_records <= 0:
        return "NO_PARSER"
    if not family_rules:
        return "NO_RULE"
    if "exact" in alert_levels:
        return "HIT_EXACT"
    if "family" in alert_levels:
        return "HIT_FAMILY"
    return "MISS"
