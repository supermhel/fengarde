"""known_gaps -- gaps DECLARED IN EACH STORYLINE'S OWN ORACLE (owner decision 2026-11-20).

WHY
    Until 2026-11-20 every known, dated disagreement between a twin oracle and the system lived in
    name-keyed tables shared by all storylines (``oracle_consistency._ACCEPTED`` /
    ``_GAP_TECHNIQUE_WAIVED`` / ``_TRIANGULATION_WAIVED``, ``oracle_derive._WAIVED`` / ``_F2_CAP``,
    ``oracle_mutate._EQUIVALENT``). A new storyline therefore needed edits in all of them. The gaps
    now sit in the ``known_gaps:`` block of the oracle yaml of the storyline they belong to, and the
    guards read them from there; there is one code path and no per-storyline table.

THE BLOCK (a top-level list in ``eval/twin/oracle*.yaml``; absent == no known gaps)::

    known_gaps:
      - kind: order_blind_join          # a forbidden pair the WS-8 graph joins only via shared entities
        from: dns_exfil
        to: initial_access
        since: "2026-10-02"
        reason: "why it is accepted and what closing it would move"

    kind                    identity fields                      guard that reads it
    ----------------------  -----------------------------------  ---------------------------------
    order_blind_join        from, to                             oracle_consistency (forbidden pair)
    accepted_disagreement   finding, step, rule_id                oracle_consistency (any other finding)
                            (finding: stale_gap | decorative | unexpected | forbidden_rule | unknown_rule)
    gap_technique_waiver    step                                 oracle_consistency (gap w/o technique)
    triangulation_difference step, rule_id                       oracle_consistency --triangulate
    derive_waiver           finding (F1..F14), step, item        oracle_derive
    f2_cap                  max (int >= 1)                       oracle_derive (undecidable rules)
    mutant_survivor         operator, outcome, max (int >= 1)    oracle_mutate (class cap of survivors)

    Every entry also carries ``since`` (ISO date) and ``reason`` (non-empty prose). Unknown kinds,
    unknown or missing fields, a malformed date and duplicate declarations raise ``KnownGapsError``
    at load time: a malformed block is a red guard, never a silently ignored one.

FAILURE MODES (each guard enforces all three, from both sides)
    (a) UNDECLARED   an observed disagreement with no declaration fails (it is a NEW drift).
    (b) WRONG KIND   a declaration whose kind does not match what is observed fails: an
                     ``order_blind_join`` whose pair is not joined purely through entity edges, a
                     declaration whose (step, item) is observed under a DIFFERENT finding kind.
                     The declaration is reported stale with ``why: kind_mismatch`` and the observed
                     finding stays undeclared, so both halves go red.
    (c) STALE        a declaration that no longer reproduces fails. This is the ratchet toward the
                     goal: when ADR-011/012 make the graph separate a forbidden pair, the guard says
                     "delete the declaration", and the declaration is deleted.

NOT ORACLE SEMANTICS
    ``known_gaps`` describes the oracle's relationship with the system; it is not something any
    grader scores against. ``NON_SEMANTIC_KEYS`` lists the keys the mutation lane's inert-key probe
    skips, so adding or editing declarations is not an oracle semantic change (``oracle_provenance``
    pins rule text, not this block, and is untouched). ``eval/twin/baseline.json`` is never touched.

STDLIB + PyYAML (already a dependency of the neighbours).
"""
from __future__ import annotations

import datetime as _dt
import re

NON_SEMANTIC_KEYS = ("known_gaps",)

ACCEPTED_FINDING_KINDS = ("stale_gap", "decorative", "unexpected", "forbidden_rule", "unknown_rule")
MUTANT_OUTCOMES = ("SURVIVED", "IMPROVED", "CRASH", "IDENTITY_CHANGED")

# kind -> (identity fields, extra required fields); ``since`` and ``reason`` are always required.
KINDS: dict = {
    "order_blind_join": (("from", "to"), ()),
    "accepted_disagreement": (("finding", "step", "rule_id"), ()),
    "gap_technique_waiver": (("step",), ()),
    "triangulation_difference": (("step", "rule_id"), ()),
    "derive_waiver": (("finding", "step", "item"), ()),
    "f2_cap": ((), ("max",)),
    "mutant_survivor": (("operator", "outcome"), ("max",)),
}
_COMMON = ("kind", "since", "reason")
_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class KnownGapsError(ValueError):
    """A malformed ``known_gaps`` block. Raised at load time so a bad declaration fails every guard."""


def strip(oracle: dict) -> dict:
    """The oracle without its non-semantic declaration blocks (what the mutation probe perturbs)."""
    return {k: v for k, v in oracle.items() if k not in NON_SEMANTIC_KEYS}


def _since(v, where: str) -> str:
    if isinstance(v, (_dt.date, _dt.datetime)):
        v = v.isoformat()[:10]
    if not isinstance(v, str) or not _ISO.match(v):
        raise KnownGapsError(f"{where}: since must be an ISO date YYYY-MM-DD, got {v!r}")
    try:
        _dt.date.fromisoformat(v)
    except ValueError as exc:
        raise KnownGapsError(f"{where}: since {v!r} is not a real date") from exc
    return v


def load(oracle: dict | None, scenario: str = "?") -> list:
    """Validated, normalised declarations of one oracle (``since`` as ``YYYY-MM-DD`` text, plus a
    ``dated_reason`` = ``"<since> <reason>"``, the shape the legacy waiver tables used)."""
    raw = (oracle or {}).get("known_gaps")
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise KnownGapsError(f"{scenario}: known_gaps must be a list of declarations")
    out, seen = [], set()
    for i, ent in enumerate(raw):
        where = f"{scenario}: known_gaps[{i}]"
        if not isinstance(ent, dict):
            raise KnownGapsError(f"{where}: each declaration must be a mapping")
        kind = ent.get("kind")
        if kind not in KINDS:
            raise KnownGapsError(f"{where}: unknown kind {kind!r} (valid: {sorted(KINDS)})")
        ident, extra = KINDS[kind]
        allowed = set(_COMMON) | set(ident) | set(extra)
        missing = sorted(allowed - set(ent))
        unknown = sorted(set(ent) - allowed)
        if missing:
            raise KnownGapsError(f"{where} ({kind}): missing field(s) {missing}")
        if unknown:
            raise KnownGapsError(f"{where} ({kind}): unknown field(s) {unknown}")
        for f in ident:
            if not isinstance(ent[f], str) or not ent[f].strip():
                raise KnownGapsError(f"{where} ({kind}): {f} must be a non-empty string")
        for f in extra:
            if not isinstance(ent[f], int) or isinstance(ent[f], bool) or ent[f] < 1:
                raise KnownGapsError(f"{where} ({kind}): {f} must be an int >= 1")
        if not isinstance(ent["reason"], str) or len(ent["reason"].strip()) < 12:
            raise KnownGapsError(f"{where} ({kind}): reason must be real prose (>= 12 characters)")
        if kind == "accepted_disagreement" and ent["finding"] not in ACCEPTED_FINDING_KINDS:
            raise KnownGapsError(f"{where}: finding must be one of {ACCEPTED_FINDING_KINDS} "
                                 "(a forbidden pair is an order_blind_join, a missing technique a "
                                 "gap_technique_waiver)")
        if kind == "mutant_survivor" and ent["outcome"] not in MUTANT_OUTCOMES:
            raise KnownGapsError(f"{where}: outcome must be one of {MUTANT_OUTCOMES}")
        norm = dict(ent)
        norm["since"] = _since(ent["since"], where)
        norm["dated_reason"] = f"{norm['since']} {ent['reason']}"
        ident_key = (kind,) + tuple(ent[f] for f in ident)
        if ident_key in seen:
            raise KnownGapsError(f"{where}: duplicate declaration {ident_key}")
        seen.add(ident_key)
        out.append(norm)
    return out


def of_kind(gaps: list, *kinds: str) -> list:
    return [g for g in gaps if g["kind"] in kinds]


# ---------------------------------------------------------------------------
# views in the exact shape the legacy tables had (so the guard logic is unchanged)
# ---------------------------------------------------------------------------
def accepted_map(gaps: list, scenario: str) -> dict:
    """``{(scenario, finding_kind, a, b): {"reason", "kind"}}`` -- the old ``_ACCEPTED`` shape."""
    out = {}
    for g in of_kind(gaps, "order_blind_join"):
        out[(scenario, "forbidden", g["from"], g["to"])] = {"reason": g["dated_reason"], "kind": g["kind"]}
    for g in of_kind(gaps, "accepted_disagreement"):
        out[(scenario, g["finding"], g["step"], g["rule_id"])] = {"reason": g["dated_reason"], "kind": g["kind"]}
    return out


def gap_technique_map(gaps: list, scenario: str) -> dict:
    """``{(scenario, step): dated reason}`` -- the old ``_GAP_TECHNIQUE_WAIVED`` shape."""
    return {(scenario, g["step"]): g["dated_reason"] for g in of_kind(gaps, "gap_technique_waiver")}


def triangulation_map(gaps: list, scenario: str) -> dict:
    """``{(scenario, step, rule_id): dated reason}`` -- the old ``_TRIANGULATION_WAIVED`` shape."""
    return {(scenario, g["step"], g["rule_id"]): g["dated_reason"] for g in of_kind(gaps, "triangulation_difference")}


def derive_map(gaps: list, scenario: str) -> dict:
    """``{(scenario, finding, step, item): dated reason}`` -- the old ``oracle_derive._WAIVED`` shape."""
    return {(scenario, g["finding"], g["step"], g["item"]): g["dated_reason"] for g in of_kind(gaps, "derive_waiver")}


def f2_caps(gaps: list, scenario: str) -> dict:
    """``{scenario: cap}`` -- the old ``_F2_CAP`` shape (empty when the oracle declares none)."""
    return {scenario: g["max"] for g in of_kind(gaps, "f2_cap")}


def mutant_map(gaps: list, scenario: str) -> dict:
    """``{(scenario, operator, outcome): {"max", "reason"}}`` -- the old ``_EQUIVALENT`` shape."""
    return {(scenario, g["operator"], g["outcome"]): {"max": g["max"], "reason": g["dated_reason"]}
            for g in of_kind(gaps, "mutant_survivor")}
