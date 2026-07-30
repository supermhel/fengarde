"""WS-4 scoring + funnel routing (Contract D, scoring.yaml).

score = clamp( max(severity_floor of matched rules, capped_sum of score_weights) )
Funnel decision uses the thresholds defined once in scoring.yaml.
"""
from __future__ import annotations

from pathlib import Path

import yaml


class Scorer:
    def __init__(self, scoring_yaml: Path):
        cfg = yaml.safe_load(Path(scoring_yaml).read_text(encoding="utf-8"))
        self.t = cfg["thresholds"]
        self.floor = cfg["severity_floor"]
        self.clamp_min = cfg["clamp"]["min"]
        self.clamp_max = cfg["clamp"]["max"]

    def score(self, matched_rules) -> int:
        if not matched_rules:
            return 0
        weight_sum = sum(r.score_weight for r in matched_rules)
        floor = max(self.floor.get(r.level, 0) for r in matched_rules)
        return max(self.clamp_min, min(self.clamp_max, max(weight_sum, floor)))

    def routing_score(self, matched_rules) -> int:
        """Design-B (2026-07-29 audit): like ``score()``, but a matched rule
        with ``llm_gate: false`` (``Rule.llm_gate is False``) does not
        contribute its severity floor to this value -- only to the
        analyst-facing ``score()``. ``score_weight`` still counts for every
        rule either way (an operator's weight tuning always matters); this
        only removes the floor's override for rules that opted out of it.
        Use this (never ``score()``) to decide the funnel action -- ``score()``
        is what gets stored on the alert and shown to analysts."""
        if not matched_rules:
            return 0
        weight_sum = sum(r.score_weight for r in matched_rules)
        gated_levels = [r.level for r in matched_rules if r.llm_gate]
        floor = max((self.floor.get(lvl, 0) for lvl in gated_levels), default=0)
        return max(self.clamp_min, min(self.clamp_max, max(weight_sum, floor)))

    def route(self, score: int) -> str:
        """Return funnel action: 'store' | 'classifier' | 'llm'."""
        if score >= self.t["llm_min"]:
            return "llm"
        if score >= self.t["classifier_min"]:
            return "classifier"
        return "store"
