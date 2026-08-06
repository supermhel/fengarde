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
        # FIX 22 (2026-08-06): in-memory dedup of LLM/classifier-funnel enqueues
        # per alert key. A hot stateful rule fires repeatedly within its window
        # bucket with the SAME alert_key; without dedup every fire re-queues WS-5
        # triage for the same incident. Bounded: ~1000 entries, pruned on growth.
        self._recent_llm_enqueues: dict[str, float] = {}  # alert_key -> enqueue ts
        self._llm_cooldown_s = 300  # 5 minutes
        self._llm_cache_budget = 1000

    def should_enqueue_llm(self, alert_key: str, now: float | None = None) -> bool:
        """FIX 22: True if an ``ai.requests`` enqueue for ``alert_key`` should
        proceed -- i.e. it was NOT enqueued within the cooldown window. Records
        the enqueue timestamp on a fresh/expired key (the dedup is internal and
        caller-transparent). Prunes the in-memory table when it exceeds the
        budget, dropping entries older than two cooldowns.
        """
        import time as _time
        now = _time.time() if now is None else now
        last = self._recent_llm_enqueues.get(alert_key, 0.0)
        if now - last < self._llm_cooldown_s:
            return False
        self._recent_llm_enqueues[alert_key] = now
        if len(self._recent_llm_enqueues) > self._llm_cache_budget:
            cutoff = now - self._llm_cooldown_s * 2
            self._recent_llm_enqueues = {
                k: v for k, v in self._recent_llm_enqueues.items() if v > cutoff}
        return True

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
