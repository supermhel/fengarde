"""WS-4 scoring + funnel routing (Contract D, scoring.yaml).

score = clamp( max(severity_floor of matched rules, capped_sum of score_weights) )
Funnel decision uses the thresholds defined once in scoring.yaml.
"""
from __future__ import annotations

from pathlib import Path

import yaml

try:  # logging is best-effort; tests import this module standalone
    from shared.log import get_logger
    _log = get_logger("ws4-detection")
except Exception:  # pragma: no cover - fallback when shared not importable
    class _NullLog:
        def info(self, *a, **k):
            pass

        warn = error = info
    _log = _NullLog()


class Scorer:
    # Gap-hunt (2026-08-26): severity_floor's keys must EXACTLY match the set
    # of scoring levels this pipeline defines. A missing/typo'd key (e.g.
    # `info:` instead of `informational:`) used to silently floor such a rule
    # to 0 -- turning a critical rule's guaranteed 80 into whatever its
    # score_weight sums to (and dropping it out of the LLM tier) -- with CI
    # green, because no code ever checked the dict's keys. Constructing a
    # Scorer from a scoring.yaml whose severity_floor has any unexpected key
    # (or is missing any of these) now raises, so the mistake is loud at
    # boot/CI time instead of silent.
    FLOOR_LEVELS = frozenset({"informational", "low", "medium", "high", "critical"})

    def __init__(self, scoring_yaml: Path):
        cfg = yaml.safe_load(Path(scoring_yaml).read_text(encoding="utf-8"))
        self.t = cfg["thresholds"]
        self.floor = cfg["severity_floor"]
        # Gap-hunt (2026-08-26): exact-key validation (see FLOOR_LEVELS).
        if set(self.floor) != Scorer.FLOOR_LEVELS:
            raise ValueError(
                "scoring.yaml severity_floor keys must be exactly "
                f"{sorted(Scorer.FLOOR_LEVELS)}, got {sorted(self.floor)} -- "
                "a typo'd/missing key silently floors that level to 0")
        self.clamp_min = cfg["clamp"]["min"]
        self.clamp_max = cfg["clamp"]["max"]
        # FIX 22 (2026-08-06): in-memory dedup of LLM/classifier-funnel enqueues
        # per alert key. A hot stateful rule fires repeatedly within its window
        # bucket with the SAME alert_key; without dedup every fire re-queues WS-5
        # triage for the same incident. Bounded: hard-capped at ~1000 entries;
        # the oldest entries are evicted when the cap is hit (see
        # record_enqueue) -- gap-hunt (2026-08-26) found the old age-only prune
        # left the table unbounded when every entry was fresh.
        self._recent_llm_enqueues: dict[str, float] = {}  # alert_key -> enqueue ts
        self._llm_cooldown_s = 300  # 5 minutes
        self._llm_cache_budget = 1000
        # Gap-hunt (2026-08-26): a rule level with no severity_floor entry used
        # to floor silently to 0 forever. Warn ONCE per unknown level at score
        # time, then keep the (fail-safe) 0 floor.
        self._unknown_levels_warned: set[str] = set()

    def is_llm_funnel_fresh(self, alert_key: str, now: float | None = None) -> bool:
        """FIX 22: pure CHECK (no mutation) -- True if an ``ai.requests``
        enqueue for ``alert_key`` should proceed, i.e. it was NOT enqueued
        within the cooldown window.

        Gap-hunt (2026-08-26): this must NOT record anything. The old
        record-during-check shape committed the cooldown BEFORE
        bus.produce() ran, so a produce failure left the cooldown burned:
        the message would be redelivered but the funnel gate would skip the
        re-enqueue forever (silently -- no exception, no metric). Callers
        check with this, then produce, then commit with ``record_enqueue``.
        """
        import time as _time
        now = _time.time() if now is None else now
        last = self._recent_llm_enqueues.get(alert_key, 0.0)
        return now - last >= self._llm_cooldown_s

    def record_enqueue(self, alert_key: str, now: float | None = None) -> None:
        """FIX 22: commit that ``alert_key`` was enqueued to ``ai.requests`` at
        ``now``. Call ONLY after ``bus.produce`` returned successfully -- the
        cooldown must never be burned by a produce that failed (see
        is_llm_funnel_fresh). Bounded: drops entries older than two cooldowns,
        then hard-caps the table at ``_llm_cache_budget`` by evicting the
        OLDEST entries regardless of age.
        """
        import time as _time
        now = _time.time() if now is None else now
        self._recent_llm_enqueues[alert_key] = now
        if len(self._recent_llm_enqueues) > self._llm_cache_budget:
            cutoff = now - self._llm_cooldown_s * 2
            self._recent_llm_enqueues = {
                k: v for k, v in self._recent_llm_enqueues.items() if v > cutoff}
        # Hard cap: the age prune above cannot shrink a table whose entries are
        # ALL fresh (a flood of distinct alert keys within two cooldowns), so
        # evict the oldest insertion-order entries until back under budget.
        while len(self._recent_llm_enqueues) > self._llm_cache_budget:
            self._recent_llm_enqueues.pop(next(iter(self._recent_llm_enqueues)))

    def should_enqueue_llm(self, alert_key: str, now: float | None = None) -> bool:
        """[compat] Record-on-fresh gating kept for the FIX 22 unit tests:
        True when ``alert_key`` is not in cooldown, and records the enqueue
        timestamp. The DETECTOR must not use this for its gate -- it records
        before the caller's produce (the cooldown-before-produce bug, see
        is_llm_funnel_fresh). Use is_llm_funnel_fresh + record_enqueue there.
        """
        if not self.is_llm_funnel_fresh(alert_key, now):
            return False
        self.record_enqueue(alert_key, now)
        return True

    def _floor_for(self, level: str) -> int:
        """Severity floor for a rule level; 0 for an unknown level, with a
        one-time warning per level (gap-hunt 2026-08-26: an unlisted level
        used to floor silently to 0 forever)."""
        val = self.floor.get(level, 0)
        if level in self.floor:
            return val
        if level not in self._unknown_levels_warned:
            self._unknown_levels_warned.add(level)
            _log.warn(
                "rule level has no severity_floor entry; flooring to 0 "
                "(scoring.yaml keys must be one of "
                f"{sorted(Scorer.FLOOR_LEVELS)})", level=level)
        return 0

    def score(self, matched_rules) -> int:
        if not matched_rules:
            return 0
        weight_sum = sum(r.score_weight for r in matched_rules)
        floor = max(self._floor_for(r.level) for r in matched_rules)
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
        floor = max((self._floor_for(lvl) for lvl in gated_levels), default=0)
        return max(self.clamp_min, min(self.clamp_max, max(weight_sum, floor)))

    def route(self, score: int) -> str:
        """Return funnel action: 'store' | 'classifier' | 'llm'."""
        if score >= self.t["llm_min"]:
            return "llm"
        if score >= self.t["classifier_min"]:
            return "classifier"
        return "store"
