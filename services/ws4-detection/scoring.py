"""WS-4 scoring + funnel routing (Contract D, scoring.yaml).

score = clamp( max(severity_floor of matched rules, capped_sum of score_weights) )
Funnel decision uses the thresholds defined once in scoring.yaml.

Phase 5 (2026-09-04): the `exposure` block wires ONE of its documented
factors -- `asset_criticality`, fed by `contracts/ot-points/*.yml`'s
`points[].criticality` (WP-2-E, schema-only until now: "No parser, rule, or
loader reads this block today"). `internet_exposure`/`tenant_tier` stay
unwired -- no signal exists yet to feed either (no network-topology config,
no tenant-tier config) -- flipping `enabled: true` only activates the factor
that has a real reader; the other two evaluate to their neutral default
(1.0 multiplier / 0 points) because no matching config ever sets them.
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

# R4-24 (2026-08-27): scoring.yaml's top-level `version` key is read by nothing
# -- every value in that file is consumed (thresholds/severity_floor/clamp), but
# the declared schema version was dead config. Minimal wiring: the Scorer now
# reads it at construction and warns ONCE if it is missing or not 1 (the only
# version this scorer is written against), so a future bump of that key -- the
# exact signal that this file's expectations may now be stale -- is loud rather
# than silent. Module-level set keeps it a warn-once-per-process guarantee even
# if multiple Scorer instances are built.
_SCORING_VERSION_WARNED = False


def load_ot_criticality(ot_points_dir: Path) -> dict[int, str]:
    """Phase 5 (2026-09-04): {wire_address: criticality} across every
    ``contracts/ot-points/<device-id>.yml`` device file. `README.md` and
    `writer-categories.yml` are the two non-device files in that directory
    (per README.md's own "Directory layout") -- distinguished by shape, not
    filename, so a future non-device file added there degrades safely: any
    YAML doc lacking a `points` list is silently skipped, matching this
    module's fail-open convention for optional config (same posture as
    `not_in`'s missing-allowlist handling in engine.py).

    v1 scoping: keyed by wire_address ALONE, not (device, wire_address) --
    two distinct devices sharing an address collide (last file wins, files
    read in sorted-filename order for determinism) is a known, documented
    simplification, not an oversight; the modbus_anomaly event this feeds
    (``unmapped.ot.address``) carries no device identifier the parser
    exposes today for a tighter join. A real fix needs that first.

    Never raises: a missing directory, or one containing a malformed YAML
    file, returns whatever WAS loadable rather than crashing detection --
    same "config, not inference" ship-safety this whole contract already
    committed to (ot-points/README.md's own framing).
    """
    result: dict[int, str] = {}
    if not ot_points_dir.is_dir():
        return result
    for path in sorted(ot_points_dir.glob("*.yml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001 - a broken device file must not blind the scorer
            _log.warn(f"ot-points {path.name}: failed to parse, skipping ({exc})")
            continue
        if not isinstance(doc, dict):
            continue
        points = doc.get("points")
        if not isinstance(points, list):
            continue  # not a device file (e.g. writer-categories.yml) -- silently not applicable
        for point in points:
            if not isinstance(point, dict):
                continue
            addr = point.get("wire_address")
            crit = point.get("criticality")
            if isinstance(addr, int) and not isinstance(addr, bool) and isinstance(crit, str):
                result[addr] = crit
    return result


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

    def __init__(self, scoring_yaml: Path, ot_points_dir: Path | None = None):
        cfg = yaml.safe_load(Path(scoring_yaml).read_text(encoding="utf-8"))
        self.t = cfg["thresholds"]
        self.floor = cfg["severity_floor"]
        # Phase 5 (2026-09-04): see module docstring -- only asset_criticality
        # has a real reader; internet_exposure/tenant_tier stay inert even
        # with enabled: true (no config feeds either yet).
        self._exposure = cfg.get("exposure") or {}
        self._ot_criticality = load_ot_criticality(ot_points_dir) if ot_points_dir else {}
        # Gap-hunt (2026-08-26): exact-key validation (see FLOOR_LEVELS).
        if set(self.floor) != Scorer.FLOOR_LEVELS:
            raise ValueError(
                "scoring.yaml severity_floor keys must be exactly "
                f"{sorted(Scorer.FLOOR_LEVELS)}, got {sorted(self.floor)} -- "
                "a typo'd/missing key silently floors that level to 0")
        self.clamp_min = cfg["clamp"]["min"]
        self.clamp_max = cfg["clamp"]["max"]
        # R4-24: read + validate the document `version` (see module note).
        global _SCORING_VERSION_WARNED
        if not _SCORING_VERSION_WARNED and cfg.get("version") != 1:
            _SCORING_VERSION_WARNED = True
            _log.warn(
                "scoring.yaml 'version' is missing or not 1; this scorer was "
                f"written against the version-1 layout (got {cfg.get('version')!r})")
        self.version = cfg.get("version")
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

    def _exposure_points(self, event: dict | None) -> int:
        """Phase 5 (2026-09-04): absolute point add from
        `exposure.factors.asset_criticality.tiers`, keyed by the OT point's
        `criticality` (contracts/ot-points/*.yml, looked up by the event's
        `unmapped.ot.address`). 0 when exposure is disabled, the event
        carries no OT address, the address isn't in any loaded ot-points
        file, or that criticality has no tier entry -- every one of those
        is "no signal", not an error."""
        if not self._exposure.get("enabled") or not event:
            return 0
        addr = ((event.get("unmapped") or {}).get("ot") or {}).get("address")
        if not isinstance(addr, int) or isinstance(addr, bool):
            return 0
        criticality = self._ot_criticality.get(addr)
        if criticality is None:
            return 0
        tiers = ((self._exposure.get("factors") or {}).get("asset_criticality") or {}).get("tiers") or {}
        return int(tiers.get(criticality, 0))

    def _apply_exposure(self, base_score: int, event: dict | None) -> int:
        adjusted = base_score + self._exposure_points(event)
        ceiling = (self._exposure.get("cap") or {}).get("ceiling", self.clamp_max)
        return max(self.clamp_min, min(self.clamp_max, min(ceiling, adjusted)))

    def score(self, matched_rules, event: dict | None = None) -> int:
        if not matched_rules:
            return 0
        weight_sum = sum(r.score_weight for r in matched_rules)
        floor = max(self._floor_for(r.level) for r in matched_rules)
        base = max(self.clamp_min, min(self.clamp_max, max(weight_sum, floor)))
        return self._apply_exposure(base, event)

    def routing_score(self, matched_rules, event: dict | None = None) -> int:
        """Design-B (2026-07-29 audit): like ``score()``, but a matched rule
        with ``llm_gate: false`` (``Rule.llm_gate is False``) does not
        contribute its severity floor to this value -- only to the
        analyst-facing ``score()``. ``score_weight`` still counts for every
        rule either way (an operator's weight tuning always matters); this
        only removes the floor's override for rules that opted out of it.
        Use this (never ``score()``) to decide the funnel action -- ``score()``
        is what gets stored on the alert and shown to analysts.

        Review-fix (2026-09-04): a matched rule with ``exposure_gate: false``
        (``Rule.exposure_gate is False``) excludes exposure's point-add from
        THIS value only -- ``score()`` still applies it in full, so the
        alert's analyst-facing severity honestly reflects a high/critical
        asset. Without this, exposure could silently push a rule that was
        deliberately scored low to stay out of the classifier/LLM funnel
        (e.g. a ticketed/authorized OT write) back over ``classifier_min``
        purely because the asset it hit happens to be exposure-tiered --
        defeating that rule's whole reason for existing.

        Review-fix (2026-09-04, round 2): exposure is a single event-level
        signal, not a per-rule one, so it can't be split across a mixed
        matched_rules list the way llm_gate's per-rule floor exclusion can.
        Two matched rules CAN legitimately co-fire on one event (several
        shipped rules share class_uid 4001 with the ticketed OT-write rule
        -- a burst of OT traffic can trip a stateful rule on the SAME event
        a ticketed write also matches), so "any rule opts out -> skip
        exposure for the WHOLE alert" silently defeated exposure for an
        unrelated, ungated rule too. Fixed by computing routing_score as
        the MAX of two clamped values: `base` (every matched rule, weight +
        gated floor, NO exposure -- the alert's guaranteed floor,
        independent of exposure_gate) and exposure applied to a SECOND
        base computed from ONLY the exposure-eligible rules (their own
        weight_sum/floor, exposure_gate'd rules excluded entirely from
        this second computation). A gated rule can never gain from
        exposure (covered by the first term), and an ungated rule can
        never LOSE its exposure eligibility just because an unrelated
        gated rule happened to co-fire (covered by the second term) --
        collapses to the exact same two fast paths as before when the
        matched set is uniformly gated or uniformly ungated."""
        if not matched_rules:
            return 0
        weight_sum = sum(r.score_weight for r in matched_rules)
        gated_levels = [r.level for r in matched_rules if r.llm_gate]
        floor = max((self._floor_for(lvl) for lvl in gated_levels), default=0)
        base = max(self.clamp_min, min(self.clamp_max, max(weight_sum, floor)))

        exposure_eligible = [r for r in matched_rules if r.exposure_gate]
        if len(exposure_eligible) == len(matched_rules):
            return self._apply_exposure(base, event)  # uniformly ungated
        if not exposure_eligible:
            return base  # uniformly gated

        weight_sum_elig = sum(r.score_weight for r in exposure_eligible)
        gated_levels_elig = [r.level for r in exposure_eligible if r.llm_gate]
        floor_elig = max((self._floor_for(lvl) for lvl in gated_levels_elig), default=0)
        base_elig = max(self.clamp_min, min(self.clamp_max, max(weight_sum_elig, floor_elig)))
        return max(base, self._apply_exposure(base_elig, event))

    def route(self, score: int) -> str:
        """Return funnel action: 'store' | 'classifier' | 'llm'."""
        if score >= self.t["llm_min"]:
            return "llm"
        if score >= self.t["classifier_min"]:
            return "classifier"
        return "store"
