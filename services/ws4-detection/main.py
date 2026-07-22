"""WS-4 Detection entrypoint.

Consume normalized.events -> evaluate Sigma rules -> compute score (Contract D) ->
set siem.score -> produce scored.events. On any rule match, emit an alert; when the
score crosses either funnel threshold (contracts/scoring.yaml), enqueue to
ai.requests -- tier="llm" at >=llm_min (full LLM triage), tier="classifier" at
>=classifier_min (WS-5's cheap layer-2 classifier only, no LLM call). Scores
below classifier_min are indexed only (P1-2, 2026-07-21 audit: this second
tier used to route nowhere -- scoring.yaml/sigma-convention.md promised it,
detector.process() computed the "classifier" action correctly via
Scorer.route(), but this file only ever checked action=="llm").
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
ROOT = SERVICES.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))

from shared.bus import Bus  # noqa: E402
from engine import load_rules  # noqa: E402
from scoring import Scorer  # noqa: E402
from tenants import tenant_of, load_disabled_rules  # noqa: E402
from plugins import discover_rule_pack_dirs  # noqa: E402

# contracts/ lives at repo/contracts (host) or /app/contracts (container). HERE.parent
# is repo/services (host) or /app (container), so search both it and its parent.
def _contracts_dir() -> Path:
    for base in (SERVICES, ROOT):
        if (base / "contracts" / "scoring.yaml").exists():
            return base / "contracts"
    return ROOT / "contracts"

_CONTRACTS = _contracts_dir()
RULES_DIR = _CONTRACTS / "rules"
SCORING_YAML = _CONTRACTS / "scoring.yaml"
TENANTS_DIR = _CONTRACTS / "tenants"
ALLOWLISTS_DIR = _CONTRACTS / "allowlists"


class Detector:
    def __init__(self, tenants_dir: Path = TENANTS_DIR,
                 plugin_rule_dirs: list[Path] | None = None):
        """``plugin_rule_dirs``: directories of extra rule YAML to merge in,
        same shape as ``contracts/rules/*.yml``. Defaults to whatever
        ``plugins.discover_rule_pack_dirs()`` finds installed via the
        ``fengarde.rule_packs`` entry-point group (M4.5, empty in this repo
        by default -- pass ``[]`` explicitly to skip discovery, e.g. in a
        test that wants a deterministic rule set regardless of what's
        installed in the environment)."""
        self._plugin_rule_dirs = (
            [d for _name, d in discover_rule_pack_dirs()]
            if plugin_rule_dirs is None else plugin_rule_dirs)
        self.scorer = Scorer(SCORING_YAML)
        self.tenants_dir = tenants_dir
        self._window_counter = None  # set by main() when BUS_BACKEND=redis
        self.rules, self._by_class_uid = self._load()

    def _load(self):
        """Load base + plugin rules and bucket them by class_uid. Raises on
        any parse/validation error -- callers decide what to do with a
        failed load (__init__ lets it propagate; reload() catches it)."""
        rules = load_rules(RULES_DIR, ALLOWLISTS_DIR)
        # A plugin rule whose id collides with an already-loaded one (built-
        # in or an earlier plugin) is skipped -- whichever loaded first
        # wins, so a plugin extends detection but can never silently
        # replace an existing rule's condition.
        seen_ids = {r.id for r in rules}
        for plugin_dir in self._plugin_rule_dirs:
            for rule in load_rules(plugin_dir, ALLOWLISTS_DIR):
                if rule.id in seen_ids:
                    continue
                rules.append(rule)
                seen_ids.add(rule.id)
        if self._window_counter is not None:
            for r in rules:
                if r.stateful:
                    r.set_counter(self._window_counter)
        # B1: index rules by their (equality) class_uid selection so process()
        # only evaluates the subset of rules that could possibly match a given
        # event's class_uid, instead of every rule for every event. Rules with
        # no class_uid equality selection go in the catch-all bucket (key None)
        # and are still evaluated against every event -- conservative/safe.
        by_class_uid: dict = {None: []}
        for r in rules:
            by_class_uid.setdefault(r.class_uid, []).append(r)
        return rules, by_class_uid

    def reload(self) -> bool:
        """Re-read RULES_DIR/plugin packs from disk and atomically swap in
        the new rule set. Returns True on a successful swap, False if the
        new set failed to parse/validate -- in which case the PREVIOUS rule
        set stays live (fail-closed: a bad edit on disk must not take
        detection down) and the failure is logged loudly, not swallowed.

        Window-state semantics: sliding-window counters are keyed by rule
        id (services/ws4-detection/window.py), not by object identity, so
        an unchanged rule keeps its in-flight window across a reload; an
        edited rule's new threshold/window_seconds applies to whatever is
        already sitting in its window; a removed rule's key simply stops
        being read (it ages out via the counter's own sweep/EXPIRE) --
        there is no explicit eviction needed.
        """
        try:
            new_rules, new_by_class_uid = self._load()
        except Exception as exc:
            from shared.log import get_logger
            get_logger("ws4-detection").warn(
                "rule reload failed, keeping previous rule set", error=repr(exc))
            return False
        self.rules = new_rules
        self._by_class_uid = new_by_class_uid
        return True

    def process(self, event: dict):
        """Return (scored_event, matched_rules, action)."""
        class_uid = event.get("class_uid")
        candidates = self._by_class_uid.get(class_uid, []) + self._by_class_uid[None]
        # M4 multi-tenancy: a tenant's config can disable specific global
        # rules for their own events (contracts/tenants/<tenant_id>.yml).
        # Missing config/entry -> nothing disabled (fail open to detection,
        # same convention as engine.py's allowlist loading).
        tenant = tenant_of(event)
        disabled = load_disabled_rules(self.tenants_dir, tenant)
        if disabled:
            candidates = [r for r in candidates if r.id not in disabled]
        matched = [r for r in candidates if r.evaluate(event)]
        score = self.scorer.score(matched)
        event.setdefault("siem", {})["score"] = score
        action = self.scorer.route(score)
        return event, matched, action


def rules_max_mtime(rules_dir: Path = RULES_DIR, allowlists_dir: Path = ALLOWLISTS_DIR) -> float:
    """Max mtime across every rule/allowlist YAML, 0.0 if neither dir exists.
    Used by the B4 hot-reload poll to detect "something on disk changed"
    without re-parsing on every tick."""
    latest = 0.0
    for d in (rules_dir, allowlists_dir):
        if not d.is_dir():
            continue
        for f in d.glob("*.yml"):
            try:
                latest = max(latest, f.stat().st_mtime)
            except OSError:
                pass
    return latest


def start_rule_reload_watcher(detector: "Detector", shutdown, interval_s: float,
                              rules_dir: Path = RULES_DIR, allowlists_dir: Path = ALLOWLISTS_DIR):
    """B4: opt-in mtime-poll hot-reload. Returns None (no thread) when
    ``interval_s <= 0`` -- the default, byte-for-byte the pre-B4 behavior.
    Otherwise starts a daemon thread that calls ``detector.reload()`` at
    most once per ``interval_s`` seconds, only when the rules/allowlists
    directories' max mtime has actually changed since the last check."""
    if interval_s <= 0:
        return None
    import threading
    from shared.log import get_logger
    log = get_logger("ws4-detection")

    def _loop():
        last_mtime = rules_max_mtime(rules_dir, allowlists_dir)
        while not shutdown.wait(interval_s):
            mtime = rules_max_mtime(rules_dir, allowlists_dir)
            if mtime == last_mtime:
                continue
            last_mtime = mtime
            if detector.reload():
                log.info("rules hot-reloaded", rule_count=len(detector.rules))
            # on failure, reload() already logged a warn and kept the old set

    t = threading.Thread(target=_loop, name="rule-reload-watcher", daemon=True)
    t.start()
    return t


def make_alert(event, rule, score):
    return {
        # T7: deterministic id so redelivery yields the SAME alert (idempotent),
        # not a fresh uuid that the indexer would store as a duplicate.
        "alert_id": rule.alert_key(event),
        "time": event.get("time"),
        "rule_id": rule.id,
        "rule_title": rule.title,
        "level": rule.level,
        "score": score,
        "sector": event.get("siem", {}).get("sector"),
        # C3: passthrough of the rule's own optional mitre block (see
        # tools/validate_rules.py's shape check), so the coverage heatmap
        # can be driven off real alerts, not just the static rules list.
        "mitre": rule.raw.get("mitre"),
        # M4 multi-tenancy: carries the triggering event's envelope-v1 tenant
        # onto the alert so WS-3's router can index it into a tenant-scoped
        # alerts-{tenant}-{date} index (router.py). Absent tenant -> "default",
        # matching every pre-M4 event/alert (see services/shared/envelope.py).
        "tenant_id": event.get("siem", {}).get("tenant"),
        "src_endpoint": event.get("src_endpoint", {}),
        "actor": event.get("actor", {}),
        "event_ids": [event.get("siem", {}).get("ingest_id")],
    }


def detect_one(bus, detector: "Detector", event: dict) -> None:
    """Process a single normalized event and emit its derived records.

    Pulled out of run() so the same logic backs both the batch run() loop (tests)
    and the shared-runner handler (daemon). Raises on any failure so the runner
    leaves the message unacked for redelivery.
    """
    event, matched, action = detector.process(event)
    key = (event.get("src_endpoint") or {}).get("ip", "0.0.0.0")
    bus.produce("scored.events", key=key, payload=event)
    for rule in matched:
        alert = make_alert(event, rule, event["siem"]["score"])
        bus.produce("alerts", key=alert["alert_id"], payload=alert)
    # P1-2 (2026-07-21 audit): scoring.yaml/sigma-convention.md promise a
    # 20-59 "light classifier" band, but only action=="llm" (>=60) ever
    # reached ai.requests -- the band was dead, scores 20-59 got indexed and
    # never classified. `tier` tells WS-5 which layer to run: "llm" pays for
    # a real model call; "classifier" runs only the cheap deterministic/ML
    # classifier (classifier.py) -- never the LLM, or the whole point of a
    # separate cheap tier is defeated.
    if action in ("llm", "classifier"):
        bus.produce("ai.requests", key=event["siem"].get("ingest_id", key),
                    payload={"event_id": event["siem"].get("ingest_id"),
                             "event": event, "tier": action,
                             "reason": [r.title for r in matched]})


def run(bus, detector: "Detector") -> dict:
    stats = {"scored": 0, "alerts": 0, "ai_enqueued": 0, "classifier_enqueued": 0}
    for msg in bus.consume("normalized.events", group="cg-detect"):
        event, matched, action = detector.process(msg.payload)
        key = (event.get("src_endpoint") or {}).get("ip", "0.0.0.0")
        bus.produce("scored.events", key=key, payload=event)
        stats["scored"] += 1
        for rule in matched:
            alert = make_alert(event, rule, event["siem"]["score"])
            bus.produce("alerts", key=alert["alert_id"], payload=alert)
            stats["alerts"] += 1
        if action in ("llm", "classifier"):  # P1-2: see detect_one()'s comment
            bus.produce("ai.requests", key=event["siem"].get("ingest_id", key),
                        payload={"event_id": event["siem"].get("ingest_id"),
                                 "event": event, "tier": action,
                                 "reason": [r.title for r in matched]})
            stats["ai_enqueued"] += 1
            if action == "classifier":
                stats["classifier_enqueued"] += 1
    return stats


def main():
    import threading  # noqa: E402
    from shared.runner import serve, start_depth_watchdog  # noqa: E402  (lazy: keeps run() import-light)
    from shared.log import get_logger  # noqa: E402

    detector = Detector()

    # T6: on Redis, give stateful rules a GLOBAL window counter so the threshold
    # count is correct across multiple WS-4 replicas. A per-process deque would
    # split the count and the brute-force alert would never fire under scaling.
    # Stashed on the detector (not just applied once) so a later reload() also
    # rewires newly-loaded rule objects onto the same counter.
    if os.getenv("BUS_BACKEND", "memory").lower() == "redis":
        try:
            import redis  # type: ignore
            from window import RedisWindowCounter  # noqa: E402
            client = redis.Redis.from_url(
                os.getenv("REDIS_URL", "redis://localhost:6379/0"),
                decode_responses=True)
            counter = RedisWindowCounter(client)
            detector._window_counter = counter
            for r in detector.rules:
                if r.stateful:
                    r.set_counter(counter)
        except Exception:  # redis missing/unreachable -> per-replica deque fallback
            pass

    # P1-3 (2026-07-21 audit): ONE Bus() per worker, not one per event. Safe
    # because runner.py's _topic_worker owns exactly one topic (WS-4 consumes
    # only normalized.events) per thread and calls this handler serially on
    # that single thread -- no cross-thread sharing to guard against.
    # Constructing Bus() per event on the redis backend meant a fresh
    # redis-py client (fresh TCP connect) per event.
    handler_bus = Bus()

    def handler(payload: dict) -> None:
        detect_one(handler_bus, detector, payload)

    # P2.4: watch WS-4's own output topics for backpressure buildup (signal-only;
    # see start_depth_watchdog's docstring for why internal topics aren't trimmed).
    log = get_logger("ws4-detection")
    shutdown = threading.Event()
    warn_at = int(os.getenv("DETECTION_OUTPUT_DEPTH_WARN", "100000"))
    watchdog = start_depth_watchdog(Bus(), log, shutdown,
                                    ["scored.events", "ai.requests"], warn_at=warn_at)
    # B4: opt-in rule hot-reload, off by default (RULES_RELOAD_INTERVAL_S=0) --
    # matches the pre-existing load-once-at-startup behavior byte-for-byte.
    reload_interval = float(os.getenv("RULES_RELOAD_INTERVAL_S", "0"))
    reload_thread = start_rule_reload_watcher(detector, shutdown, reload_interval)
    try:
        serve({"normalized.events": ("cg-detect", handler)},
              health_port=int(os.getenv("PORT", "8004")),
              service_name="ws4-detection", shutdown=shutdown)
    finally:
        if watchdog is not None:
            watchdog.join(timeout=5)
        if reload_thread is not None:
            reload_thread.join(timeout=5)


if __name__ == "__main__":
    main()
