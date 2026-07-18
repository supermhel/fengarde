"""WS-4 Detection entrypoint.

Consume normalized.events -> evaluate Sigma rules -> compute score (Contract D) ->
set siem.score -> produce scored.events. On any rule match, emit an alert; when the
score crosses the LLM threshold, enqueue to ai.requests (the buffered AI funnel).
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
        self.rules = load_rules(RULES_DIR, ALLOWLISTS_DIR)
        # A plugin rule whose id collides with an already-loaded one (built-
        # in or an earlier plugin) is skipped -- whichever loaded first
        # wins, so a plugin extends detection but can never silently
        # replace an existing rule's condition.
        if plugin_rule_dirs is None:
            plugin_rule_dirs = [d for _name, d in discover_rule_pack_dirs()]
        seen_ids = {r.id for r in self.rules}
        for plugin_dir in plugin_rule_dirs:
            for rule in load_rules(plugin_dir, ALLOWLISTS_DIR):
                if rule.id in seen_ids:
                    continue
                self.rules.append(rule)
                seen_ids.add(rule.id)
        self.scorer = Scorer(SCORING_YAML)
        self.tenants_dir = tenants_dir
        # B1: index rules by their (equality) class_uid selection so process()
        # only evaluates the subset of rules that could possibly match a given
        # event's class_uid, instead of every rule for every event. Rules with
        # no class_uid equality selection go in the catch-all bucket (key None)
        # and are still evaluated against every event -- conservative/safe.
        self._by_class_uid: dict = {None: []}
        for r in self.rules:
            self._by_class_uid.setdefault(r.class_uid, []).append(r)

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
    if action == "llm":
        bus.produce("ai.requests", key=event["siem"].get("ingest_id", key),
                    payload={"event_id": event["siem"].get("ingest_id"),
                             "event": event,
                             "reason": [r.title for r in matched]})


def run(bus, detector: "Detector") -> dict:
    stats = {"scored": 0, "alerts": 0, "ai_enqueued": 0}
    for msg in bus.consume("normalized.events", group="cg-detect"):
        event, matched, action = detector.process(msg.payload)
        key = (event.get("src_endpoint") or {}).get("ip", "0.0.0.0")
        bus.produce("scored.events", key=key, payload=event)
        stats["scored"] += 1
        for rule in matched:
            alert = make_alert(event, rule, event["siem"]["score"])
            bus.produce("alerts", key=alert["alert_id"], payload=alert)
            stats["alerts"] += 1
        if action == "llm":
            bus.produce("ai.requests", key=event["siem"].get("ingest_id", key),
                        payload={"event_id": event["siem"].get("ingest_id"),
                                 "event": event,
                                 "reason": [r.title for r in matched]})
            stats["ai_enqueued"] += 1
    return stats


def main():
    import threading  # noqa: E402
    from shared.runner import serve, start_depth_watchdog  # noqa: E402  (lazy: keeps run() import-light)
    from shared.log import get_logger  # noqa: E402

    detector = Detector()

    # T6: on Redis, give stateful rules a GLOBAL window counter so the threshold
    # count is correct across multiple WS-4 replicas. A per-process deque would
    # split the count and the brute-force alert would never fire under scaling.
    if os.getenv("BUS_BACKEND", "memory").lower() == "redis":
        try:
            import redis  # type: ignore
            from window import RedisWindowCounter  # noqa: E402
            client = redis.Redis.from_url(
                os.getenv("REDIS_URL", "redis://localhost:6379/0"),
                decode_responses=True)
            counter = RedisWindowCounter(client)
            for r in detector.rules:
                if r.stateful:
                    r.set_counter(counter)
        except Exception:  # redis missing/unreachable -> per-replica deque fallback
            pass

    # One bus per produce; the runner gives each worker its own Bus, so the
    # handler produces through a fresh Bus() rather than closing over one.
    def handler(payload: dict) -> None:
        detect_one(Bus(), detector, payload)

    # P2.4: watch WS-4's own output topics for backpressure buildup (signal-only;
    # see start_depth_watchdog's docstring for why internal topics aren't trimmed).
    log = get_logger("ws4-detection")
    shutdown = threading.Event()
    warn_at = int(os.getenv("DETECTION_OUTPUT_DEPTH_WARN", "100000"))
    watchdog = start_depth_watchdog(Bus(), log, shutdown,
                                    ["scored.events", "ai.requests"], warn_at=warn_at)
    try:
        serve({"normalized.events": ("cg-detect", handler)},
              health_port=int(os.getenv("PORT", "8004")),
              service_name="ws4-detection", shutdown=shutdown)
    finally:
        if watchdog is not None:
            watchdog.join(timeout=5)


if __name__ == "__main__":
    main()
