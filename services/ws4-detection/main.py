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


class Detector:
    def __init__(self):
        self.rules = load_rules(RULES_DIR)
        self.scorer = Scorer(SCORING_YAML)
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
