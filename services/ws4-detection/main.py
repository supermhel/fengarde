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
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
ROOT = SERVICES.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))

from shared.bus import Bus  # noqa: E402
from engine import load_rules  # noqa: E402
from shared.window import DequeWindowCounter  # noqa: E402
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
                 plugin_rule_dirs: list[Path] | None = None,
                 force_linear_scan: bool = False):
        """``plugin_rule_dirs``: directories of extra rule YAML to merge in,
        same shape as ``contracts/rules/*.yml``. Defaults to whatever
        ``plugins.discover_rule_pack_dirs()`` finds installed via the
        ``fengarde.rule_packs`` entry-point group (M4.5, empty in this repo
        by default -- pass ``[]`` explicitly to skip discovery, e.g. in a
        test that wants a deterministic rule set regardless of what's
        installed in the environment).

        ``force_linear_scan`` (default False, byte-identical behavior when
        unset): bypasses the B1 class_uid bucket index in process() and
        evaluates every loaded rule against every event, the pre-B1
        behavior. Exists ONLY as a measurement knob for
        ``tools/fengarde_bench.py --compare-prefilter`` -- the "before"
        side of the before/after number the bench module's own docstring
        used to list as a still-open TODO (2026-08-19). Never set true in
        a real deployment path (main()/reload() never pass it)."""
        self._force_linear_scan = force_linear_scan
        self._plugin_rule_dirs = (
            [d for _name, d in discover_rule_pack_dirs()]
            if plugin_rule_dirs is None else plugin_rule_dirs)
        self.scorer = Scorer(SCORING_YAML)
        self.tenants_dir = tenants_dir
        # Detector-owned (not Rule-owned) so it survives reload(): each
        # DequeWindowCounter.hit()/hit_distinct() call is keyed by a string
        # that already starts with the rule's id (engine.py's window_key),
        # so one shared counter here correctly preserves in-flight window
        # state across a reload the same way RedisWindowCounter does globally
        # -- a fresh Rule object with the SAME id resumes the SAME window.
        # Previously this was `None` on the default in-memory backend (only
        # ever set to a real counter in main() when BUS_BACKEND=redis), which
        # meant _load()'s `if self._window_counter is not None` skipped
        # rewiring entirely -- every reload() built brand-new Rule objects
        # each allocating their OWN empty DequeWindowCounter (engine.py's
        # Rule.__init__), silently resetting every stateful rule's window to
        # zero on every hot-reload tick, contradicting this class's own
        # reload() docstring. main() still overwrites this with a
        # RedisWindowCounter when BUS_BACKEND=redis/redis-sentinel.
        self._window_counter = DequeWindowCounter()
        # M7 follow-up (2026-08-05): rule-health watchdog. Keyed by rule id (not
        # object identity) so it survives a reload() the same way window state
        # does -- an edited rule keeps its fire history, a removed-then-readded
        # rule with the same id keeps it too. In-process only (no cross-replica
        # aggregation): each WS-4 replica reports its own view, same scope as
        # every other counter this module already tracks via shared.runner.Metrics.
        self.rule_last_fired: dict[str, float] = {}
        # Gap-hunt (2026-08-26): the scored/alerts/ai_enqueued counters used to
        # live ONLY in run(), the batch path the daemon never calls -- the prod
        # detect_one path exposed zero counters. Tracked on the detector now so
        # BOTH paths (run() and detect_one/_emit) feed the same gauges, exposed
        # via metrics()/main()'s metrics_provider.
        self.stats: dict[str, int] = {"scored": 0, "alerts": 0,
                                      "ai_enqueued": 0, "classifier_enqueued": 0}
        self.rules, self._by_class_uid = self._load()

    def record_fire(self, rule_id: str, ts: float | None = None) -> None:
        """Record that ``rule_id`` fired, for the rule-health Prometheus surface."""
        self.rule_last_fired[rule_id] = time.time() if ts is None else ts

    def rule_health_metrics(self) -> dict:
        """Zero-arg callable shape expected by ``shared.runner.serve``'s
        ``metrics_provider``.

        TWO series, so never-firing rules are visible WITHOUT fabricating a
        timestamp (a deliberate prior contract -- test_rule_health.py rejects
        a made-up ``rule_last_fired_timestamp:0``):

          * ``rule_last_fired_timestamp:<id>`` -- the real most-recent fire
            epoch for rules that HAVE fired (unchanged, honest).
          * ``rule_never_fired:<id>`` = 1 -- one gauge per LOADED rule that
            has NEVER fired (gap-hunt 2026-08-26 #15). A dead/never-firing
            rule is otherwise invisible to the Grafana panel built to catch
            it; this distinct key flags it from boot without lying about the
            last-fired time. Rebuilt from the CURRENT rule set each call, so
            a rule removed by a reload drops out of both series.
        """
        out = {f"rule_last_fired_timestamp:{r.id}": self.rule_last_fired[r.id]
               for r in self.rules if r.id in self.rule_last_fired}
        for r in self.rules:
            if r.id not in self.rule_last_fired:
                out[f"rule_never_fired:{r.id}"] = 1
        return out

    def metrics(self) -> dict:
        """Combined metrics_provider for the daemon (main()): the per-rule
        rule-health gauges PLUS the emit-path counters that only run() used to
        track (gap-hunt 2026-08-26) -- detect_one, the real daemon path, now
        bumps self.stats via _emit(), so /metrics reflects production."""
        out = self.rule_health_metrics()
        out.update({
            "detection_scored_total": self.stats["scored"],
            "detection_alerts_total": self.stats["alerts"],
            "detection_ai_enqueued_total": self.stats["ai_enqueued"],
            "detection_classifier_enqueued_total": self.stats["classifier_enqueued"],
        })
        return out

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
        if self._force_linear_scan:
            # Measurement-only path (see __init__ docstring): every rule,
            # no bucket index -- the pre-B1 linear scan.
            candidates = self.rules
        else:
            class_uid = event.get("class_uid")
            # FIX 13 (2026-08-06): an event with class_uid=None (no class equality)
            # must get only the catch-all bucket, NOT the catch-all added twice --
            # the old expression `by_class.get(None, []) + by_class[None]` would
            # evaluate every catch-all rule TWICE against such an event (double
            # stateful-window hits / duplicate alerts). When the class is present,
            # the class bucket is combined with the catch-all as before.
            if class_uid is None:
                candidates = self._by_class_uid[None]
            else:
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
        # Design-B (2026-07-29 audit): route off routing_score, NOT the
        # analyst-facing score -- routing_score is the one that respects a
        # matched rule's llm_gate:false opt-out. The stored/displayed score
        # above is unaffected either way.
        action = self.scorer.route(self.scorer.routing_score(matched))
        return event, matched, action

    def _funnel_fresh(self, event: dict, matched: list) -> bool:
        """FIX 22: gate an ``ai.requests`` enqueue. Returns True when at least
        one matched rule's alert_key is not within the LLM-funnel cooldown.
        No matched rules -> no dedup to apply (True).

        Gap-hunt (2026-08-26): this is a pure CHECK -- it must NOT record the
        cooldown (the old ``_funnel_dedup`` did, via Scorer.should_enqueue_llm,
        which committed the cooldown BEFORE bus.produce ran). Commit the
        cooldown with ``_record_funnel`` ONLY after produce succeeds, so a
        produce failure leaves the gate open for redelivery to re-enqueue."""
        if not matched:
            return True
        for rule in matched:
            if self.scorer.is_llm_funnel_fresh(rule.alert_key(event)):
                return True
        return False

    def _record_funnel(self, event: dict, matched: list) -> None:
        """Commit the LLM/classifier-funnel cooldown for every matched rule's
        alert_key. Call ONLY after ``bus.produce('ai.requests', ...)`` returned
        successfully (see _funnel_fresh)."""
        for rule in matched:
            self.scorer.record_enqueue(rule.alert_key(event))

    def _emit(self, bus, event: dict, matched: list, action: str) -> tuple[int, int, int]:
        """Emit the scored/alert/funnel records for one processed event. This
        is the SINGLE code path behind BOTH detect_one() and run() -- the two
        used to be independent parallel copies that had to be changed in lockstep
        (their docstrings warned about exactly that drift). Returns
        ``(n_alerts, n_ai_enqueued, n_classifier_enqueued)`` for run()'s stats
        (detect_one ignores the return).

        Ordering contract (gap-hunt 2026-08-26, CRITICAL): the ``ai.requests``
        emit is CHECK -> PRODUCE -> RECORD. The funnel cooldown entry is only
        committed AFTER ``bus.produce`` returns. If produce raises, this method
        propagates (callers re-raise), the message stays unacked, and the next
        redelivery re-checks a FRESH gate and re-enqueues. Committing the
        cooldown before produce meant a produce failure silently skipped the
        re-enqueue forever (2 alerts, 0 ai.requests, no exception/error/metric).
        """
        key = (event.get("src_endpoint") or {}).get("ip", "0.0.0.0")
        bus.produce("scored.events", key=key, payload=event)
        self.stats["scored"] += 1
        n_alerts = n_ai = n_clf = 0
        for rule in matched:
            alert = make_alert(event, rule, event["siem"]["score"])
            bus.produce("alerts", key=alert["alert_id"], payload=alert)
            self.record_fire(rule.id)
            self.stats["alerts"] += 1
            n_alerts += 1
        # P1-2 (2026-07-21 audit): scoring.yaml/sigma-convention.md promise a
        # 20-59 "light classifier" band, but only action==\"llm\" (>=60) ever
        # reached ai.requests -- the band was dead, scores 20-59 got indexed and
        # never classified. `tier` tells WS-5 which layer to run: "llm" pays for
        # a real model call; "classifier" runs only the cheap deterministic/ML
        # classifier (classifier.py) -- never the LLM, or the whole point of a
        # separate cheap tier is defeated.
        if action in ("llm", "classifier") and self._funnel_fresh(event, matched):
            bus.produce("ai.requests", key=event["siem"].get("ingest_id", key),
                        payload={"event_id": event["siem"].get("ingest_id"),
                                 "event": event, "tier": action,
                                 "reason": [r.title for r in matched]})
            self._record_funnel(event, matched)  # only AFTER produce succeeded
            self.stats["ai_enqueued"] += 1
            n_ai += 1
            if action == "classifier":
                self.stats["classifier_enqueued"] += 1
                n_clf += 1
        return n_alerts, n_ai, n_clf


def rules_fingerprint(rules_dir: Path = RULES_DIR, allowlists_dir: Path = ALLOWLISTS_DIR,
                      tenants_dir: Path = TENANTS_DIR) -> tuple:
    """Sorted ``(filename, mtime)`` tuple across every rule/allowlist/tenant-
    config YAML, ``()`` if none of the dirs exist. Used by the B4 hot-reload
    poll to detect \"something on disk changed\" without re-parsing on every
    tick.

    Gap-hunt (2026-08-26): the old poll compared only the MAX mtime, so
    deleting/restoring a NON-newest file (whose mtime is rarely the max) never
    changed the poll value and the watcher never reloaded. A fingerprint of ALL
    files sees any add/remove/edit. Tenants_dir is included for the same reason
    rules_max_mtime included it (a tenant disabled-rules edit must take effect).

    ``(name, mtime)`` (not a full path) is enough: on a duplicate name the
    stable sort preserves the fixed rules->allowlists->tenants iteration order,
    so the tuple is deterministic for a given set of dirs/files/mtimes."""
    entries: list[tuple] = []
    for d in (rules_dir, allowlists_dir, tenants_dir):
        if not d.is_dir():
            continue
        for f in d.glob("*.yml"):
            try:
                entries.append((f.name, f.stat().st_mtime))
            except OSError:
                pass
    return tuple(sorted(entries))


def rules_max_mtime(rules_dir: Path = RULES_DIR, allowlists_dir: Path = ALLOWLISTS_DIR,
                    tenants_dir: Path = TENANTS_DIR) -> float:
    """Max mtime across every rule/allowlist/tenant-config YAML, 0.0 if none
    of the dirs exist. Kept as a compatibility view over rules_fingerprint();
    the B4 hot-reload poll must use rules_fingerprint() instead -- a max-mtime
    comparison cannot see the delete/restore of a non-newest file, so such a
    change would never trigger a reload (gap-hunt 2026-08-26)."""
    latest = 0.0
    for _name, mtime in rules_fingerprint(rules_dir, allowlists_dir, tenants_dir):
        latest = max(latest, mtime)
    return latest


def start_rule_reload_watcher(detector: "Detector", shutdown, interval_s: float,
                              rules_dir: Path = RULES_DIR, allowlists_dir: Path = ALLOWLISTS_DIR,
                              tenants_dir: Path = TENANTS_DIR):
    """B4: opt-in mtime-poll hot-reload. Returns None (no thread) when
    ``interval_s <= 0`` -- the default, byte-for-byte the pre-B4 behavior.
    Otherwise starts a daemon thread that calls ``detector.reload()`` at
    most once per ``interval_s`` seconds, only when the rules/allowlists/
    tenants directories' FINGERPRINT (all files' (name, mtime), not just the
    max mtime -- gap-hunt 2026-08-26) has actually changed since the last
    check. Also clears tenants.py's per-tenant cache on every such tick,
    since a tenant-config-only edit doesn't change RULES_DIR/ALLOWLISTS_DIR
    and detector.reload() alone would never pick it up."""
    if interval_s <= 0:
        return None
    import threading
    from shared.log import get_logger
    from tenants import invalidate_cache as invalidate_tenant_cache
    log = get_logger("ws4-detection")

    def _loop():
        last = rules_fingerprint(rules_dir, allowlists_dir, tenants_dir)
        while not shutdown.wait(interval_s):
            fp = rules_fingerprint(rules_dir, allowlists_dir, tenants_dir)
            if fp == last:
                continue
            last = fp
            invalidate_tenant_cache()
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
        # Gap-hunt (2026-08-26): 6 shipped rules key on the destination, but
        # make_alert never copied it, so dest-field lookups on alerts-* came
        # back empty. Mirror the src_endpoint passthrough (these are raw event
        # fields; the OpenSearch alerts mapping declares what is indexable).
        "dst_endpoint": event.get("dst_endpoint", {}),
        "actor": event.get("actor", {}),
        # Design-A (2026-07-29 audit): a stateful alert's window counter
        # already remembers which events/values contributed (window.py's
        # members()/distinct_members()) -- Rule.contributing_event_ids()
        # reads that back instead of recording only the one event that
        # happened to cross the threshold. Falls back to the single
        # triggering id for non-stateful rules or when the counter has
        # nothing to report (never fabricates an id).
        "event_ids": rule.contributing_event_ids(event),
        # Gap-hunt (2026-08-26): WS-3's list_alerts filters on
        # {"term": {"triage.status": ...}} and the alerts mapping is
        # dynamic:false, so an ALERT MUST carry an explicit triage field
        # at creation or every status-filtered GET returns zero results on
        # OpenSearch (MemoryStore.List_alerts defaults a missing triage to
        # "new", which is why the offline suite stayed green). Stamp the
        # initial triage here so the prod read path and MemoryStore agree.
        # Only set it when absent from a redelivered envelope so an
        # analyst's saved triage on a pre-existing alert is never reset.
        "triage": event.get("triage") or {"status": "new"},
    }


def detect_one(bus, detector: "Detector", event: dict) -> None:
    """Process a single normalized event and emit its derived records.

    Backs the shared-runner handler (daemon). Raises on any failure so the
    runner leaves the message unacked for redelivery.

    **Shared with run()**: ever since the gap-hunt (2026-08-26) funnel-
    ordering fix, BOTH entry points delegate to Detector._emit(), the single
    emission path -- the "two parallel copies that must be changed together"
    era is over (the old copies had already drifted into the
    cooldown-before-produce bug once; that class of defect cannot recur)."""
    event, matched, action = detector.process(event)
    detector._emit(bus, event, matched, action)


def run(bus, detector: "Detector") -> dict:
    stats = {"scored": 0, "alerts": 0, "ai_enqueued": 0, "classifier_enqueued": 0}
    for msg in bus.consume("normalized.events", group="cg-detect"):
        event, matched, action = detector.process(msg.payload)
        # _emit also bumps detector.stats (the daemon-side counters, gap-hunt
        # 2026-08-26); the local `stats` stays the per-run() view the batch
        # harnesses assert on.
        n_alerts, n_ai, n_clf = detector._emit(bus, event, matched, action)
        stats["scored"] += 1
        stats["alerts"] += n_alerts
        stats["ai_enqueued"] += n_ai
        stats["classifier_enqueued"] += n_clf
    return stats


def main():
    import threading  # noqa: E402
    from shared.runner import serve, start_depth_watchdog  # noqa: E402  (lazy: keeps run() import-light)
    from shared.log import get_logger  # noqa: E402

    detector = Detector()

    _backend = os.getenv("BUS_BACKEND", "memory").lower()
    # T6: on a shared Redis bus, give stateful rules a GLOBAL window counter so
    # the threshold count is correct across multiple WS-4 replicas. A per-process
    # deque would split the count and the brute-force alert would never fire
    # under scaling. Stashed on the detector (not just applied once) so a later
    # reload() also rewires newly-loaded rule objects onto the same counter.
    # FIX 1 (CRITICAL, 2026-08-06): the HA compose sets BUS_BACKEND=redis-sentinel,
    # which the old exact == "redis" gate silently ignored -> 12 stateful rules
    # fell back to per-process counters that never fire at scale. Now BOTH
    # "redis" and "redis-sentinel" are wired.
    #
    # C1 follow-up (2026-08-06): the first version resolved the master ONCE via
    # `Sentinel.discover_master()` and built a plain `redis.Redis(host, port)`
    # pinned to that address. Sentinel exists to survive exactly the event that
    # breaks a pinned client: on a real failover the old master demotes to a
    # replica, starts answering "READONLY You can't write against a read only
    # replica.", and the pinned client keeps hammering it until the process is
    # restarted -- the counter goes dark for the rest of the process lifetime.
    # `Sentinel.master_for()` returns a client that re-asks Sentinel for the
    # current master on each new connection (including the reconnect after a
    # failover breaks the old one), so writes follow the master automatically.
    if _backend in ("redis", "redis-sentinel"):
        try:
            import redis  # type: ignore
            from shared.window import RedisWindowCounter  # noqa: E402
            if _backend == "redis-sentinel":
                from redis.sentinel import Sentinel  # type: ignore
                sentinel_hosts = []
                for part in os.getenv("REDIS_SENTINEL_HOSTS", "").split(","):
                    part = part.strip()
                    if not part:
                        continue
                    host, _, port = part.partition(":")
                    sentinel_hosts.append((host.strip(),
                                           int(port.strip()) if port.strip() else 26379))
                master_name = os.getenv("REDIS_SENTINEL_MASTER", "mymaster")
                password = os.getenv("REDIS_PASSWORD", "") or None
                sentinel = Sentinel(sentinel_hosts, password=password,
                                    socket_timeout=1, decode_responses=True)
                client = sentinel.master_for(master_name, redis_class=redis.Redis,
                                             password=password,
                                             decode_responses=True)
            else:
                client = redis.Redis.from_url(
                    os.getenv("REDIS_URL", "redis://localhost:6379/0"),
                    decode_responses=True)
            counter = RedisWindowCounter(client)
            detector._window_counter = counter
            for r in detector.rules:
                if r.stateful:
                    r.set_counter(counter)
        except ImportError:
            # Code-quality #1 (2026-07-29 audit): only the documented case --
            # redis-py isn't installed -- falls back silently to the
            # per-replica deque counter. That fallback is the exact mode T6's
            # comment above warns is broken under horizontal scaling (each
            # replica sees a fraction of events, brute-force never trips), so
            # anything else that can raise here (a bug in this setup code,
            # not "redis missing") must not be swallowed into that mode with
            # zero operator visibility -- let it propagate and crash loudly
            # instead.
            get_logger("ws4-detection").warn(
                f"BUS_BACKEND={_backend} requested but redis-py is not installed; "
                "falling back to per-replica window counter (NOT safe across "
                "multiple WS-4 replicas)")

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
                                    ["scored.events", "ai.requests", "alerts"],
                                    warn_at=warn_at)
    # B4: opt-in rule hot-reload, off by default (RULES_RELOAD_INTERVAL_S=0) --
    # matches the pre-existing load-once-at-startup behavior byte-for-byte.
    reload_interval = float(os.getenv("RULES_RELOAD_INTERVAL_S", "0"))
    reload_thread = start_rule_reload_watcher(detector, shutdown, reload_interval)
    # Task M / Finding F4 (2026-08-07): one flooding tenant's messages used to
    # sit ahead of every other tenant's in this single serial consume loop,
    # degrading their detection latency in lockstep with the flood. Default
    # ON: for the common single-tenant case this degenerates to plain FIFO
    # (see fairness.py's docstring), so it's behavior-preserving there and a
    # real fix for the multi-tenant case. FENGARDE_TENANT_FAIR_CONSUME=0 opts
    # back out to the raw bus if ever needed.
    bus_factory = Bus
    if os.getenv("FENGARDE_TENANT_FAIR_CONSUME", "1").strip().lower() not in ("0", "false", "no"):
        from shared.fairness import FairConsumeBus, default_tenant_key

        def bus_factory():
            return FairConsumeBus(Bus(), tenant_key_fn=default_tenant_key)
    try:
        serve({"normalized.events": ("cg-detect", handler)},
              health_port=int(os.getenv("PORT", "8004")),
              service_name="ws4-detection", shutdown=shutdown,
              # Gap-hunt (2026-08-26) #11: was detector.rule_health_metrics --
              # per-rule gauges only. detector.metrics() adds the emit-path
              # counters (scored/alerts/ai_enqueued) that used to exist only
              # in run(), the batch path the daemon never calls.
              metrics_provider=detector.metrics,
              bus_factory=bus_factory)
    finally:
        if watchdog is not None:
            watchdog.join(timeout=5)
        if reload_thread is not None:
            reload_thread.join(timeout=5)


if __name__ == "__main__":
    main()
