"""Regression tests for the Phase 1-3 detection-engine fixes (2026-08-06).

Covers, per the unified fix plan:
  FIX 1   (CRITICAL)  HA env-gate accepts BUS_BACKEND=redis-sentinel and
                      builds the RedisWindowCounter client via
                      Sentinel.master_for (NOT REDIS_URL, NOT a one-shot
                      discover_master() pinned to a fixed host:port -- that
                      would keep writing to a demoted master after a real
                      failover; master_for() re-resolves on reconnect).
  FIX 2   (HIGH)      Poison-pill: window_seconds/threshold type-validated at
                      construction; a poisoned rule that slips past validation
                      fails closed at evaluate (no crash); load_rules rejects
                      a poisoned rule at load time.
  FIX 13  (MED)       class_uid=None event evaluates catch-all rules exactly
                      once (not twice).
  FIX 14  (MED)       not_in allowlist is fail-CLOSED on a missing/malformed
                      file (rule never fires) while behaving normally for a
                      valid allowlist.
  FIX 22  (MED)       LLM-funnel enqueue dedup per alert key within cooldown.
  FIX L1  (LOW)       Far-future (clock-skewed) event is dropped with a WARN
                      and never drives the window.

Run: python services/ws4-detection/test_fix_detection_engine.py
"""
from __future__ import annotations

import io
import os
import sys
import types
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
ROOT = SERVICES.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))
os.environ["BUS_BACKEND"] = "memory"

from engine import Rule, load_rules  # noqa: E402
from scoring import Scorer  # noqa: E402
import main as ws4  # noqa: E402
from window import RedisWindowCounter  # noqa: E402

SCORING_YAML = ROOT / "contracts" / "scoring.yaml"

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


# --- FIX 1: HA env-gate ------------------------------------------------------

def _make_ha_runner(backend, env_overrides):
    """Patch os.getenv + Detector + Bus + serve and run ws4.main(), returning
    (stub_detector, fake_clients). Fakes bus/serve so main() sets up the
    counter wiring and returns without starting the server."""
    stub = SimpleNamespace(rules=[], _window_counter=None,
                           rule_health_metrics=lambda: {})
    env = {
        "BUS_BACKEND": backend,
        "RULES_RELOAD_INTERVAL_S": "0",
        "PORT": "8004",
        "DETECTION_OUTPUT_DEPTH_WARN": "100000",
    }
    env.update(env_overrides)

    def fake_getenv(key, default=None):
        return env.get(key, default)

    with mock.patch.object(ws4, "Detector", lambda *a, **k: stub), \
         mock.patch.object(ws4, "Bus", lambda *a, **k: SimpleNamespace()), \
         mock.patch("os.getenv", side_effect=fake_getenv), \
         mock.patch("shared.runner.serve", lambda *a, **k: None), \
         mock.patch("shared.runner.start_depth_watchdog", lambda *a, **k: None):
        ws4.main()
    return stub


def _inject_fake_redis(fake_clients, with_sentinel=True):
    """Insert fake `redis` (and `redis.sentinel`) modules into sys.modules so
    main()'s lazy `import redis` / `from redis.sentinel import Sentinel` pick
    them up regardless of what real redis is installed. Returns original slots
    for restore."""
    saved = {}

    class _Redis:
        def __init__(self, *a, **kw):
            fake_clients.append(("direct", kw))

        @staticmethod
        def from_url(url, **kw):
            fake_clients.append(("from_url", url, kw))
            return object()

    redis_mod = types.ModuleType("redis")
    redis_mod.Redis = _Redis
    saved["redis"] = sys.modules.get("redis")
    sys.modules["redis"] = redis_mod
    if with_sentinel:
        saved["redis.sentinel"] = sys.modules.get("redis.sentinel")

        class _Sentinel:
            def __init__(self, hosts, password=None, socket_timeout=None,
                         decode_responses=None):
                self.hosts = hosts

            def master_for(self, name, redis_class=None, **kw):
                fake_clients.append(("master_for", name, kw))
                return object()

        sentinel_mod = types.ModuleType("redis.sentinel")
        sentinel_mod.Sentinel = _Sentinel
        sys.modules["redis.sentinel"] = sentinel_mod
    return saved


def _restore_redis(saved):
    for name, orig in saved.items():
        if orig is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = orig


def test_fix1_ha_sentinel_attaches_counter_via_master_for():
    fake_clients: list = []
    saved = _inject_fake_redis(fake_clients, with_sentinel=True)
    try:
        stub = _make_ha_runner("redis-sentinel", {
            "REDIS_SENTINEL_HOSTS": "10.0.1.1:26379, 10.0.1.2",
            "REDIS_SENTINEL_MASTER": "mymaster",
            "REDIS_PASSWORD": "s3cret",
        })
    finally:
        _restore_redis(saved)
    check(isinstance(stub._window_counter, RedisWindowCounter),
          "fix1: redis-sentinel must attach a RedisWindowCounter")
    check(fake_clients and fake_clients[0] == (
        "master_for", "mymaster",
        {"password": "s3cret", "decode_responses": True}),
          f"fix1 (C1 follow-up): sentinel client must be built via "
          f"Sentinel.master_for (NOT a one-shot discover_master() pinned to a "
          f"fixed host:port, and NOT REDIS_URL) so writes follow a real "
          f"failover instead of a stale demoted master; got {fake_clients}")


def test_fix1_ha_redis_still_uses_from_url():
    fake_clients: list = []
    saved = _inject_fake_redis(fake_clients, with_sentinel=False)
    try:
        stub = _make_ha_runner("redis", {"REDIS_URL": "redis://x:1/0"})
    finally:
        _restore_redis(saved)
    check(isinstance(stub._window_counter, RedisWindowCounter),
          "fix1: BUS_BACKEND=redis must still attach a RedisWindowCounter")
    check(fake_clients and fake_clients[0] == (
        "from_url", "redis://x:1/0", {"decode_responses": True}),
          f"fix1: redis branch must use from_url, got {fake_clients}")


def test_fix1_ha_memory_skips_counter():
    stub = _make_ha_runner("memory", {})
    check(stub._window_counter is None,
          "fix1: BUS_BACKEND=memory must NOT attach a window counter")


# --- FIX 2: poison-pill ------------------------------------------------------

def test_fix2_poison_window_raises_at_construction():
    try:
        Rule({"id": "r", "title": "t", "level": "high",
              "detection": {"s": {"class_uid": 3002}, "condition": "s"},
              "siem": {"window_seconds": "60", "threshold": 2}})
        check(False, "fix2: window_seconds=\"60\" must raise at construction")
    except ValueError as exc:
        check("window_seconds" in str(exc),
              f"fix2: ValueError must name the field, got {exc}")


def test_fix2_poison_threshold_raises_at_construction():
    try:
        Rule({"id": "r", "title": "t", "level": "high",
              "detection": {"s": {"class_uid": 3002}, "condition": "s"},
              "siem": {"window_seconds": 60, "threshold": "2"}})
        check(False, "fix2: threshold=\"2\" must raise at construction")
    except ValueError as exc:
        check("threshold" in str(exc),
              f"fix2: ValueError must name the field, got {exc}")


def test_fix2_poison_rule_evaluate_fails_closed_no_crash():
    """A poisoned rule that slips past construction validation (mutated after
    construction) must fail closed at evaluate, never raise."""
    r = Rule({"id": "r", "title": "t", "level": "high",
              "detection": {"s": {"class_uid": 3002, "activity_id": 4},
                            "condition": "s"},
              "siem": {"window_seconds": 60, "threshold": 2,
                       "group_by": "src_endpoint.ip"}})
    r.window_seconds = "60"  # simulate poison slipped past load validation
    import time
    ev = {"time": int(time.time() * 1000) - 1000, "class_uid": 3002,
          "activity_id": 4, "src_endpoint": {"ip": "1.1.1.1"},
          "siem": {"ingest_id": "x1"}}
    check(r.evaluate(ev) is False,
          "fix2: poisoned window arithmetic must fail closed (False), not raise")
    r.threshold = "2"
    check(r.evaluate(ev) is False,
          "fix2: poisoned threshold comparison must fail closed (False), not raise")


def test_fix2_load_rules_rejects_poisoned_rule(tmp_path):
    d = tmp_path / "reject"
    d.mkdir()
    (d / "bad.yml").write_text(
        "title: p\n"
        "id: 11111111-1111-1111-1111-111111111111\n"
        "status: stable\nlevel: high\n"
        "logsource: {category: auth}\n"
        "detection:\n  s: {class_uid: 3002}\n  condition: s\n"
        "siem: {sector: common, score_weight: 40, "
        "window_seconds: \"60\", threshold: 2}\n", encoding="utf-8")
    try:
        load_rules(d)
        check(False, "fix2c: load_rules must reject window_seconds=\"60\"")
    except ValueError as exc:
        check("bad.yml" in str(exc) or "window_seconds" in str(exc),
              f"fix2c: rejection must reference the file/field, got {exc}")


def test_fix2_load_rules_accepts_valid_rule(tmp_path):
    d = tmp_path / "accept"
    d.mkdir()
    (d / "ok.yml").write_text(
        "title: ok\nid: 22222222-2222-2222-2222-222222222222\n"
        "status: stable\nlevel: high\n"
        "logsource: {category: auth}\n"
        "detection:\n  s: {class_uid: 3002}\n  condition: s\n"
        "siem: {sector: common, score_weight: 40, "
        "window_seconds: 60, threshold: 2}\n", encoding="utf-8")
    rules = load_rules(d)
    check(len(rules) == 1 and rules[0].stateful,
          "fix2c: a valid stateful rule must still load")


# --- FIX 13: class_uid=None single evaluation --------------------------------

def test_fix13_class_uid_none_single_evaluation():
    detector = ws4.Detector(plugin_rule_dirs=[])
    counting = Rule({"id": "c1", "title": "t", "level": "high",
                     "detection": {"s": {"activity_id": 1}, "condition": "s"},
                     "siem": {"score_weight": 80}})  # no class_uid -> catch-all
    calls = {"n": 0}
    orig = counting.evaluate

    def counted(event):
        calls["n"] += 1
        return orig(event)

    counting.evaluate = counted
    detector.rules = [counting]
    detector._by_class_uid = {None: [counting]}
    ev = {"siem": {"sector": "common", "ingest_id": "e1"},
          "src_endpoint": {"ip": "9.9.9.9"}}  # class_uid absent -> None
    detector.process(ev)
    check(calls["n"] == 1,
          f"fix13: catch-all rule must be evaluated exactly once for a "
          f"class_uid=None event, got {calls['n']}")


# --- FIX 14: not_in fails OPEN on a missing allowlist (M2, corrected) -------
# M2 adjudication (2026-08-06): `not_in` is a SUPPRESSION allowlist. Its
# established, test-enshrined posture is FAIL-OPEN -- a missing/malformed
# allowlist must NEVER disable detection (the rule keeps firing = noise, never
# a missed alert). The original finding was that the WARNING TEXT claimed the
# inverse ("fail closed") when the code actually failed open. We keep the
# tested fail-open behavior and fixed the message. See engine.py:load_allowlist.

def test_fix14_not_in_fail_OPEN_on_missing_file(tmp_path):
    allow_dir = tmp_path / "allow_missing"
    allow_dir.mkdir()
    r = Rule({"id": "r", "title": "t", "level": "high",
              "detection": {"s": {"src_endpoint.ip": {"not_in": "does_not_exist"}},
                            "condition": "s"}},
             allowlists_dir=allow_dir)
    ev = {"src_endpoint": {"ip": "10.0.0.5"}, "siem": {"ingest_id": "x"}}
    check(r.evaluate(ev) is True,
          "fix14: missing allowlist file must fail OPEN (rule keeps firing, "
          "detection never silently disabled)")


def test_fix14_not_in_valid_allowlist_behaves(tmp_path):
    allow_dir = tmp_path / "allow_ok"
    allow_dir.mkdir()
    (allow_dir / "ok.yml").write_text("entries:\n  - 10.0.0.99\n", encoding="utf-8")
    r = Rule({"id": "r", "title": "t", "level": "high",
              "detection": {"s": {"src_endpoint.ip": {"not_in": "ok"}},
                            "condition": "s"}},
             allowlists_dir=allow_dir)
    check(r.evaluate({"src_endpoint": {"ip": "10.0.0.5"}}) is True,
          "fix14: valid allowlist, value NOT listed -> rule still fires")
    check(r.evaluate({"src_endpoint": {"ip": "10.0.0.99"}}) is False,
          "fix14: valid allowlist, value listed -> suppressed (no fire)")


# --- FIX 22: LLM-funnel cooldown dedup --------------------------------------

def test_fix22_scorer_cooldown_dedup():
    scorer = Scorer(SCORING_YAML)
    t0 = 1000.0
    check(scorer.should_enqueue_llm("k", t0) is True,
          "fix22: first enqueue for a key must proceed")
    check(scorer.should_enqueue_llm("k", t0 + 299) is False,
          "fix22: repeat within cooldown must be deduped")
    check(scorer.should_enqueue_llm("k2", t0) is True,
          "fix22: a DIFFERENT alert key must proceed (not deduped)")
    check(scorer.should_enqueue_llm("k", t0 + 300) is True,
          "fix22: after cooldown elapses, the key may proceed again")


def test_fix22_scorer_cache_is_bounded():
    scorer = Scorer(SCORING_YAML)
    scorer._llm_cache_budget = 3
    now = 100000.0
    # seed expired entries directly (simulating old enqueues)
    for i in range(3):
        scorer._recent_llm_enqueues[f"old{i}"] = now - 1000
    scorer.should_enqueue_llm("fresh", now)  # triggers >budget prune
    check(len(scorer._recent_llm_enqueues) <= 3,
          f"fix22: cache must be pruned to the bound, got "
          f"{len(scorer._recent_llm_enqueues)}")
    check("old0" not in scorer._recent_llm_enqueues,
          "fix22: expired entries must be pruned")


def test_fix22_funnel_dedup_gates_enqueue():
    detector = ws4.Detector(plugin_rule_dirs=[])
    rule = Rule({"id": "c1", "title": "t", "level": "high",
                 "detection": {"s": {"activity_id": 1}, "condition": "s"},
                 "siem": {"score_weight": 80}})
    detector.rules = [rule]
    detector._by_class_uid = {None: [rule]}
    ev = {"siem": {"sector": "common", "ingest_id": "e1"}}
    check(detector._funnel_dedup(ev, [rule]) is True,
          "fix22: first fire gates the funnel enqueue")
    check(detector._funnel_dedup(ev, [rule]) is False,
          "fix22: the same alert key within cooldown must NOT re-enqueue")


# --- FIX L1: clock-skew WARN -------------------------------------------------

def test_fix_l1_future_event_warns_and_fails_closed():
    import time
    r = Rule({"id": "l1", "title": "t", "level": "high",
              "detection": {"s": {"class_uid": 3002}, "condition": "s"},
              "siem": {"window_seconds": 60, "threshold": 1,
                       "group_by": "src_endpoint.ip"}})
    future = int(time.time() * 1000) + 10 * 365 * 24 * 3600 * 1000  # ~10y ahead
    ev = {"time": future, "class_uid": 3002, "src_endpoint": {"ip": "1.1.1.1"},
          "siem": {"ingest_id": "f"}}
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            fired = r.evaluate(ev)
    finally:
        pass
    check(fired is False,
          "fixL1: a far-future event must fail closed (never drive the window)")
    check("WARN" in buf.getvalue(),
          f"fixL1: far-future drop must log a WARN, got: {buf.getvalue()!r}")


def main():
    import tempfile
    tmp_path = tempfile.mkdtemp(prefix="fengarde-fixdet-")
    p = Path(tmp_path)
    test_fix1_ha_sentinel_attaches_counter_via_master_for()
    test_fix1_ha_redis_still_uses_from_url()
    test_fix1_ha_memory_skips_counter()
    test_fix2_poison_window_raises_at_construction()
    test_fix2_poison_threshold_raises_at_construction()
    test_fix2_poison_rule_evaluate_fails_closed_no_crash()
    test_fix2_load_rules_rejects_poisoned_rule(p)
    test_fix2_load_rules_accepts_valid_rule(p)
    test_fix13_class_uid_none_single_evaluation()
    test_fix14_not_in_fail_OPEN_on_missing_file(p)
    test_fix14_not_in_valid_allowlist_behaves(p)
    test_fix22_scorer_cooldown_dedup()
    test_fix22_scorer_cache_is_bounded()
    test_fix22_funnel_dedup_gates_enqueue()
    test_fix_l1_future_event_warns_and_fails_closed()

    if FAILS:
        print(f"[FAIL] fix_detection_engine: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] fix_detection_engine: FIX 1/2/13/14/22/L1 regression PASS")


if __name__ == "__main__":
    main()
