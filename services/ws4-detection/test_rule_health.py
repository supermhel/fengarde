"""M7 follow-up (2026-08-05): rule-health / dead-rule watchdog, zero infra.

Closes the gap between "rules that can fire" (eval/attack/fire_check.py,
proven 26/26) and "rules that ARE firing" (no live signal before this).
Covers: a fired rule's last-fired timestamp appears in
Detector.rule_health_metrics(); a never-fired rule is absent, not
fabricated as 0/None; a second fire advances the timestamp; the metrics
dict survives a rule reload keyed by rule id; and shared.runner.
render_prometheus renders the metric as a real gauge line end-to-end.
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
os.environ["BUS_BACKEND"] = "memory"

import main as ws4  # noqa: E402
from shared.bus import Bus  # noqa: E402
from shared.runner import render_prometheus  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _event():
    return {"class_uid": 9999, "category_uid": 0, "activity_id": 1, "type_uid": 999901,
            "severity_id": 1, "time": 1750000000000, "status": "Unknown",
            "src_endpoint": {"ip": "10.0.0.9"}}


_RULE = """\
title: Health-check test rule
id: 00000000-0000-0000-0000-0000000009{n:02d}
status: stable
logsource:
  category: test
detection:
  hit:
    class_uid: 9999
    activity_id: 1
  condition: hit
fields:
  - src_endpoint.ip
siem:
  sector: common
  score_weight: 10
  window_seconds: 60
  threshold: 1
  group_by: src_endpoint.ip
"""


def _with_tmp_rules_dir(fn):
    import shutil
    import tempfile
    orig_rules, orig_allow = ws4.RULES_DIR, ws4.ALLOWLISTS_DIR
    tmp = Path(tempfile.mkdtemp(prefix="fengarde-rulehealth-"))
    try:
        ws4.RULES_DIR = tmp
        ws4.ALLOWLISTS_DIR = tmp / "allowlists"
        fn(tmp)
    finally:
        ws4.RULES_DIR, ws4.ALLOWLISTS_DIR = orig_rules, orig_allow
        shutil.rmtree(tmp, ignore_errors=True)


def test_never_fired_rule_absent_not_fabricated():
    def body(tmp):
        (tmp / "r.yml").write_text(_RULE.format(n=1), encoding="utf-8")
        detector = ws4.Detector(plugin_rule_dirs=[])
        rule_id = detector.rules[0].id
        metrics = detector.rule_health_metrics()
        # A rule that hasn't fired must NOT appear as a fabricated
        # `rule_last_fired_timestamp:<id>` (0.0 is a lie about when it
        # fired) -- the deliberate prior contract. It IS surfaced via the
        # distinct `rule_never_fired:<id>`=1 marker (gap-hunt 2026-08-26
        # #15) so a dead rule stays visible to the Grafana panel without a
        # made-up timestamp.
        check(f"rule_last_fired_timestamp:{rule_id}" not in metrics,
              "a rule that hasn't fired must be ABSENT from the last-fired "
              "series, not present with a fabricated 0/None value")
        check(metrics.get(f"rule_never_fired:{rule_id}") == 1,
              f"a never-fired rule must be visible via rule_never_fired:"
              f"{rule_id}, got {metrics}")
    _with_tmp_rules_dir(body)


def test_fired_rule_records_a_real_timestamp():
    def body(tmp):
        (tmp / "r.yml").write_text(_RULE.format(n=2), encoding="utf-8")
        detector = ws4.Detector(plugin_rule_dirs=[])
        rule_id = detector.rules[0].id
        before = time.time()
        bus = Bus()
        ws4.detect_one(bus, detector, _event())
        after = time.time()
        metrics = detector.rule_health_metrics()
        key = f"rule_last_fired_timestamp:{rule_id}"
        check(key in metrics, f"fired rule must appear in rule_health_metrics, got {metrics}")
        check(before <= metrics[key] <= after,
              f"recorded timestamp {metrics[key]} must be within the fire window "
              f"[{before}, {after}]")
    _with_tmp_rules_dir(body)


def test_second_fire_advances_the_timestamp():
    def body(tmp):
        (tmp / "r.yml").write_text(_RULE.format(n=3), encoding="utf-8")
        detector = ws4.Detector(plugin_rule_dirs=[])
        rule_id = detector.rules[0].id
        detector.record_fire(rule_id, ts=1000.0)
        detector.record_fire(rule_id, ts=2000.0)
        metrics = detector.rule_health_metrics()
        check(metrics[f"rule_last_fired_timestamp:{rule_id}"] == 2000.0,
              "a second, later fire must overwrite the earlier timestamp (most-recent-fire "
              f"semantics), got {metrics}")
    _with_tmp_rules_dir(body)


def test_fire_history_survives_a_reload_keyed_by_rule_id():
    def body(tmp):
        (tmp / "r.yml").write_text(_RULE.format(n=4), encoding="utf-8")
        detector = ws4.Detector(plugin_rule_dirs=[])
        rule_id = detector.rules[0].id
        detector.record_fire(rule_id, ts=1234.0)

        # Edit the rule's threshold (same id) and reload -- same convention
        # test_hot_reload.py uses: window state (and now fire history) is
        # keyed by rule id, not object identity, so it must survive.
        edited = _RULE.format(n=4).replace("threshold: 1", "threshold: 5")
        (tmp / "r.yml").write_text(edited, encoding="utf-8")
        ok = detector.reload()
        check(ok is True, "a valid edit must reload successfully")
        metrics = detector.rule_health_metrics()
        check(metrics.get(f"rule_last_fired_timestamp:{rule_id}") == 1234.0,
              f"fire history for an edited-but-still-present rule id must survive "
              f"reload(), got {metrics}")
    _with_tmp_rules_dir(body)


def test_renders_as_a_real_prometheus_gauge_line():
    rule_id = "00000000-0000-0000-0000-000000000999"
    extra = {f"rule_last_fired_timestamp:{rule_id}": 1700000000.5}
    text = render_prometheus("ws4-detection", {}, extra)
    check("fengarde_extra" in text, f"expected the fengarde_extra gauge block, got:\n{text}")
    check(f'field="rule_last_fired_timestamp:{rule_id}"' in text,
          f"expected the rule id as a field label, got:\n{text}")
    check("1700000000.5" in text, f"expected the real timestamp value rendered, got:\n{text}")


def main():
    test_never_fired_rule_absent_not_fabricated()
    test_fired_rule_records_a_real_timestamp()
    test_second_fire_advances_the_timestamp()
    test_fire_history_survives_a_reload_keyed_by_rule_id()
    test_renders_as_a_real_prometheus_gauge_line()

    if FAILS:
        print(f"[FAIL] rule_health: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] rule-health watchdog: fired rules get a real last-fired timestamp, "
          "never-fired rules are absent (not fabricated), a later fire advances the "
          "timestamp, fire history survives a rule reload, and the metric renders as "
          "a real Prometheus gauge line via /metrics/prom")


if __name__ == "__main__":
    main()
