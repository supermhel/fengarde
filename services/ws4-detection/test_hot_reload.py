"""B4: rule hot-reload -- Detector.reload() and rules_max_mtime(), zero infra.

Covers: a valid edit swaps in and changes firing behavior; a malformed edit
is rejected and the previous rule set keeps working (fail-closed); a
removed rule stops firing. start_rule_reload_watcher()'s poll loop is
exercised directly (short interval, real filesystem, no bus/daemon needed).
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))
os.environ["BUS_BACKEND"] = "memory"

import main as ws4  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


_RULE_TMPL = """\
title: Test threshold rule
id: 00000000-0000-0000-0000-00000000000{n}
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
  threshold: {threshold}
  group_by: src_endpoint.ip
"""


def _event():
    return {"class_uid": 9999, "category_uid": 0, "activity_id": 1, "type_uid": 999901,
            "severity_id": 1, "time": 1750000000000, "status": "Unknown",
            "src_endpoint": {"ip": "10.0.0.9"}}


def _with_tmp_rules_dir(fn):
    """Point ws4.RULES_DIR/ALLOWLISTS_DIR at a fresh tmpdir for the duration
    of `fn(rules_dir)`, then restore the real contract dirs -- Detector._load
    reads those module globals directly, same knob test_tenants.py-style
    tests use."""
    orig_rules, orig_allow = ws4.RULES_DIR, ws4.ALLOWLISTS_DIR
    tmp = Path(tempfile.mkdtemp(prefix="fengarde-hotreload-"))
    try:
        ws4.RULES_DIR = tmp
        ws4.ALLOWLISTS_DIR = tmp / "allowlists"  # doesn't need to exist
        fn(tmp)
    finally:
        ws4.RULES_DIR, ws4.ALLOWLISTS_DIR = orig_rules, orig_allow
        shutil.rmtree(tmp, ignore_errors=True)


def test_reload_picks_up_a_new_threshold():
    def body(tmp):
        (tmp / "r.yml").write_text(_RULE_TMPL.format(n=1, threshold=100), encoding="utf-8")
        detector = ws4.Detector(plugin_rule_dirs=[])
        _, matched, _ = detector.process(_event())
        check(matched == [], "threshold=100 must not fire on a single event")

        (tmp / "r.yml").write_text(_RULE_TMPL.format(n=1, threshold=1), encoding="utf-8")
        ok = detector.reload()
        check(ok is True, "a valid edit must reload successfully")
        _, matched2, _ = detector.process(_event())
        check(len(matched2) == 1, f"threshold=1 after reload must fire, got {matched2}")
    _with_tmp_rules_dir(body)


def test_reload_rejects_malformed_edit_keeps_old_set():
    def body(tmp):
        (tmp / "r.yml").write_text(_RULE_TMPL.format(n=2, threshold=1), encoding="utf-8")
        detector = ws4.Detector(plugin_rule_dirs=[])
        _, matched, _ = detector.process(_event())
        check(len(matched) == 1, "sanity: valid rule fires before the bad edit")

        (tmp / "r.yml").write_text("not: [valid, yaml, condition\n", encoding="utf-8")
        ok = detector.reload()
        check(ok is False, "a malformed edit must fail reload()")
        _, matched2, _ = detector.process(_event())
        check(len(matched2) == 1, "the PREVIOUS rule set must still fire after a rejected reload")
    _with_tmp_rules_dir(body)


def test_reload_removed_rule_stops_firing():
    def body(tmp):
        (tmp / "r.yml").write_text(_RULE_TMPL.format(n=3, threshold=1), encoding="utf-8")
        detector = ws4.Detector(plugin_rule_dirs=[])
        _, matched, _ = detector.process(_event())
        check(len(matched) == 1, "sanity: rule fires before removal")

        (tmp / "r.yml").unlink()
        ok = detector.reload()
        check(ok is True, "removing the only rule file must still be a valid (empty) reload")
        _, matched2, _ = detector.process(_event())
        check(matched2 == [], "a removed rule must not fire after reload")
    _with_tmp_rules_dir(body)


def test_rules_max_mtime_reflects_real_changes():
    def body(tmp):
        (tmp / "r.yml").write_text(_RULE_TMPL.format(n=4, threshold=1), encoding="utf-8")
        m1 = ws4.rules_max_mtime(tmp, tmp / "allowlists")
        check(m1 > 0, "mtime of an existing rule file must be > 0")
        time.sleep(0.05)
        (tmp / "r.yml").write_text(_RULE_TMPL.format(n=4, threshold=2), encoding="utf-8")
        m2 = ws4.rules_max_mtime(tmp, tmp / "allowlists")
        check(m2 >= m1, "rewriting the file must not decrease max mtime")
        check(ws4.rules_max_mtime(tmp / "does-not-exist", tmp / "also-missing") == 0.0,
              "a nonexistent dir must report mtime 0.0, not raise")
    _with_tmp_rules_dir(body)


def test_reload_watcher_disabled_by_default():
    detector = ws4.Detector(plugin_rule_dirs=[])
    shutdown = threading.Event()
    t = ws4.start_rule_reload_watcher(detector, shutdown, 0)
    check(t is None, "interval_s<=0 must start no thread (matches pre-B4 default)")


def test_reload_watcher_picks_up_a_change():
    def body(tmp):
        (tmp / "r.yml").write_text(_RULE_TMPL.format(n=5, threshold=100), encoding="utf-8")
        detector = ws4.Detector(plugin_rule_dirs=[])
        shutdown = threading.Event()
        t = ws4.start_rule_reload_watcher(detector, shutdown, 0.05,
                                          rules_dir=tmp, allowlists_dir=tmp / "allowlists")
        check(t is not None, "interval_s>0 must start a watcher thread")
        time.sleep(0.15)
        (tmp / "r.yml").write_text(_RULE_TMPL.format(n=5, threshold=1), encoding="utf-8")
        # give the poll loop a few ticks to notice the mtime change
        for _ in range(20):
            time.sleep(0.05)
            _, matched, _ = detector.process(_event())
            if matched:
                break
        check(bool(matched), "watcher must reload the lowered threshold within a few ticks")
        shutdown.set()
        t.join(timeout=2)
        check(not t.is_alive(), "watcher thread must exit after shutdown.set()")
    _with_tmp_rules_dir(body)


def main():
    test_reload_picks_up_a_new_threshold()
    test_reload_rejects_malformed_edit_keeps_old_set()
    test_reload_removed_rule_stops_firing()
    test_rules_max_mtime_reflects_real_changes()
    test_reload_watcher_disabled_by_default()
    test_reload_watcher_picks_up_a_change()

    if FAILS:
        print(f"[FAIL] hot_reload: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] B4 hot-reload: valid edit swaps in, malformed edit rejected "
          "(fail-closed, old set kept), removed rule stops firing, mtime poll "
          "watcher off by default and picks up real changes when enabled")


if __name__ == "__main__":
    main()
