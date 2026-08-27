"""WS-4 gap-hunt regressions (2026-08-27): Detector owns ITS rule dirs,
plugin-dir changes are part of the hot-reload fingerprint, and the
ai_enqueued counter counts only the LLM tier.

Covers three ws4/validate-contract contract findings in one zero-infra file
(memory bus, tmp dirs, no daemon):

  * R4-30: Detector._load() used to read the MODULE GLOBALS RULES_DIR/
    ALLOWLISTS_DIR, so a detector built with custom dirs loaded the global
    set and hot-reloaded the global set -- its own dirs were only honored
    for tenants. Now _load()/reload() read self.rules_dir/self.allowlists_dir,
    so a custom-dir detector loads AND reloads exactly ITS dirs.

  * Gap-hunt #5: rules_fingerprint()/the reload watcher used to ignore
    plugin rule packs entirely (self._plugin_rule_dirs), so editing a plugin
    pack could never trigger a hot-reload. Plugin dirs are now folded into
    the fingerprint, and the watcher watches each detector's own dirs.

  * Gap-hunt #9: ai_enqueued incremented for BOTH the "llm" and "classifier"
    actions while a separate classifier_enqueued also existed -- so
    ai_enqueued over-counted LLM cost whenever a cheap classifier-tier alert
    was queued. ai_enqueued now counts ONLY tier="llm"; classifier stays in
    classifier_enqueued (both still reach ai.requests).

Run: python services/ws4-detection/test_fix_plugin_reload_and_llm_metrics.py
"""
from __future__ import annotations

import os
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

from shared.bus import Bus  # noqa: E402
import main as ws4  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


# Instant, non-stateful rule (fires on the first matching event, like the
# test_design_b gated template). score_weight drives the funnel tier:
# >=60 -> "llm", 20-59 -> "classifier" (contracts/scoring.yaml).
_RULE_TMPL = """\
title: {title}
id: {id}
status: stable
level: {level}
logsource:
  category: test
detection:
  sel:
    class_uid: 3002
  condition: sel
siem:
  sector: common
  score_weight: {weight}
"""


def _rule(title, uid, level="medium", weight=50):
    return _RULE_TMPL.format(title=title, id=uid, level=level, weight=weight)


def _event(ingest_id="e1", ip="10.0.0.9"):
    return {
        "class_uid": 3002, "category_uid": 3, "activity_id": 1,
        "type_uid": 300201, "severity_id": 1, "time": 1750000000000,
        "status": "Success", "src_endpoint": {"ip": ip},
        "siem": {"sector": "common", "ingest_id": ingest_id},
    }


class TmpDirs:
    """Isolated empty rules/allowlists/tenants/plugins layout in a tmpdir,
    auto-cleaned."""

    def __enter__(self):
        base = Path(tempfile.mkdtemp(prefix="fengarde-rs4fix-"))
        self.rules = base / "rules"
        self.allowlists = base / "allowlists"
        self.tenants = base / "tenants"
        self.plugin = base / "plugin"
        self.rules.mkdir()
        self.plugin.mkdir()
        return self

    def __exit__(self, *exc):
        import shutil
        shutil.rmtree(self.rules.parent, ignore_errors=True)


# -- Fix 2 (R4-30): Detector loads/reloads ITS OWN dirs -------------------
def test_custom_rules_dir_is_loaded_not_the_module_global():
    """A detector built with a custom rules_dir must load THOSE rules, never
    the module-global RULES_DIR -- proven by a custom rule whose id/title
    exists nowhere in the real contracts/rules."""
    with TmpDirs() as t:
        (t.rules / "r.yml").write_text(
            _rule("R4-30 custom rule", "c0000000-0000-0000-0000-0000000000c1", weight=70),
            encoding="utf-8")
        det = ws4.Detector(rules_dir=t.rules, allowlists_dir=t.allowlists,
                           plugin_rule_dirs=[])
        titles = {r.title for r in det.rules}
        check("R4-30 custom rule" in titles,
              f"detector must load from ITS custom rules_dir, not the module "
              f"global RULES_DIR; got {sorted(titles)[:5]}...")


def test_reload_uses_its_own_dirs():
    """reload() must re-read the detector's custom dirs (not the globals):
    rewriting the file to a DIFFERENT rule id swaps the live set on reload."""
    with TmpDirs() as t:
        (t.rules / "r.yml").write_text(
            _rule("before", "b0000000-0000-0000-0000-0000000000b1", weight=10),
            encoding="utf-8")
        det = ws4.Detector(rules_dir=t.rules, allowlists_dir=t.allowlists,
                          plugin_rule_dirs=[])
        check(any(r.title == "before" for r in det.rules), "sanity: initial rule loaded")
        (t.rules / "r.yml").write_text(
            _rule("after", "a0000000-0000-0000-0000-0000000000a1", weight=10),
            encoding="utf-8")
        ok = det.reload()
        check(ok is True, "a valid custom-dir edit must reload")
        titles = {r.title for r in det.rules}
        check("before" not in titles and "after" in titles,
              "reload must swap in the NEW rule from the detector's custom dir")


# -- Fix 3 (NEW-hunt #5): plugin dirs are part of the fingerprint/watcher --
def test_plugin_edit_changes_fingerprint():
    """rules_fingerprint() must fold plugin_rule_dirs in so a plugin pack
    edit changes the poll value (before this fix it never did)."""
    with TmpDirs() as t:
        (t.rules / "base.yml").write_text(
            _rule("base", "d0000000-0000-0000-0000-0000000000d1", weight=20),
            encoding="utf-8")
        uid = "e0000000-0000-0000-0000-0000000000e1"
        (t.plugin / "p.yml").write_text(_rule("plugin v1", uid, weight=20),
                                        encoding="utf-8")
        fp1 = ws4.rules_fingerprint(t.rules, t.allowlists, t.tenants,
                                    plugin_rule_dirs=[t.plugin])
        time.sleep(0.05)
        (t.plugin / "p.yml").write_text(_rule("plugin v2", uid, weight=50),
                                        encoding="utf-8")
        fp2 = ws4.rules_fingerprint(t.rules, t.allowlists, t.tenants,
                                    plugin_rule_dirs=[t.plugin])
        check(fp1 != fp2,
              "editing a PLUGIN rule file must change the fingerprint")


def test_plugin_edit_triggers_watcher_reload_on_custom_dirs():
    """start_rule_reload_watcher() watches the detector's OWN dirs (R4-30)
    INCLUDING its plugin_rule_dirs (#5): edit a plugin pack file and the
    watcher swaps in the new plugin rule on a custom-dir detector."""
    with TmpDirs() as t:
        (t.rules / "base.yml").write_text(
            _rule("base", "f0000000-0000-0000-0000-0000000000f1", weight=20),
            encoding="utf-8")
        (t.plugin / "p.yml").write_text(
            _rule("plugin v1", "f0000000-0000-0000-0000-0000000000f2", weight=20),
            encoding="utf-8")
        det = ws4.Detector(rules_dir=t.rules, allowlists_dir=t.allowlists,
                          plugin_rule_dirs=[t.plugin])
        shutdown = threading.Event()
        # NO explicit dirs -> must resolve to detector's own rules+plugin dirs.
        th = ws4.start_rule_reload_watcher(det, shutdown, 0.05)
        check(th is not None, "interval_s>0 must start a watcher")
        time.sleep(0.15)
        (t.plugin / "p.yml").write_text(
            _rule("plugin v2", "f0000000-0000-0000-0000-0000000000f3", weight=20),
            encoding="utf-8")
        seen = False
        for _ in range(40):
            time.sleep(0.05)
            if any(r.title == "plugin v2" for r in det.rules):
                seen = True
                break
        check(seen,
              "editing a PLUGIN pack file must trigger a reload that swaps in "
              "the plugin rule (watcher must fold plugin dirs into its fingerprint)")
        shutdown.set()
        th.join(timeout=2)


# -- Fix 4 (gap-hunt #9): ai_enqueued counts ONLY the LLM tier ------------
def test_ai_enqueued_counts_only_llm_tier():
    """Both tiers reach ai.requests; ai_enqueued bumps for tier='llm' only,
    classifier_enqueued for tier='classifier' only -- no double counting."""
    # LLM tier: score_weight=70 >= llm_min(60)
    with TmpDirs() as t:
        (t.rules / "llm.yml").write_text(
            _rule("llm rule", "70000000-0000-0000-0000-000000000700", level="high", weight=70),
            encoding="utf-8")
        det = ws4.Detector(rules_dir=t.rules, allowlists_dir=t.allowlists,
                          plugin_rule_dirs=[])
        bus = Bus()
        ev = _event("e-llm")
        scored, _matched, action = det.process(ev)
        check(action == "llm", f"expected action 'llm', got {action!r} "
              f"(score {scored['siem']['score']})")
        ws4.detect_one(bus, det, ev)
        reqs = bus.drain("ai.requests")
        check(len(reqs) == 1, f"llm tier must enqueue 1 ai.requests, got {len(reqs)}")
        check(det.stats["ai_enqueued"] == 1,
              f"llm-tier enqueue must count ai_enqueued=1, got {det.stats['ai_enqueued']}")
        check(det.stats["classifier_enqueued"] == 0,
              f"llm tier must not touch classifier_enqueued, got {det.stats['classifier_enqueued']}")

    # Classifier tier (score_weight=30 in [20,60))
    with TmpDirs() as t:
        (t.rules / "clf.yml").write_text(
            _rule("classifier rule", "80000000-0000-0000-0000-000000000800", weight=30),
            encoding="utf-8")
        det2 = ws4.Detector(rules_dir=t.rules, allowlists_dir=t.allowlists,
                           plugin_rule_dirs=[])
        bus2 = Bus()
        ev2 = _event("e-clf")
        scored, _matched, action2 = det2.process(ev2)
        check(action2 == "classifier", f"expected action 'classifier', got {action2!r} "
              f"(score={scored['siem']['score']})")
        ws4.detect_one(bus2, det2, ev2)
        check(det2.stats["classifier_enqueued"] == 1,
              f"classifier tier must count classifier_enqueued=1, got {det2.stats['classifier_enqueued']}")
        check(det2.stats["ai_enqueued"] == 0,
              f"classifier tier must NOT inflate ai_enqueued, got {det2.stats['ai_enqueued']}")
        check(len(bus2.drain("ai.requests")) == 1,
              "classifier tier still reaches ai.requests")


def main():
    test_custom_rules_dir_is_loaded_not_the_module_global()
    test_reload_uses_its_own_dirs()
    test_plugin_edit_changes_fingerprint()
    test_plugin_edit_triggers_watcher_reload_on_custom_dirs()
    test_ai_enqueued_counts_only_llm_tier()

    if FAILS:
        print(f"[FAIL] plugin-reload+LLM-metrics: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] R4-30 custom-dir Detector (_load/reload use its own dirs); "
          "gap-hunt #5 (plugin packs in fingerprint + watcher hot-reload); "
          "gap-hunt #9 (ai_enqueued counts LLM tier only)")


if __name__ == "__main__":
    main()