"""v0.4 (P1.7) rule-tuning tests.

after_hours_admin gained an `actor.user.name not_in: service_accounts` clause so
routine service accounts can be silenced without losing the signal for human
admins. Ships empty (nothing suppressed); this proves both states.

Run: C:/Python313/python.exe services/ws4-detection/test_v04_rule_tuning.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from engine import Rule  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _rule(allowlists_dir):
    # Mirrors common_after_hours_admin's suppression clause in isolation (no time
    # predicate, so the test is deterministic regardless of wall clock).
    return Rule({
        "id": "ah", "title": "after-hours admin", "level": "high",
        "detection": {
            "priv": {"class_uid": 1002, "activity_id": 2,
                     "actor.user.name": {"not_in": "service_accounts"}},
            "condition": "priv",
        },
        "siem": {"score_weight": 60},
    }, allowlists_dir=allowlists_dir)


def _event(user):
    return {"class_uid": 1002, "activity_id": 2, "actor": {"user": {"name": user}}}


def run():
    # --- populated allowlist: listed service account suppressed, human fires ---
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "service_accounts.yml").write_text(
            "entries:\n  - svc_backup\n", encoding="utf-8")
        r = _rule(Path(d))
        check(r.evaluate(_event("svc_backup")) is False,
              "listed service account must be suppressed")
        check(r.evaluate(_event("alice")) is True,
              "human admin must still fire")
        # an event missing actor.user.name is not suppressed (fires)
        check(r.evaluate({"class_uid": 1002, "activity_id": 2}) is True,
              "missing actor.user.name must not be suppressed")

    # --- empty allowlist (shipped default): nothing suppressed, all fire ---
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "service_accounts.yml").write_text("entries: []\n", encoding="utf-8")
        r = _rule(Path(d))
        check(r.evaluate(_event("svc_backup")) is True,
              "empty allowlist -> no suppression -> fires (no silent behavior change)")

    # --- missing allowlist file: a broken/absent SUPPRESSION list must not
    #     silently disable detection -- the not_in never suppresses, so the rule
    #     keeps firing (the safe direction for a suppression allowlist) ---
    with tempfile.TemporaryDirectory() as d:
        r = _rule(Path(d))  # no service_accounts.yml present
        check(r.evaluate(_event("alice")) is True,
              "missing suppression allowlist must not disable detection (rule still fires)")


def main():
    run()
    if FAILS:
        print(f"[FAIL] rule tuning: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] v0.4 rule tuning (after-hours service-account allowlist) PASS")


if __name__ == "__main__":
    main()
