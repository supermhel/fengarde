"""v0.3 (A3) time-of-day predicate tests: `outside_hours`.

Adversarial like test_v03_rule_grammar.py: the operator runs on untrusted
contributor rules, so every malformed-spec case must FAIL CLOSED (selection
doesn't match) rather than raise past evaluate(). Correctness cases pin the
weekday/minute math to real calendar dates via datetime, not hand-derived
epoch numbers. Ends by driving the shipped common_after_hours_admin.yml rule
through the REAL windows_eventlog parser.

Run: C:/Python313/python.exe services/ws4-detection/test_v03_time_predicate.py
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "services"))
sys.path.insert(0, str(ROOT / "services" / "ws2-normalization"))

from engine import Rule, load_rules, _time_outside_hours  # noqa: E402
from parsers.windows_eventlog import WindowsEventLogParser  # noqa: E402

RULES_DIR = ROOT / "contracts" / "rules"
AFTER_HOURS_ID = "9b5f2d18-3c7a-4e61-8f24-5a1d7c3e9b06"
FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def ms(year, month, day, hour, minute) -> int:
    return int(datetime(year, month, day, hour, minute,
                        tzinfo=timezone.utc).timestamp() * 1000)


BUSINESS = {"start": "08:00", "end": "18:00"}  # days default Mon-Fri, tz 0

# Calendar anchors (verified by datetime itself): 2026-07-07 is a Tuesday,
# 2026-07-11 a Saturday, 2026-07-12 a Sunday.
TUE_03 = ms(2026, 7, 7, 3, 0)
TUE_12 = ms(2026, 7, 7, 12, 0)
TUE_0800 = ms(2026, 7, 7, 8, 0)
TUE_1759 = ms(2026, 7, 7, 17, 59)
TUE_1800 = ms(2026, 7, 7, 18, 0)
SAT_12 = ms(2026, 7, 11, 12, 0)
SUN_03 = ms(2026, 7, 12, 3, 0)


def run():
    assert datetime(2026, 7, 7, tzinfo=timezone.utc).weekday() == 1  # Tuesday
    assert datetime(2026, 7, 11, tzinfo=timezone.utc).weekday() == 5  # Saturday

    # --- correctness: weekday business hours ---
    check(_time_outside_hours(BUSINESS, TUE_03) is True, "Tue 03:00 is outside 08-18")
    check(_time_outside_hours(BUSINESS, TUE_12) is False, "Tue 12:00 is within 08-18")
    check(_time_outside_hours(BUSINESS, SAT_12) is True, "Sat 12:00 is outside Mon-Fri")
    check(_time_outside_hours(BUSINESS, SUN_03) is True, "Sun 03:00 is outside")
    # boundaries: start inclusive, end exclusive
    check(_time_outside_hours(BUSINESS, TUE_0800) is False, "08:00 exactly is within")
    check(_time_outside_hours(BUSINESS, TUE_1759) is False, "17:59 is within")
    check(_time_outside_hours(BUSINESS, TUE_1800) is True, "18:00 exactly is outside")

    # --- tz offset: 03:00 UTC == 12:00 UTC+9 -> within local business hours ---
    jst = dict(BUSINESS, tz_offset_minutes=540)
    check(_time_outside_hours(jst, TUE_03) is False, "Tue 03:00Z is 12:00 JST, within")
    # offset can also flip the weekday: Sun 23:00 UTC+2h = Mon 01:00, still outside
    # hours but exercises the day rollover
    sun_23 = ms(2026, 7, 12, 23, 0)
    plus2 = dict(BUSINESS, tz_offset_minutes=120)
    check(_time_outside_hours(plus2, sun_23) is True, "Mon 01:00 local is outside 08-18")
    mon_07z = ms(2026, 7, 13, 7, 0)  # Monday 07:00Z = Monday 09:00 UTC+2 -> within
    check(_time_outside_hours(plus2, mon_07z) is False, "Mon 09:00 local is within")

    # --- overnight window (start > end wraps midnight) ---
    night = {"start": "22:00", "end": "06:00", "days": ["mon", "tue", "wed", "thu", "fri"]}
    tue_23 = ms(2026, 7, 7, 23, 0)
    check(_time_outside_hours(night, tue_23) is False, "Tue 23:00 within 22-06 overnight")
    check(_time_outside_hours(night, TUE_03) is False, "Tue 03:00 within 22-06 overnight")
    check(_time_outside_hours(night, TUE_12) is True, "Tue 12:00 outside 22-06 overnight")

    # --- custom days list ---
    weekend_only = dict(BUSINESS, days=["sat", "sun"])
    check(_time_outside_hours(weekend_only, SAT_12) is False, "Sat 12:00 within sat/sun hours")
    check(_time_outside_hours(weekend_only, TUE_12) is True, "Tue outside sat/sun days")

    # --- pre-1970 timestamps must not raise, and weekday math still floors ---
    neg = ms(1969, 12, 28, 12, 0)  # Sunday before epoch
    check(_time_outside_hours(BUSINESS, neg) is True, "pre-epoch Sunday is outside")

    # --- fail closed: malformed specs (each returns False, never raises) ---
    bad_specs = [
        None, "08:00-18:00", 42, {}, [],
        {"start": "08:00"},                                  # missing end
        {"start": "8:00", "end": "18:00"},                   # not HH:MM
        {"start": "25:00", "end": "18:00"},                  # bad hour
        {"start": "08:60", "end": "18:00"},                  # bad minute
        {"start": "aa:bb", "end": "18:00"},
        {"start": 800, "end": 1800},                         # non-string
        {"start": "08:00", "end": "08:00"},                  # empty window
        dict(BUSINESS, tz_offset_minutes="60"),              # non-int tz
        dict(BUSINESS, tz_offset_minutes=True),              # bool tz
        dict(BUSINESS, tz_offset_minutes=100000),            # absurd tz
        dict(BUSINESS, days="mon"),                          # days not a list
        dict(BUSINESS, days=[]),                             # empty days
        dict(BUSINESS, days=["mon", "funday"]),              # unknown day
        dict(BUSINESS, days=[1, 2]),                         # non-string days
        dict(BUSINESS, typo_key=1),                          # unknown key
    ]
    for spec in bad_specs:
        check(_time_outside_hours(spec, TUE_03) is False,
              f"malformed spec {spec!r} must fail closed")

    # --- fail closed: bad event time ---
    for t in (None, "yesterday", True, [], {}):
        check(_time_outside_hours(BUSINESS, t) is False,
              f"non-numeric event time {t!r} must fail closed")

    # --- through Rule.evaluate: never raises, matches as expected ---
    r = Rule({"id": "t", "title": "t", "level": "high",
              "detection": {"sel": {"time": {"outside_hours": dict(BUSINESS)}},
                            "condition": "sel"},
              "siem": {"score_weight": 10}})
    check(r.evaluate({"time": SUN_03}) is True, "Rule: Sun 03:00 fires")
    check(r.evaluate({"time": TUE_12}) is False, "Rule: Tue 12:00 does not fire")
    check(r.evaluate({}) is False, "Rule: missing time fails closed")
    check(r.evaluate({"time": "corrupt"}) is False, "Rule: corrupt time fails closed")

    # --- the shipped rule, driven through the REAL windows parser ---
    rules = load_rules(RULES_DIR)
    after = next(x for x in rules if x.id == AFTER_HOURS_ID)
    win = WindowsEventLogParser()

    def win_event(t_ms):
        return win.parse({"raw": {"EventID": 4672, "SubjectUserName": "admin",
                                  "Computer": "dc01", "TimeCreated": t_ms},
                          "meta": {"ingest_id": f"i{t_ms}"}})

    ev_night = win_event(SUN_03)
    check(ev_night is not None and ev_night["class_uid"] == 1002
          and ev_night["activity_id"] == 2,
          "REAL windows parser must emit class 1002 activity 2 for 4672")
    check(after.evaluate(ev_night) is True,
          "after-hours rule MUST fire on a real 4672 at Sun 03:00 UTC")
    check(after.evaluate(win_event(TUE_12)) is False,
          "after-hours rule must NOT fire on a real 4672 at Tue 12:00 UTC")

    # class matches but activity doesn't (4688 process launch, activity 1)
    ev_proc = win.parse({"raw": {"EventID": 4688, "SubjectUserName": "admin",
                                 "Computer": "dc01", "TimeCreated": SUN_03,
                                 "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                                 "NewProcessId": "0x1f4"}, "meta": {}})
    check(ev_proc is not None and after.evaluate(ev_proc) is False,
          "after-hours rule must NOT fire on 4688 (activity 1) even off-hours")

    if FAILS:
        print(f"[FAIL] {len(FAILS)} time-predicate check(s) failed:")
        for f in FAILS:
            print(f"  - {f}")
        return 1
    print("[OK] v0.3 time predicate: correctness, tz/overnight/day edges, "
          "fail-closed adversarial specs, real-parser after-hours firing")
    return 0


if __name__ == "__main__":
    sys.exit(run())
