"""R3-#61 (2026-08-27): deque/Redis window-count parity on redelivery.

RedisWindowCounter's ZADD refreshes an already-present member's score (so a
member that keeps appearing stays in-window). DequeWindowCounter used to
SKIP an already-live member entirely, leaving its original (older) timestamp
in place -- so a member redelivered just inside the window still aged out at
the window boundary on the deque backend while the Redis backend kept it
alive. Fix: the deque backend also refreshes the member's timestamp on
redelivery.

Run: python services/shared/test_window.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(SERVICES))

from shared.window import DequeWindowCounter  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def test_redelivered_member_refreshes_timestamp():
    """A member already alive in the window counts once, but its timestamp is
    refreshed to the redelivery time -- parity with Redis ZADD updating the
    member's score."""
    c = DequeWindowCounter()
    # first 'a' at t=100
    check(c.hit("k", 100, 1000, member="a") == 1,
          "first hit of a new member must count it once")
    # redelivery of the already-live 'a' at t=200 -> still one entry, but its
    # timestamp is refreshed to 200
    check(c.hit("k", 200, 1000, member="a") == 1,
          "redelivering a live member must not double count")
    # observer at t=1200 (window 1000 -> horizon 200): a refreshed 'a'
    # (t=200) is still in-window, plus the new 'b' -> count 2. WITHOUT the
    # refresh, 'a' would sit at t=100 (evicted at horizon 200) -> count 1.
    check(c.hit("k", 1200, 1000, member="b") == 2,
          f"redelivered member must be refreshed so it survives the window "
          f"boundary, got {c.hit('k', 1200, 1000, member='b')}")

    # members() should also agree: both 'a' and 'b' alive at t=1200.
    check(sorted(c.members("k")) == ["a", "b"],
          f"members() must include the refreshed 'a' and 'b', got {sorted(c.members('k'))}")


def test_member_without_redelivery_ages_out_normally():
    """Sanity: without a refresh, an idle member still ages out at the window
    boundary -- the refresh only applies to an actual redelivery."""
    c = DequeWindowCounter()
    check(c.hit("k", 100, 1000, member="a") == 1, "hit once")
    # a new member at t=1200 (horizon 200): 'a' at t=100 was NOT refreshed,
    # so it is evicted -> only 'b' survives.
    check(c.hit("k", 1200, 1000, member="b") == 1,
          f"an un-refreshed member must age out at the window boundary, got "
          f"{c.hit('k', 1200, 1000, member='b')}")


def test_distinct_count_path_still_refreshes_value():
    """hit_distinct keeps one entry per distinct value; re-seeing a value
    must refresh its timestamp the same way (ZADD parity)."""
    c = DequeWindowCounter()
    check(c.hit_distinct("k", 100, 1000, value=443) == 1, "port 443 first seen")
    check(c.hit_distinct("k", 200, 1000, value=443) == 1, "port 443 re-seen stays 1 distinct")
    # observer at t=1200 (horizon 200): refreshed 443 (t=200) + new 80 -> 2
    check(c.hit_distinct("k", 1200, 1000, value=80) == 2,
          f"refreshed distinct value must survive the window boundary, got "
          f"{c.hit_distinct('k', 1200, 1000, value=80)}")


def _drive_sweep(c, t_ms, window_ms, prefix="noise"):
    """Send hits on OTHER keys until the counter's next sweep tick has run (the
    cadence is read from the module, never hard-coded)."""
    from shared import window as w
    for i in range(w._SWEEP_EVERY):
        c.hit(f"{prefix}-{i}", t_ms, window_ms, member=f"{prefix}-m{i}")


def test_sweep_evicts_each_key_by_its_own_window():
    """F1 (2026-10-02, adaptive-evasion lane): the idle-key sweep used the window of
    the hit that TRIGGERED it, so benign noise on a 60 s rule wiped the live state
    of every longer-window rule. Every key must be evicted by ITS OWN window only.
    Positive control: the 60 s noise keys ARE reclaimed. Negative control: a key
    idle for less than its own window survives."""
    t0 = 1_000_000
    # --- hit(): 300 s key, last hit 100 s before the sweep ----------------------
    c = DequeWindowCounter()
    c.hit("long", t0, 300_000, member="a")
    _drive_sweep(c, t0 + 100_000, 60_000)
    check("long" in c._w and "long" in c._last,
          "a 300 s key idle for 100 s must survive a sweep triggered by 60 s noise (F1)")
    check(c.hit("long", t0 + 100_001, 300_000, member="b") == 2,
          "the long-window count must still be 2 after the noise (state not swept)")
    check("noise-0" in c._w, "noise keys are not yet past their own 60 s window (still live)")
    # --- positive control: a key idle past ITS OWN window is reclaimed ----------
    c2 = DequeWindowCounter()
    c2.hit("short", t0, 60_000, member="a")
    _drive_sweep(c2, t0 + 100_000, 60_000)
    check("short" not in c2._w and "short" not in c2._last and "short" not in c2._live_members,
          "a 60 s key idle for 100 s must still be reclaimed by the sweep (memory bound)")
    # --- negative control: a long key idle past ITS window is also reclaimed ----
    c3 = DequeWindowCounter()
    c3.hit("long", t0, 300_000, member="a")
    _drive_sweep(c3, t0 + 400_000, 60_000)
    check("long" not in c3._w, "a 300 s key idle for 400 s is past its own window and must be reclaimed")
    # --- hit_distinct(): the same property --------------------------------------
    c4 = DequeWindowCounter()
    c4.hit_distinct("dlong", t0, 300_000, value="p1")
    _drive_sweep(c4, t0 + 100_000, 60_000)
    check(c4.hit_distinct("dlong", t0 + 100_001, 300_000, value="p2") == 2,
          "hit_distinct state of a 300 s key must survive 60 s noise (F1, distinct path)")
    c5 = DequeWindowCounter()
    c5.hit_distinct("dshort", t0, 60_000, value="p1")
    _drive_sweep(c5, t0 + 100_000, 60_000)
    check("dshort" not in c5._dw and "dshort" not in c5._last,
          "an idle 60 s distinct key is still reclaimed (memory bound)")


def test_sweep_per_key_window_is_the_latest_seen_for_that_key():
    """A key whose window changes between hits (rule reload) is judged by the window
    of its LAST hit, and the sidecar map never outlives the key."""
    t0 = 1_000_000
    c = DequeWindowCounter()
    c.hit("k", t0, 300_000, member="a")
    c.hit("k", t0 + 1, 10_000, member="b")        # reloaded with a shorter window
    _drive_sweep(c, t0 + 50_000, 60_000)
    check("k" not in c._w, "after the window shrank to 10 s the key is idle past it and is reclaimed")
    check("k" not in getattr(c, "_exp", {}), "the per-key deadline record must be dropped with the key")


# ---------------------------------------------------------------------------
# Adversarial-review findings (window-property group, 2026-10-06)
# ---------------------------------------------------------------------------

def test_stale_timestamp_never_shortens_a_keys_deadline():
    """Finding 1 (high): _touch overwrote the key's deadline with now+window even
    when `now` was OLDER than the key's newest hit, so ONE stale-timestamped event
    (past timestamps are always accepted upstream) made the next sweep forget every
    live hit of the key. The pre-F1 code had the same flaw with `_last` (F1 did not
    introduce it and did not close it). The deadline must follow the NEWEST hit."""
    T = 1_700_000_000_000
    c = DequeWindowCounter()
    for i in range(3):
        c.hit("G", T + i, 60_000, member=f"m{i}")
    c.hit("G", T - 3_600_000, 60_000, member="stale")       # one hit stamped 1 h ago
    check(c._exp["G"] == T + 2 + 60_000,
          f"deadline must stay at newest-hit + window, got {c._exp['G'] - T}")
    check(c._last["G"] == T + 2, "_last must stay the newest hit time")
    _drive_sweep(c, T + 1000, 60_000)                        # unrelated traffic -> sweep
    check("G" in c._w, "a live key must survive a sweep after one stale-timestamped hit")
    check(c.hit("G", T + 2000, 60_000, member="m3") == 4,
          "the three live hits (+ the new one) must still count; the stale one is outside the window")
    # negative control: the key IS still reclaimed once idle past its own window
    c2 = DequeWindowCounter()
    c2.hit("G", T, 60_000, member="a")
    c2.hit("G", T - 3_600_000, 60_000, member="stale")
    _drive_sweep(c2, T + 200_000, 60_000)
    check("G" not in c2._w and "G" not in c2._exp, "an idle key must still be reclaimed")
    # same property on the distinct path
    c3 = DequeWindowCounter()
    c3.hit_distinct("D", T, 60_000, value="p1")
    c3.hit_distinct("D", T - 3_600_000, 60_000, value="p0")
    _drive_sweep(c3, T + 1000, 60_000)
    check(c3.hit_distinct("D", T + 2000, 60_000, value="p2") == 2,
          "hit_distinct state (p1 + the new p2) must survive a sweep after a stale-timestamped hit")


def test_sweep_clock_is_the_triggers_own_time_not_a_watermark():
    """Finding 2 (medium) DECISION: the sweep is judged by the triggering hit's own
    (engine-clamped: min(event, wall)) event time, NOT by a monotone watermark. A
    watermark (max time seen) can only make the sweep MORE eager, so it cannot fix
    the finding's scenario (a key evicted while its source lags the rest of the
    traffic by more than its window -- which the Redis backend's wall-clock EXPIRE
    tolerates and the deque backend does not; documented on _sweep). What a lagging
    trigger must never do is evict state that is live relative to ITS OWN clock."""
    T = 1_700_000_000_000
    c = DequeWindowCounter()
    c.hit("B", T, 60_000, member="b1")
    c.hit("X", T + 1_000_000, 60_000, member="x1")          # the global max time races ahead
    _drive_sweep(c, T + 10, 60_000)                          # trigger clock lags the max
    check("B" in c._w,
          "a sweep triggered by a lagging clock must judge keys by THAT clock (no watermark)")
    check(c.hit("B", T + 20, 60_000, member="b2") == 2, "B's live hit must still count")


def test_redelivery_of_the_same_event_is_not_a_rebuild():
    """Finding 4 (low): the 'O(1) dedup' claim held for fresh members only -- every
    redelivery did an O(n) scan + full sort + deque rebuild (10 ms at 32k live
    members, so replaying a batch collapsed throughput). A redelivery stamped with
    the member's CURRENT timestamp changes nothing, so it must be O(1): the deque
    object is untouched."""
    T = 1_700_000_000_000
    c = DequeWindowCounter()
    for i in range(50):
        c.hit("g", T + i, 10 ** 9, member=f"id{i}")
    w = c._w["g"]
    snap = list(w)
    check(c.hit("g", T + 10, 10 ** 9, member="id10") == 50, "redelivery must not double count")
    check(c._w["g"] is w and list(w) == snap,
          "a same-timestamp redelivery must not rebuild or reorder the window (O(1) path)")
    # the refresh semantics of R3-#61 are unchanged for a DIFFERENT timestamp
    check(c.hit("g", T + 500, 10 ** 9, member="id10") == 50, "refresh keeps the count")
    check(c._live_members["g"]["id10"] == T + 500 and list(c._w["g"])[-1] == (T + 500, "id10"),
          "a redelivery at a new timestamp still refreshes the member (and the mirror)")


class _ScanCountingDict(dict):
    """Counts every way a caller could walk the whole key set."""
    scanned = 0

    def items(self):
        _ScanCountingDict.scanned += len(self)
        return super().items()

    def values(self):
        _ScanCountingDict.scanned += len(self)
        return super().values()

    def keys(self):
        _ScanCountingDict.scanned += len(self)
        return super().keys()

    def __iter__(self):
        _ScanCountingDict.scanned += len(self)
        return super().__iter__()


def test_sweep_is_not_a_full_scan_of_the_live_keys():
    """Finding 5 (low): the sweep was a full scan of every live key each 256 hits, so
    per-hit cost grew linearly with the live key count (233 us/hit at 400k keys,
    measured). It now pops a deadline min-heap, so sweeping a large LIVE key set walks
    none of it, while reclaim latency (<= _SWEEP_EVERY hits) and the resident bound
    (live + _SWEEP_EVERY) are exactly what they were."""
    from shared import window as w
    T = 1_700_000_000_000
    n = 4000
    c = DequeWindowCounter()
    c._exp = _ScanCountingDict()
    _ScanCountingDict.scanned = 0
    for i in range(n):                                       # n live keys, all in-window
        c.hit(f"k{i}", T + i, 10 ** 9, member=f"m{i}")
    for i in range(n):                                       # n more hits on live keys
        c.hit(f"k{i}", T + n + i, 10 ** 9, member=f"r{i}")
    check(_ScanCountingDict.scanned == 0,
          f"the sweep walked the live key set ({_ScanCountingDict.scanned} key visits over "
          f"{2 * n} hits); it must be heap-driven")
    check(len(c._w) == n, "no live key may be lost by the sweep")
    # resident bound: a spray of one-shot stale keys next to a live set stays within live + 256
    c2 = DequeWindowCounter()
    live = 1000
    for i in range(live):
        c2.hit(f"live{i}", T, 10 ** 12, member=f"l{i}")
    worst = 0
    for i in range(20_000):
        c2.hit(f"spray{i}", T + i * 1_000_000, 60_000, member=f"s{i}")
        worst = max(worst, len(c2._exp))
    check(worst <= live + w._SWEEP_EVERY + 2,
          f"resident keys peaked at {worst}; bound is live({live}) + {w._SWEEP_EVERY}")
    check(sum(1 for k in c2._exp if k.startswith("live")) == live, "live keys survive the spray")
    # an in-window key whose heap entry went outdated (it was hit again) is rescheduled, not lost
    c3 = DequeWindowCounter()
    c3.hit("hot", T, 60_000, member="a")
    for i in range(3):                                       # window passes its first deadline 3x
        t = T + 50_000 * (i + 1)
        c3.hit("hot", t, 60_000, member=f"h{i}")
        _drive_sweep(c3, t, 60_000, prefix=f"n{i}")
    check("hot" in c3._w and c3.hit("hot", T + 150_001, 60_000, member="z") >= 2,
          "a hot key hit inside its window must survive every sweep (rescheduled, not forgotten)")


def test_nonpositive_window_reclaims_inline():
    """Finding 6 (low): the 'if not w:' branches were called dead code. They ARE
    reachable, only with window_ms < 0 (which the counter API does not reject):
    hit_distinct() empties its deque, and hit() empties it when a redelivery
    refreshes the key's only live member to a time behind the (negative) horizon.
    They must keep dropping every per-key record (no empty deque, no orphan
    _exp/_last, no mirror entry)."""
    c = DequeWindowCounter()
    check(c.hit_distinct("d", 100, -1, value="a") == 0, "negative window holds nothing (distinct)")
    check("d" not in c._dw and "d" not in c._last and "d" not in c._exp,
          "an emptied distinct key must be dropped inline (no orphan sidecar records)")
    c.hit("k", 1000, 60_000, member="a")
    check(c.hit("k", 100, -1, member="a") == 0, "the refreshed member is outside the negative window")
    check("k" not in c._w and "k" not in c._live_members and "k" not in c._last and "k" not in c._exp,
          "an emptied hit() key must be dropped inline from every map")
    # the member mirror must not keep a member that the SAME call evicted
    c.hit("m", 1000, 60_000, member="a")
    c.hit("m", 100, -500, member="z")
    check("z" not in c._live_members.get("m", {}), "a member evicted in the same call is not live")


class _Model:
    """Trivial reference for hit / hit_distinct / hit_periodic: per-key entry lists,
    eviction by the CURRENT call's own window, no sweeping, no sidecar maps."""

    def __init__(self):
        self.h: dict = {}       # key -> [[ts, member]]   (hit / hit_periodic)
        self.d: dict = {}       # key -> [(ts, value)]    (hit_distinct)
        self.newest: dict = {}  # key -> max ts ever seen

    @staticmethod
    def _evict(ents, horizon):
        return [e for e in ents if e[0] >= horizon]

    def hit(self, key, now, window, member):
        ents = self._evict(self.h.get(key, []), now - window)
        for e in ents:
            if member is not None and e[1] == member:
                e[0] = now
                break
        else:
            ents.append([now, member])
        ents = self._evict(ents, now - window)
        self.h[key] = ents
        self.newest[key] = max(self.newest.get(key, now), now)
        return len(ents)

    def periodic(self, key, now, window, member):
        from shared.window import _coefficient_of_variation
        n = self.hit(key, now, window, member)
        return n, _coefficient_of_variation(sorted(t for t, _ in self.h[key]))

    def distinct(self, key, now, window, value):
        ents = self._evict(self.d.get(key, []) + [(now, value)], now - window)
        self.d[key] = ents
        self.newest[key] = max(self.newest.get(key, now), now)
        return len({v for _, v in ents})


def _property_run(seed, mode):
    """Random hit / hit_distinct / hit_periodic interleavings over several keys and
    windows (fixed per key) with equal / backwards / jumping timestamps, against
    the reference model, with a tiny sweep cadence so sweeps fire constantly.
    mode 'mono'  : non-decreasing time (incl. equal)  -> exact equality WITH sweeps.
    mode 'back'  : equal/backwards/jumping time        -> exact equality, sweeps off.
    mode 'stale' : same, sweeps ON                     -> a key may vanish only once its
                   deadline (newest hit + window) is behind the TRIGGERING hit's clock,
                   and a tracked key's deadline is always newest hit + window."""
    import random
    from shared import window as w
    rng = random.Random(seed)
    saved = w._SWEEP_EVERY
    w._SWEEP_EVERY = 10 ** 9 if mode == "back" else 8
    try:
        wins = {"h0": 60_000, "h1": 300_000, "h2": 600_000, "d0": 60_000, "d1": 300_000,
                "p0": 60_000, "p1": 3_600_000}
        keys = list(wins)
        c, m, T = DequeWindowCounter(), _Model(), 1_700_000_000_000
        t = T
        for step in range(500):
            key = rng.choice(keys)
            win = wins[key]
            if mode == "mono":
                t += rng.choice((0, 0, 1, 500, 5_000, 40_000, 700_000))
                ts = t
            else:
                ts = T + rng.choice((rng.randrange(0, 4_000_000), t - T, rng.randrange(0, 3000)))
                t = max(t, ts)
            member = rng.choice((None, f"m{rng.randrange(40)}", f"m{rng.randrange(40)}"))
            before = set(c._exp)
            if key[0] == "d":
                val = rng.randrange(6)
                got = c.hit_distinct(key, ts, win, val, member)
                want = m.distinct(key, ts, win, val)
            elif key[0] == "p":
                got = c.hit_periodic(key, ts, win, member)
                want = m.periodic(key, ts, win, member)
            else:
                got = c.hit(key, ts, win, member)
                want = m.hit(key, ts, win, member)
            if mode != "stale" and got != want:
                return f"seed {seed} {mode} step {step} {key} ts={ts - T}: got {got} want {want}"
            if mode == "stale":
                for k in before - set(c._exp):
                    if k != key and not m.newest[k] + wins[k] < ts:
                        return (f"seed {seed} stale step {step}: live key {k} (deadline "
                                f"{m.newest[k] + wins[k] - T}) swept by a hit at {ts - T}")
                    m.newest.pop(k, None)   # a forgotten key starts over
                for k, dl in c._exp.items():
                    if dl != m.newest[k] + wins[k]:
                        return (f"seed {seed} stale step {step}: {k} deadline {dl - T} != "
                                f"newest+window {m.newest[k] + wins[k] - T}")
            for k, mirror in c._live_members.items():
                have = {mm: tt for tt, mm in c._w.get(k, ()) if mm is not None}
                if mirror != have:
                    return f"seed {seed} {mode} step {step}: _live_members[{k}] drifted from the deque"
            if set(c._w) | set(c._dw) != set(c._exp) or set(c._exp) != set(c._last):
                return f"seed {seed} {mode} step {step}: sidecar maps out of sync"
            first = {}
            for d, k in c._heap:
                first[k] = min(d, first.get(k, d))
            for k, dl in c._exp.items():
                if first.get(k, dl + 1) > dl:
                    return f"seed {seed} {mode} step {step}: {k} has no sweep-heap entry <= its deadline"
        return None
    finally:
        w._SWEEP_EVERY = saved


def test_property_against_reference_model():
    """Permanent regression guard (seeded, deterministic): the deque backend equals a
    trivial reference model under random interleavings, and the sweep never forgets
    a live key (finding 1) nor leaves the sidecar maps inconsistent."""
    for mode in ("mono", "back", "stale"):
        for seed in range(25):
            err = _property_run(seed, mode)
            if err:
                check(False, "property: " + err)
                break


def main():
    test_redelivered_member_refreshes_timestamp()
    test_member_without_redelivery_ages_out_normally()
    test_distinct_count_path_still_refreshes_value()
    test_sweep_evicts_each_key_by_its_own_window()
    test_sweep_per_key_window_is_the_latest_seen_for_that_key()
    test_stale_timestamp_never_shortens_a_keys_deadline()
    test_sweep_clock_is_the_triggers_own_time_not_a_watermark()
    test_redelivery_of_the_same_event_is_not_a_rebuild()
    test_sweep_is_not_a_full_scan_of_the_live_keys()
    test_nonpositive_window_reclaims_inline()
    test_property_against_reference_model()

    if FAILS:
        print(f"[FAIL] window parity: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] R3-#61: deque window counter refreshes a redelivered member's "
          "timestamp (parity with Redis ZADD); idle members still age out")


if __name__ == "__main__":
    main()
