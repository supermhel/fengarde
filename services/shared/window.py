"""Sliding-window counters for WS-4 stateful rules (T6).

A stateful rule fires when the count of matching events for a group reaches
``threshold`` within ``window_seconds``. WHERE that count lives matters:

- **Single process / tests** -> ``DequeWindowCounter``: an in-process deque per
  group. Correct and zero-dependency for one replica.
- **Multiple replicas on Redis** -> ``RedisWindowCounter``: the count lives in a
  Redis sorted set so EVERY replica sees the SAME global count. With a local deque,
  two replicas each see half the events and neither reaches the threshold — the
  brute-force alert would never fire under horizontal scaling. (This was the T6
  finding from the Opus review.)

Both expose the same methods::

    hit(key, now_ms, window_ms, member) -> int
        # COUNT of events in [now-window, now] after add (brute-force, mass-delete)

    hit_distinct(key, now_ms, window_ms, value, member) -> int
        # DISTINCT-COUNT of `value` seen in [now-window, now] after add
        # (port scan = distinct dst ports; lateral movement = distinct dst hosts)

    hit_periodic(key, now_ms, window_ms, member) -> tuple[int, float | None]
        # (COUNT, coefficient-of-variation of inter-arrival deltas) after add.
        # v0.5 A3: periodicity/beaconing primitive -- see its design note below.

The engine calls one of them and compares the returned count to the rule's threshold.

Distinct-count design
---------------------
A plain COUNT can't express "one IP touched many *different* ports": 30 connections
to a single port must NOT trip a port-scan rule, but 15 connections to 15 different
ports must. So distinct-count keys the window on the *field value* (port / host),
not on the event, and reports how many distinct values are alive in the window.

The two backends stay consistent the same way the COUNT pair does:

- ``DequeWindowCounter`` keeps ``(now_ms, value)`` tuples per group; after trimming
  by the horizon it returns ``len({value for _, value in window})``. Re-seeing a
  value just appends a fresher tuple, so an actively-recurring value never ages out
  while it keeps appearing.
- ``RedisWindowCounter`` stores the *value itself* as the sorted-set member, scored
  by time. ZADD on an already-present value updates its score (refreshes its
  recency) instead of adding a row, so the set naturally holds one entry per distinct
  value; ZREMRANGEBYSCORE ages values out and ZCARD is the distinct count. This is
  exactly the COUNT path with member := value, which is why both backends agree.

Periodicity design (v0.5 A3, docs/superpowers/specs/2026-07-21-periodicity-
primitive.md has the full rationale)
-----------------------------------
A C2 beacon calls home at a roughly REGULAR interval; a plain COUNT can't tell
a beacon apart from a burst of unrelated traffic to the same group. Both
backends already keep the exact timestamps a plain ``hit()`` needs to trim the
window -- ``hit_periodic()`` reuses that same window state (no new storage)
and additionally reports the coefficient of variation (stdev / mean) of the
CONSECUTIVE inter-arrival deltas among the events currently in-window. Low CV
= evenly spaced = beacon-shaped. ``None`` when fewer than 3 events are in the
window (need 2 deltas for a variance to mean anything) -- the caller must
treat ``None`` as "can't judge yet", never as "passes/fails" on its own.

This is deliberately a COARSE proxy, not a robust beacon detector: it is
trivially evaded by an attacker adding random jitter to their callback
interval (documented, not silently overpromised -- see the design doc). It is
bounded-memory and backend-symmetric (same underlying window, same member-
dedup as ``hit()``), which was the actual design goal: don't add new
storage or new redelivery-dedup semantics on top of what already works.
"""
from __future__ import annotations

import math

from collections import defaultdict, deque


# How often (in hits) the deque backend sweeps idle group keys. A group that
# stops producing events is never re-trimmed on its own (we only touch a key on
# a hit for THAT key), so without a sweep its entry -- and the dict key itself --
# would live forever. On an internet-facing sensor grouping by src_endpoint.ip
# that is effectively unbounded and an attacker can force OOM by spraying random
# source IPs/usernames. The Redis backend self-cleans via EXPIRE; this sweep is
# the deque equivalent. Amortized O(1): a full scan every _SWEEP_EVERY hits.
_SWEEP_EVERY = 256


def _coefficient_of_variation(sorted_times: list) -> float | None:
    """stdev/mean of consecutive deltas in a sorted list of timestamps (ms), or
    None if there are fewer than 2 deltas (need >=3 timestamps) -- with only
    0 or 1 deltas a "variance" is either undefined or trivially zero, neither
    of which says anything real about regularity. None if the mean delta is
    not positive (degenerate/duplicate timestamps -- no rate to speak of)."""
    if len(sorted_times) < 3:
        return None
    deltas = [b - a for a, b in zip(sorted_times, sorted_times[1:])]
    mean = sum(deltas) / len(deltas)
    if mean <= 0:
        return None
    variance = sum((d - mean) ** 2 for d in deltas) / len(deltas)
    return math.sqrt(variance) / mean


class DequeWindowCounter:
    """In-process sliding window (default; correct for a single replica).

    Two robustness properties the naive version lacked (both fixed here so the
    deque backend matches ``RedisWindowCounter`` semantics):

    - **Member dedup.** ``hit`` records ``(now_ms, member)`` and ignores a repeat
      of a ``member`` already alive in the window. Under at-least-once redelivery
      the same event (same OCSF ``ingest_id``) must count ONCE; the old version
      appended blindly, so a redelivered event double-counted on memory but not on
      Redis (ZADD dedups by member) -- the two backends disagreed and thresholds
      tripped with fewer real events on the backend the test-gate uses.
    - **Key eviction.** Empty group deques are dropped inline and idle keys are
      swept periodically, so the key set stays bounded (see ``_SWEEP_EVERY``).
    """

    def __init__(self) -> None:
        self._w: dict[str, deque] = defaultdict(deque)
        self._dw: dict[str, deque] = defaultdict(deque)
        # P1-5 (2026-07-21 audit): mirrors _w's non-None members for O(1)
        # dedup lookup. Live-proven finding: `any(m == member for _, m in w)`
        # was an O(window-size) scan on EVERY hit, making a single-source
        # burst -- the exact traffic common_bruteforce.yml targets -- O(n^2)
        # over the burst (e.g. ~60k comparisons/event at 1k EPS into a 60s
        # window), collapsing detection throughput under real attack load.
        # Invariant this set relies on: because hit() already skips
        # re-appending an already-live member, a given non-None member value
        # appears in `_w[key]` AT MOST ONCE at any time -- so popping an
        # entry's member out of this set on eviction is always safe (it
        # cannot still be "live" via a second deque entry).
        self._live_members: dict[str, set] = defaultdict(set)
        self._last: dict[str, int] = {}   # key -> most-recent now_ms (for sweeping)
        self._hits = 0

    def _sweep(self, now_ms: int, window_ms: int) -> None:
        """Drop keys whose newest event is older than the window (idle groups)."""
        self._hits += 1
        if self._hits % _SWEEP_EVERY:
            return
        horizon = now_ms - window_ms
        stale = [k for k, ts in self._last.items() if ts < horizon]
        for k in stale:
            self._w.pop(k, None)
            self._dw.pop(k, None)
            self._live_members.pop(k, None)
            self._last.pop(k, None)

    def hit(self, key: str, now_ms: int, window_ms: int, member=None) -> int:
        w = self._w[key]
        members = self._live_members[key]
        horizon = now_ms - window_ms
        # C1 (2026-07-29 audit): front-only eviction assumed `now_ms` is
        # non-decreasing per key, which the bus does NOT guarantee (replay,
        # clock skew, or Redis consumer-group round-robin across batches can
        # deliver events out of order for the same group). A late-arriving
        # event wedged behind a not-yet-expired later one used to stay
        # counted forever, inflating the window. Fix keeps the deque
        # time-sorted: the common case (in-order arrival, the vast majority
        # of traffic) still appends at the back in O(1); only a genuine
        # out-of-order arrival pays an O(n log n) re-sort, so the P1-5
        # near-linear-burst guarantee for well-ordered traffic is preserved.
        while w and w[0][0] < horizon:
            _, evicted_member = w.popleft()
            if evicted_member is not None:
                members.discard(evicted_member)
        # Redelivery guard: a member already alive in the window counts once,
        # but its timestamp is REFRESHED to now_ms (R3-#61, 2026-08-27) --
        # parity with RedisWindowCounter, where ZADD on an already-present
        # member updates its score. Without the refresh, a member that keeps
        # being redelivered just inside the window would still age out at the
        # window boundary on the deque backend while the Redis backend kept
        # it alive -- the two backends disagreed on when a recurring value
        # expires.
        if member is not None and member in members:
            for i, (_t, _m) in enumerate(w):
                if _m == member:
                    w[i] = (now_ms, member)
                    break
            # keep the deque time-sorted (C1): the refreshed entry may no
            # longer be at its old position relative to its neighbours.
            items = list(w)
            items.sort(key=lambda e: e[0])
            w = deque(items)
            self._w[key] = w
            while w and w[0][0] < horizon:
                _, evicted_member = w.popleft()
                if evicted_member is not None:
                    members.discard(evicted_member)
            count = len(w)
        else:
            if w and now_ms < w[-1][0]:
                items = list(w)
                items.append((now_ms, member))
                items.sort(key=lambda e: e[0])
                w = deque(items)
                self._w[key] = w
                # Sorting may have surfaced a newly-stale entry at the front
                # (the out-of-order insert could sit anywhere) -- re-evict.
                while w and w[0][0] < horizon:
                    _, evicted_member = w.popleft()
                    if evicted_member is not None:
                        members.discard(evicted_member)
            else:
                w.append((now_ms, member))
            if member is not None:
                members.add(member)
            count = len(w)
        self._last[key] = now_ms
        if not w:
            self._w.pop(key, None)
            self._live_members.pop(key, None)
            self._last.pop(key, None)
        self._sweep(now_ms, window_ms)
        return count

    def hit_distinct(self, key: str, now_ms: int, window_ms: int,
                     value=None, member=None) -> int:
        """Distinct-count of ``value`` within the window after recording it."""
        w = self._dw[key]
        # C1 fix: keep the deque time-sorted on insert (see hit() comment) so
        # front-only eviction below stays correct under out-of-order arrival.
        if w and now_ms < w[-1][0]:
            items = list(w)
            items.append((now_ms, value))
            items.sort(key=lambda e: e[0])
            w = deque(items)
            self._dw[key] = w
        else:
            w.append((now_ms, value))
        horizon = now_ms - window_ms
        while w and w[0][0] < horizon:
            w.popleft()
        count = len({v for _, v in w})
        self._last[key] = now_ms
        if not w:
            self._dw.pop(key, None)
            self._last.pop(key, None)
        self._sweep(now_ms, window_ms)
        return count

    def hit_periodic(self, key: str, now_ms: int, window_ms: int, member=None):
        """(count, cv) -- reuses the exact same window `hit()` maintains (same
        member-dedup, same trim), just also reports inter-arrival regularity."""
        count = self.hit(key, now_ms, window_ms, member)
        times = sorted(t for t, _ in self._w.get(key, ()))
        return count, _coefficient_of_variation(times)

    def members(self, key: str) -> list:
        """Design-A (2026-07-29 audit): the ingest_ids currently in-window for
        a `hit()`/`hit_periodic()` key, read-only -- the same state those
        calls already maintain, exposed so a fired stateful alert can record
        WHICH events contributed instead of only a count. Oldest-first;
        ``None`` members (an event with no ingest_id) are omitted."""
        return [m for _, m in self._w.get(key, ()) if m is not None]

    def distinct_members(self, key: str) -> list:
        """Same idea as ``members()`` but for a `hit_distinct()` key, where
        the tracked member IS the distinct field value (e.g. the distinct
        dst ports of a port-scan window), not an event id."""
        seen: list = []
        for _, v in self._dw.get(key, ()):
            if v is not None and v not in seen:
                seen.append(v)
        return seen


class RedisWindowCounter:
    """Global sliding window in a Redis sorted set per (rule, group).

    Atomic per call via a pipeline:
      ZADD  key {member: now}            -- record this event (member must be unique)
      ZREMRANGEBYSCORE key 0 horizon-1   -- drop events older than the window
      ZCARD key                          -- the global count in-window
      EXPIRE key window_s+1              -- quiet groups self-delete (no leak)

    ``member`` MUST be unique per event (use the OCSF ingest_id); otherwise ZADD
    would overwrite and undercount. Falls back to the timestamp if none given.
    """

    def __init__(self, client, namespace: str = "ws4:win") -> None:
        self.r = client
        self.ns = namespace

    def hit(self, key: str, now_ms: int, window_ms: int, member=None) -> int:
        zkey = f"{self.ns}:{key}"
        m = str(member) if member is not None else str(now_ms)
        horizon = now_ms - window_ms
        pipe = self.r.pipeline()
        pipe.zadd(zkey, {m: now_ms})
        pipe.zremrangebyscore(zkey, 0, horizon - 1)
        pipe.zcard(zkey)
        pipe.expire(zkey, max(1, window_ms // 1000 + 1))
        res = pipe.execute()
        return int(res[2])  # ZCARD result

    def hit_distinct(self, key: str, now_ms: int, window_ms: int,
                     value=None, member=None) -> int:
        """Distinct-count of ``value`` in-window (global, across replicas).

        The sorted-set member is the *value* itself, so re-seeing the same value
        only refreshes its score (ZADD updates), keeping one entry per distinct
        value. ZCARD is then the distinct count. ``member`` is ignored on purpose:
        deduplication here is by value, not by event id.
        """
        zkey = f"{self.ns}:d:{key}"
        m = str(value) if value is not None else str(now_ms)
        horizon = now_ms - window_ms
        pipe = self.r.pipeline()
        pipe.zadd(zkey, {m: now_ms})
        pipe.zremrangebyscore(zkey, 0, horizon - 1)
        pipe.zcard(zkey)
        pipe.expire(zkey, max(1, window_ms // 1000 + 1))
        res = pipe.execute()
        return int(res[2])

    def hit_periodic(self, key: str, now_ms: int, window_ms: int, member=None):
        """(count, cv) -- same ZADD/trim/EXPIRE as `hit()` (identical member-
        dedup and window state), plus one extra ZRANGE to read back the
        in-window timestamps for the coefficient-of-variation calculation."""
        zkey = f"{self.ns}:{key}"
        count = self.hit(key, now_ms, window_ms, member)
        times = sorted(int(score) for _, score in self.r.zrange(zkey, 0, -1, withscores=True))
        return count, _coefficient_of_variation(times)

    def members(self, key: str) -> list:
        """Design-A (2026-07-29 audit): see DequeWindowCounter.members -- the
        Redis mirror of the same read, oldest-first by score (insertion
        time)."""
        return list(self.r.zrange(f"{self.ns}:{key}", 0, -1))

    def distinct_members(self, key: str) -> list:
        """Same idea as ``members()`` but for a `hit_distinct()` key."""
        return list(self.r.zrange(f"{self.ns}:d:{key}", 0, -1))
