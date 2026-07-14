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
"""
from __future__ import annotations

from collections import defaultdict, deque


# How often (in hits) the deque backend sweeps idle group keys. A group that
# stops producing events is never re-trimmed on its own (we only touch a key on
# a hit for THAT key), so without a sweep its entry -- and the dict key itself --
# would live forever. On an internet-facing sensor grouping by src_endpoint.ip
# that is effectively unbounded and an attacker can force OOM by spraying random
# source IPs/usernames. The Redis backend self-cleans via EXPIRE; this sweep is
# the deque equivalent. Amortized O(1): a full scan every _SWEEP_EVERY hits.
_SWEEP_EVERY = 256


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
            self._last.pop(k, None)

    def hit(self, key: str, now_ms: int, window_ms: int, member=None) -> int:
        w = self._w[key]
        horizon = now_ms - window_ms
        while w and w[0][0] < horizon:
            w.popleft()
        # Redelivery guard: a member already alive in the window counts once.
        if member is not None and any(m == member for _, m in w):
            count = len(w)
        else:
            w.append((now_ms, member))
            count = len(w)
        self._last[key] = now_ms
        if not w:
            self._w.pop(key, None)
            self._last.pop(key, None)
        self._sweep(now_ms, window_ms)
        return count

    def hit_distinct(self, key: str, now_ms: int, window_ms: int,
                     value=None, member=None) -> int:
        """Distinct-count of ``value`` within the window after recording it."""
        w = self._dw[key]
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
