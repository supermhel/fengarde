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
  by time. ``ZADD ... GT`` on an already-present value RAISES its score (refreshes
  its recency) but never lowers it, instead of adding a row, so the set holds one
  entry per distinct value, scored by the NEWEST time it was seen -- exactly what the
  deque's "fresher tuple wins" gives. ZREMRANGEBYSCORE ages values out and ZCARD is
  the distinct count. (A plain ZADD let a repeat stamped in the PAST drag a live
  value's score backwards so it aged out at once -- see ``hit_distinct``.) GT needs
  Redis >= 6.2 (the stack runs redis:7) and redis-py >= 3.5.

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

import heapq
import math

from collections import defaultdict, deque


# How often (in hits) the deque backend sweeps idle group keys. A group that
# stops producing events is never re-trimmed on its own (we only touch a key on
# a hit for THAT key), so without a sweep its entry -- and the dict key itself --
# would live forever. On an internet-facing sensor grouping by src_endpoint.ip
# that is effectively unbounded and an attacker can force OOM by spraying random
# source IPs/usernames. The Redis backend self-cleans via EXPIRE; this sweep is
# the deque equivalent. Runs every _SWEEP_EVERY hits over a deadline min-heap, so
# it touches only keys whose recorded deadline passed (see DequeWindowCounter._sweep).
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
    - **Key eviction.** Idle keys are swept periodically, so the key set stays
      bounded (see ``_SWEEP_EVERY`` and ``_sweep``); a deque emptied by a call is also
      dropped inline (only reachable with a non-positive ``window_ms``).
    """

    def __init__(self) -> None:
        self._w: dict[str, deque] = defaultdict(deque)
        self._dw: dict[str, deque] = defaultdict(deque)
        # P1-5 (2026-07-21 audit): mirrors _w's non-None members -> their CURRENT
        # timestamp, for O(1) dedup lookup. Live-proven finding: `any(m == member
        # for _, m in w)` was an O(window-size) scan on EVERY hit, making a
        # single-source burst -- the exact traffic common_bruteforce.yml targets --
        # O(n^2) over the burst (e.g. ~60k comparisons/event at 1k EPS into a 60s
        # window), collapsing detection throughput under real attack load.
        # Cost model (the honest scope of the "O(1)" claim, review finding 4): a
        # FRESH member and a redelivery stamped with the member's current timestamp
        # are O(1) (the stored timestamp is what lets the latter skip the work);
        # only a redelivery at a DIFFERENT timestamp (the R3-#61 refresh) still pays
        # an O(n) scan + re-sort, because the deque has to move that entry.
        # Invariant this relies on: because hit() already skips re-appending an
        # already-live member, a given non-None member value appears in `_w[key]` AT
        # MOST ONCE at any time -- so popping an entry's member out of this map on
        # eviction is always safe (it cannot still be "live" via a second entry).
        self._live_members: dict[str, dict] = defaultdict(dict)
        self._last: dict[str, int] = {}   # key -> most-recent now_ms (for sweeping)
        # F1 (2026-10-02, adaptive-evasion lane): key -> the instant its newest hit
        # leaves ITS OWN window (that hit's now_ms + window_ms). The sweep judges
        # every key by this, never by the window of whichever hit happened to
        # trigger the sweep: it used to, so benign noise on a 60 s rule (one hit in
        # _SWEEP_EVERY) evicted the still-live 300 s / 600 s / 3600 s state of every
        # longer-window rule and an attacker could interleave noise to make those
        # rules forget. The Redis backend expires per key (EXPIRE window_s+1) and
        # never had the defect. Storing the deadline (not the window) keeps the
        # sweep a single comparison per key, as before.
        self._exp: dict[str, int] = {}
        # Min-heap of (deadline, key) over _exp so the sweep is not a full scan
        # (review finding 5); see _touch / _sweep.
        self._heap: list[tuple[int, str]] = []
        self._hits = 0

    def _touch(self, key: str, now_ms: int, window_ms: int) -> None:
        """Record the newest activity of ``key`` and when it leaves its own window.

        ``_last`` / ``_exp`` follow the NEWEST hit time and never move backwards
        (review finding 1): hit() trims by the call's own time and the bus delivers
        late/replayed/stale-stamped events (past timestamps are always accepted
        upstream), so an event OLDER than the key's newest one used to overwrite the
        deadline with ``old_ts + window`` -- one such event let the next sweep forget
        every live hit of the key (a brute-force/spray/scan evasion; the pre-F1 code
        had the same flaw via ``_last``). A late event does not make the key's newest
        hit any older. ``window_ms`` is still the latest hit's (rule reload)."""
        last = self._last.get(key)
        if last is None or now_ms > last:
            last = self._last[key] = now_ms
        deadline = last + window_ms
        prev = self._exp.get(key)
        self._exp[key] = deadline
        # Sweep index invariant: every key in _exp has a heap entry whose deadline
        # is <= its real one (so the sweep can never miss it). A key's deadline
        # normally only grows, so one entry per key suffices (the sweep reschedules
        # it); a NEW key, or a deadline that SHRANK (rule reload to a shorter window)
        # needs a fresh, earlier entry.
        if prev is None or deadline < prev:
            heapq.heappush(self._heap, (deadline, key))

    def _forget(self, key: str) -> None:
        self._w.pop(key, None)
        self._dw.pop(key, None)
        self._live_members.pop(key, None)
        self._last.pop(key, None)
        self._exp.pop(key, None)

    def _sweep(self, now_ms: int) -> None:
        """Drop keys whose newest event is older than THEIR OWN window (idle groups).

        Never against the window of the hit that triggered the sweep (F1).

        Clock (review finding 2, decided): ``now_ms`` is the triggering hit's own
        event time -- the engine clamps it to ``min(event, wall)`` -- and is
        deliberately NOT a monotone watermark: a watermark (max time seen) can only
        make the sweep MORE eager, so a hit that lags the rest of the traffic judges
        keys by its own clock and never evicts what is live for it. What remains is
        an inherent limit of event-time sweeping, not something a watermark fixes:
        a key whose source lags the traffic that triggers the sweep by more than the
        key's window loses its state at the next sweep (the Redis backend tolerates
        this because its EXPIRE is wall-clock per key). The pre-F1 code had the same
        limit for equal windows.

        Cost (review finding 5): the sweep used to scan EVERY live key each
        ``_SWEEP_EVERY`` hits, so per-hit cost grew linearly with the key count
        (measured 233 us/hit at 400k live keys). It now pops a min-heap of
        ``(deadline, key)`` instead: only entries whose recorded deadline has passed
        are touched, so a sweep over a large, still-live key set is O(1). A popped
        entry is either stale (the key's real deadline also passed -> forget) or
        outdated (the key was hit since -> reschedule at its real deadline, at most
        once per hit), i.e. O(log n) amortised per hit. Reclaim latency is unchanged
        (<= ``_SWEEP_EVERY`` hits after a key goes idle)."""
        self._hits += 1
        if self._hits % _SWEEP_EVERY:
            return
        heap = self._heap
        while heap and heap[0][0] < now_ms:
            deadline, k = heapq.heappop(heap)
            cur = self._exp.get(k)
            if cur is None:
                continue                        # already forgotten (orphan entry)
            if cur < now_ms:
                self._forget(k)
            else:
                heapq.heappush(heap, (cur, k))  # hit since this entry was queued

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
                members.pop(evicted_member, None)
        # Redelivery guard: a member already alive in the window counts once,
        # but its timestamp is REFRESHED to now_ms (R3-#61, 2026-08-27) --
        # parity with RedisWindowCounter, where ZADD on an already-present
        # member updates its score. Without the refresh, a member that keeps
        # being redelivered just inside the window would still age out at the
        # window boundary on the deque backend while the Redis backend kept
        # it alive -- the two backends disagreed on when a recurring value
        # expires.
        if member is not None and member in members:
            if members[member] == now_ms:
                # Same event redelivered (same timestamp): there is nothing to
                # refresh, so skip the O(n) scan + re-sort + rebuild (review
                # finding 4) -- the dominant at-least-once redelivery shape.
                count = len(w)
            else:
                for i, (_t, _m) in enumerate(w):
                    if _m == member:
                        w[i] = (now_ms, member)
                        break
                members[member] = now_ms
                # keep the deque time-sorted (C1): the refreshed entry may no
                # longer be at its old position relative to its neighbours.
                items = list(w)
                items.sort(key=lambda e: e[0])
                w = deque(items)
                self._w[key] = w
                while w and w[0][0] < horizon:
                    _, evicted_member = w.popleft()
                    if evicted_member is not None:
                        members.pop(evicted_member, None)
                count = len(w)
        else:
            if member is not None:
                members[member] = now_ms
            if w and now_ms < w[-1][0]:
                items = list(w)
                items.append((now_ms, member))
                items.sort(key=lambda e: e[0])
                w = deque(items)
                self._w[key] = w
                # Sorting may have surfaced a newly-stale entry at the front
                # (the out-of-order insert could sit anywhere) -- re-evict. The
                # mirror entry is written BEFORE this so that evicting the
                # just-inserted member (negative window) also drops it.
                while w and w[0][0] < horizon:
                    _, evicted_member = w.popleft()
                    if evicted_member is not None:
                        members.pop(evicted_member, None)
            else:
                w.append((now_ms, member))
            count = len(w)
        self._touch(key, now_ms, window_ms)
        if not w:
            # Only reachable with a non-positive window (the deque always holds
            # the entry just appended/refreshed otherwise); kept as the inline
            # reclaim for that case, covered by test_nonpositive_window_*.
            self._w.pop(key, None)
            self._live_members.pop(key, None)
            self._last.pop(key, None)
            self._exp.pop(key, None)
        self._sweep(now_ms)
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
        latest = {v: t for t, v in w}     # time-sorted: the last write per value is its newest
        count = len(latest)
        # Bound memory to ~2x the distinct count (2026-10-14, 24 h windows): a repeat of a
        # value only refreshes it -- the Redis backend's one-member-per-value ZADD GT -- so
        # older copies are dropped. Count and eviction are unchanged by the compaction.
        if len(w) > 2 * count + 64:
            w = deque(sorted(((t, v) for v, t in latest.items()), key=lambda e: e[0]))
            self._dw[key] = w
        self._touch(key, now_ms, window_ms)
        if not w:
            self._dw.pop(key, None)
            self._last.pop(key, None)
            self._exp.pop(key, None)
        self._sweep(now_ms)
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


#: ZADD GT + trim + ZCARD + EXPIRE for Redis < 6.2 (no GT flag): atomic as one script.
#: KEYS[1] zset; ARGV: member, score, trim-upper-bound, ttl seconds.
_DISTINCT_LUA = """
local cur = redis.call('ZSCORE', KEYS[1], ARGV[1])
if (not cur) or tonumber(ARGV[2]) > tonumber(cur) then
  redis.call('ZADD', KEYS[1], ARGV[2], ARGV[1])
end
redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, ARGV[3])
local n = redis.call('ZCARD', KEYS[1])
redis.call('EXPIRE', KEYS[1], ARGV[4])
return n
"""


#: Single-round-trip twins of the MULTI pipelines in RedisWindowCounter.hit /
#: hit_distinct (load test 2026-10-28: those pipelines were ~78% of WS-4's
#: per-event time, 1.4 ms each vs 0.76 ms as one EVALSHA on the measured host).
#: SAME four steps in the SAME order as the pipelines, and a Lua script is atomic
#: like MULTI/EXEC. KEYS[1] zset; ARGV: member, score, trim-upper-bound, ttl s.
_HIT_LUA = """
redis.call('ZADD', KEYS[1], ARGV[2], ARGV[1])
redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, ARGV[3])
local n = redis.call('ZCARD', KEYS[1])
redis.call('EXPIRE', KEYS[1], ARGV[4])
return n
"""
#: Redis >= 6.2 (ZADD GT). Older servers keep using _DISTINCT_LUA via eval().
_HIT_DISTINCT_GT_LUA = _HIT_LUA.replace("'ZADD', KEYS[1], ARGV[2]", "'ZADD', KEYS[1], 'GT', ARGV[2]")


def redis_client_for_backend(backend: str):
    """Redis client for ``BUS_BACKEND`` in {redis, redis-sentinel}, from env.

    Mirrors the client construction in ``ws4-detection/main.py`` (which still
    builds its own inline): ``redis-sentinel`` uses ``Sentinel.master_for`` so
    writes follow a failover (a pinned host:port client goes READONLY on the
    demoted master); ``redis`` uses ``REDIS_URL``. ``decode_responses=True`` is
    required by callers that compare members to ``str`` ids. Missing
    ``REDIS_SENTINEL_HOSTS`` under redis-sentinel raises (same fail-loud rule
    as ``shared.bus``) instead of silently running on a local counter.
    """
    import os
    import redis  # type: ignore
    if backend == "redis-sentinel":
        from redis.sentinel import Sentinel  # type: ignore
        hosts = []
        for part in os.getenv("REDIS_SENTINEL_HOSTS", "").split(","):
            part = part.strip()
            if not part:
                continue
            host, _, port = part.partition(":")
            hosts.append((host.strip(), int(port.strip()) if port.strip() else 26379))
        if not hosts:
            raise RuntimeError(
                "BUS_BACKEND=redis-sentinel requested but REDIS_SENTINEL_HOSTS "
                "is unset/empty; refusing to fall back to an in-process window")
        password = os.getenv("REDIS_PASSWORD", "") or None
        sentinel = Sentinel(hosts, password=password, socket_timeout=1,
                            decode_responses=True)
        return sentinel.master_for(os.getenv("REDIS_SENTINEL_MASTER", "mymaster"),
                                   redis_class=redis.Redis, password=password,
                                   decode_responses=True)
    if backend == "redis":
        return redis.Redis.from_url(
            os.getenv("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True)
    raise ValueError(f"no Redis client for BUS_BACKEND={backend!r}")


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

    def __init__(self, client, namespace: str = "ws4:win", zadd_gt: bool | None = None,
                 use_lua: bool | None = None) -> None:
        self.r = client
        self.ns = namespace
        # One EVALSHA per hit()/hit_distinct() instead of a 4-command MULTI
        # pipeline (same steps, same atomicity, one round trip, fewer replies to
        # parse). None = auto: on when the client can register scripts (any real
        # redis-py client); off for the in-test fakes that only model pipeline().
        # False forces the pipelines (the pre-2026-10-28 behaviour), which the
        # parity test in test_window_lua_live.py uses as the reference.
        self._use_lua = (callable(getattr(client, "register_script", None))
                         if use_lua is None else bool(use_lua))
        self._scripts: dict = {}
        # ZADD GT needs Redis >= 6.2 (Q11, 2026-10-14). None = detect once from
        # INFO server; False forces the Lua path (same semantics, any Redis >= 2.6).
        self._zadd_gt = zadd_gt

    def _gt_supported(self) -> bool:
        if self._zadd_gt is None:
            try:
                version = str((self.r.info("server") or {}).get("redis_version", ""))
                major, minor = (int(x) for x in version.split(".")[:2])
                self._zadd_gt = (major, minor) >= (6, 2)
            except Exception:  # noqa: BLE001 -- unknown server: the Lua path works everywhere
                self._zadd_gt = False
        return self._zadd_gt

    def _script(self, name: str, source: str):
        """Registered script, created on first use (registering contacts Redis
        on some redis-py versions, and a Redis that is down at construction must
        not fail ws4's startup). redis-py's Script re-loads itself on NOSCRIPT,
        which is what a Sentinel failover to a fresh master looks like."""
        sc = self._scripts.get(name)
        if sc is None:
            sc = self._scripts[name] = self.r.register_script(source)
        return sc

    def hit(self, key: str, now_ms: int, window_ms: int, member=None) -> int:
        zkey = f"{self.ns}:{key}"
        m = str(member) if member is not None else str(now_ms)
        horizon = now_ms - window_ms
        if self._use_lua:
            return int(self._script("hit", _HIT_LUA)(
                keys=[zkey], args=[m, now_ms, horizon - 1, max(1, window_ms // 1000 + 1)]))
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

        ``GT`` (review finding 3): a repeat of an already-seen value stamped OLDER
        than its stored score must not LOWER it -- with a plain ZADD one forged or
        lagging repeat dragged a live value's score into the past, the next
        ZREMRANGEBYSCORE aged it out at once and the distinct count fell below the
        threshold (the deque backend always kept the fresher tuple). New members are
        still added; only an update to a not-greater score is skipped. Needs Redis >= 6.2;
        older servers (Q11) run the same four steps as one Lua script (_DISTINCT_LUA).
        """
        zkey = f"{self.ns}:d:{key}"
        m = str(value) if value is not None else str(now_ms)
        horizon = now_ms - window_ms
        ttl = max(1, window_ms // 1000 + 1)
        if not self._gt_supported():
            return int(self.r.eval(_DISTINCT_LUA, 1, zkey, m, now_ms, horizon - 1, ttl))
        if self._use_lua:
            return int(self._script("hit_distinct", _HIT_DISTINCT_GT_LUA)(
                keys=[zkey], args=[m, now_ms, horizon - 1, ttl]))
        pipe = self.r.pipeline()
        pipe.zadd(zkey, {m: now_ms}, gt=True)
        pipe.zremrangebyscore(zkey, 0, horizon - 1)
        pipe.zcard(zkey)
        pipe.expire(zkey, ttl)
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
