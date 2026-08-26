"""Shared message-bus abstraction (Contract B).

Backends: an in-memory bus (tests / zero-infra dev) and Redis Streams (real
deployments), selected by env BUS_BACKEND; falls back to in-memory when the redis
lib is unavailable. Kafka is a CANDIDATE for the central/scaled tier, not yet
implemented (there is no _KafkaBus) — the two-backend abstraction proves the shape
that a third backend would slot into, but do not build on Kafka until it exists.

NOTE on backend fidelity: _MemoryBus now mirrors _RedisBus's per-consumer-group
semantics (gap-hunt #50/#52/#53/#54, 2026-08-26): an append-only stream, one
delivery cursor per consumer group (EACH group receives every message -- the
real 3-way `alerts` fan-out works on the memory backend too), a per-group PEL
with a bounded cap + oldest-eviction so a never-acking consumer cannot grow
unbounded, per-group acks, claim_pending() redelivery, a real acked-front
trim, and depth()/lag() that see the PEL. The one deliberate divergence:
MemoryBus depth() counts only messages not yet delivered to ANY group (the
ingest-edge queue signal the watchdog wants; a delivered-but-unacked message
is in-flight, charged to lag() instead), whereas RedisBus depth() is XLEN.
Redelivery/DLQ semantics are exercised identically on both backends.

    from shared.bus import Bus
    bus = Bus()
    bus.produce("normalized.events", key=evt["src_endpoint"]["ip"], payload=evt)
    for msg in bus.consume("normalized.events", group="cg-index"):
        handle(msg.payload)
"""
from __future__ import annotations
import json
import os
import threading
from dataclasses import dataclass
from collections import defaultdict, deque
from typing import Iterator, Optional

from shared.log import get_logger

_log = get_logger("shared.bus")


@dataclass
class Message:
    topic: str
    key: Optional[str]
    payload: dict
    id: str


def _stream_id_lt(a: str, b: str) -> bool:
    """True if Redis stream id ``a`` sorts before ``b``. IDs are
    "<ms>-<seq>"; compare numerically on both parts (a lexicographic string
    compare breaks once the millisecond part's digit count differs)."""
    def _parts(x):
        ms, _, seq = str(x).partition("-")
        return int(ms), int(seq or 0)
    return _parts(a) < _parts(b)


def _next_stream_id(id_str: str) -> str:
    """The smallest stream id strictly greater than ``id_str``. Needed because
    ``XTRIM MINID <id>`` is INCLUSIVE (keeps entries >= id): a "safe to trim
    everything through and including this id" boundary (e.g. a group's own
    last-delivered-id, when it has nothing pending) must be advanced by one
    before use, or that one entry is retained forever instead of trimmed."""
    ms, _, seq = str(id_str).partition("-")
    return f"{ms}-{int(seq or 0) + 1}"


#: Bounded-PEL cap for the memory bus (gap-hunt #54): max unacked entries
#: retained per (topic, group). Env-tunable so a test can force eviction with
#: a tiny value. Default 10k -- generous for the test/dev backend, but finite,
#: so a consumer that never acks (e.g. ws3-indexer's batch run()) cannot grow
#: this bus's memory without bound.
_MEMORY_BUS_PEL_CAP = int(os.getenv("MEMORY_BUS_PEL_CAP", "10000"))


class _MemoryBus:
    """Process-local bus for tests / no-infra dev.

    Per-group fan-out (gap-hunt #50, 2026-08-26): the stream is append-only
    and every consumer group tracks its OWN delivery cursor, so EACH group
    receives every message -- the real 3-way `alerts` fan-out
    (cg-index/cg-webhook/cg-correlate) works on this backend exactly as it
    does on Redis Streams, instead of the old one-deque-per-topic design
    where the first group to read wiped the topic for everyone else.
    """

    #: Cap on unacked (delivered, not yet acked) entries held per group
    #: (gap-hunt #54). A consumer that never acks -- e.g. the ws3-indexer
    #: batch run() path -- cannot grow this bus's memory unboundedly:
    #: beyond the cap the OLDEST unacked entry is evicted (counted in
    #: ``_pel_evicted`` for observability). Mirrors bounded-memory
    #: discipline elsewhere in this repo (window counters, runner caches).
    _pel_cap = _MEMORY_BUS_PEL_CAP

    def __init__(self):
        self._streams: dict[str, deque] = defaultdict(deque)
        self._seq = 0
        # L1 (2026-07-30 audit): `self._seq += 1` is an unsynchronized
        # read-modify-write. deque.append() is atomic in CPython (no message
        # loss), but the counter isn't -- concurrent produce() on one shared
        # _MemoryBus (e.g. SyslogUDPServer's worker-thread pool) can hand two
        # messages the same id. Mirrors the lock WS6's InventoryStore
        # already uses for its own read-modify-write.
        self._seq_lock = threading.Lock()
        # Per-group delivery cursor: topic -> group -> count of stream
        # entries already handed to that group (its private read pointer).
        # A group first appears here on its first consume(); fan-out means
        # every group's cursor advances independently.
        self._cursors: dict[str, dict[str, int]] = defaultdict(dict)
        # Per-group PEL: topic -> group -> {msg.id: (msg, delivered_at_monotonic,
        # delivery_count)}, insertion-ordered so `next(iter(...))` is always
        # the OLDEST unacked entry (used by the cap's eviction below).
        # Closes the gap the module docstring's old "NOTE on backend
        # fidelity" only documented, never fixed: consume() used to remove
        # a message from the deque unconditionally BEFORE the handler even
        # ran, so a handler exception meant instant, permanent loss. Now the
        # PEL is real and per-group, like RedisBus's XPENDING/XAUTOCLAIM.
        self._pel: dict[str, dict[str, dict[str, tuple]]] = defaultdict(dict)
        self._pel_lock = threading.Lock()
        # gap-hunt #54 observability: (topic, group) -> evicted count.
        self._pel_evicted: "dict[tuple, int]" = defaultdict(int)

    def _group_key(self, group):
        """Normalize the group arg: None means the conventional default
        group name, same as _RedisBus's ``group="cg-default"`` default."""
        return group or "cg-default"

    def produce(self, topic, key, payload):
        with self._seq_lock:
            self._seq += 1
            seq = self._seq
        self._streams[topic].append(Message(topic, key, payload, str(seq)))

    def consume(self, topic, group=None, block_ms=0) -> Iterator[Message]:
        group_key = self._group_key(group)
        # L2 (2026-08-06 audit, Task H): the check-and-pop was NOT atomic;
        # the fix keeps "is there a message? + claim it" atomic PER
        # consume() call under _seq_lock (each message is claimed by
        # exactly one cursor advance, same guarantee as the pop-under-lock
        # fix, and the L2 all-or-nothing batch semantics test_bus_memory_race
        # pins). The lock is released BEFORE the yields on purpose: _seq_lock
        # is also taken by produce(), and a service's handler runs INSIDE
        # this consume loop and produces on the SAME bus in the same thread
        # (e.g. ws2 consumes raw.events -> produces normalized.events).
        # Holding a non-reentrant lock across a yield would self-deadlock
        # that handler.
        #
        # Delivered messages go into THIS GROUP's PEL (not popped from a
        # shared deque): an abandoned iteration (topic_worker breaks its
        # for-loop on shutdown mid-batch) leaves the rest claimable via
        # claim_pending(), mirroring _RedisBus at-least-once semantics --
        # nothing is ever silently lost.
        import time as _t
        with self._seq_lock:
            q = self._streams[topic]
            cursor = self._cursors[topic].get(group_key, 0)
            if cursor >= len(q):
                return
            batch = [q[i] for i in range(cursor, len(q))]
            self._cursors[topic][group_key] = len(q)
        with self._pel_lock:
            pel = self._pel[topic].setdefault(group_key, {})
            now = _t.monotonic()
            for msg in batch:
                pel[msg.id] = (msg, now, 1)
            while len(pel) > self._pel_cap:
                oldest_id = next(iter(pel))
                del pel[oldest_id]
                self._pel_evicted[(topic, group_key)] += 1
        for msg in batch:
            yield msg

    def ack(self, msg, group=None):
        group_key = self._group_key(group)
        with self._pel_lock:
            per_group = self._pel.get(msg.topic)
            if per_group:
                per_group.get(group_key, {}).pop(msg.id, None)

    def ack_batch(self, msgs, group=None):
        """Ack every message in ``msgs`` (P1-8 remainder). Additive:
        existing single-message ack() callers are unaffected. MemoryBus has
        no real round-trip to batch away -- this exists so callers (runner.py)
        can use one code path regardless of backend; here it's just a loop.
        """
        for msg in msgs:
            self.ack(msg, group)

    def claim_pending(self, topic, group=None, min_idle_ms=0, max_redeliveries=5):
        """Reclaim this GROUP's in-flight (delivered, not yet acked) messages
        idle at least ``min_idle_ms`` -- the mirror of _RedisBus's
        XAUTOCLAIM+XPENDING, per group (gap-hunt #52: one group's ack must
        not cancel another group's redelivery). A handler exception leaves a
        message unacked in ``self._pel[topic][group]``; the next worker-loop
        tick's claim_pending() call (runner.py's _topic_worker) picks it
        back up instead of it being gone forever.
        """
        group_key = self._group_key(group)
        import time as _t
        now = _t.monotonic()
        horizon_s = min_idle_ms / 1000.0
        claimed: list[tuple] = []
        with self._pel_lock:
            pel = self._pel[topic].get(group_key)
            if not pel:
                return
            for mid, (msg, delivered_at, count) in list(pel.items()):
                if now - delivered_at >= horizon_s:
                    new_count = count + 1
                    pel[mid] = (msg, now, new_count)
                    claimed.append((msg, new_count))
        for msg, times in claimed:
            yield msg, times

    def drain(self, topic):
        """Messages not yet delivered to ANY consumer group (the remainder
        past every group's cursor). A topic nothing has ever consumed from
        returns its whole stream -- the shape tests rely on for produced-
        but-unread topics; a fully-drained topic returns [] even though the
        stream itself keeps the (trimmable) history, same external contract
        as the old pop-on-consume behavior.
        """
        with self._seq_lock:
            q = self._streams[topic]
            cursors = self._cursors.get(topic, {})
            done = max(cursors.values()) if cursors else 0
            return list(q)[done:]

    def depth(self, topic) -> int:
        """B2/gap-hunt #53: messages not yet delivered to ANY consumer group --
        the ingest-edge backlog signal the depth watchdog wants (raw events
        still sitting in the queue unconsumed). Delivered-but-unacked work is
        deliberately NOT here: it's in-flight to a consumer, and would double
        count against lag() below -- depth() is the QUEUE signal, lag() is
        the per-consumer backlog including the PEL.
        """
        with self._seq_lock:
            q = self._streams[topic]
            if not q:
                return 0
            cursors = self._cursors.get(topic, {})
            done = max(cursors.values()) if cursors else 0
            return max(0, len(q) - done)

    def lag(self, topic) -> int:
        """P1-7 + gap-hunt #53: worst-case per-group backlog INCLUDING the
        PEL -- (stream entries past this group's cursor = undelivered) +
        (that group's unacked pending count). The old implementation was
        defined as depth(), so 5 unacked messages reported lag=0: the PEL
        was invisible. A group that read everything but acked nothing now
        reports its full pending count. No groups yet -> nothing has read
        anything -> the whole stream is the backlog (depth()).
        """
        with self._seq_lock:
            qlen = len(self._streams[topic])
            cursors = dict(self._cursors.get(topic, {}))
            if not cursors:
                # Nothing has read anything yet -> the whole stream is the
                # backlog, same as depth(). Computed inline (not via a nested
                # self.depth() call) because _seq_lock is NOT reentrant.
                return qlen
        with self._pel_lock:
            pending = {g: len(pel) for g, pel in self._pel.get(topic, {}).items()}
        return max((qlen - cur) + pending.get(g, 0) for g, cur in cursors.items())

    def pel_evicted(self, topic) -> int:
        """gap-hunt #54 companion: the eviction counter was tracked but never
        read anywhere -- a group stuck never-acking would silently evict its
        oldest pending work forever with zero visibility. Sums evictions
        across every group for `topic` (a MemoryBus-only concept: RedisBus's
        PEL lives in Redis itself and isn't synthetically capped)."""
        with self._pel_lock:
            return sum(n for (t, _g), n in self._pel_evicted.items() if t == topic)

    def trim_acked(self, topic) -> int:
        """Gap-hunt #54 companion: real acked-front trim, mirroring
        _RedisBus.trim_acked's safety proof. Only LEADING stream entries every
        registered group has consumed AND acked are removed (nothing any
        group still has pending may be dropped); the append-only stream
        would otherwise grow forever on this backend too. Every group's
        cursor is decremented to match. A topic with zero groups is left
        untouched (0). Holds _seq_lock across the whole op so a concurrent
        consume() can't claim-and-pend entries between the safety snapshot
        and the trim (a fresh group registering mid-trim would otherwise be
        able to lose leading entries it was about to receive).
        """
        with self._seq_lock:
            q = self._streams[topic]
            if not q:
                return 0
            cursors = self._cursors.get(topic, {})
            if not cursors:
                return 0
            entries = list(q)
            with self._pel_lock:
                pending_by_group = {g: set(pel) for g, pel in self._pel.get(topic, {}).items()}
            k = min(cursors.values())
            for group_key, cursor in cursors.items():
                if k <= 0:
                    break
                pending = pending_by_group.get(group_key, set())
                acked_prefix = 0
                for i in range(min(cursor, k)):
                    if entries[i].id in pending:
                        break
                    acked_prefix = i + 1
                k = min(k, acked_prefix)
            if k <= 0:
                return 0
            for _ in range(k):
                if self._streams[topic]:
                    self._streams[topic].popleft()
            for group_key in list(self._cursors.get(topic, {})):
                new_cursor = self._cursors[topic][group_key] - k
                if new_cursor <= 0:
                    del self._cursors[topic][group_key]
                else:
                    self._cursors[topic][group_key] = new_cursor
        return k


class _RedisBus:
    def __init__(self, url):
        import redis  # type: ignore
        self.r = redis.Redis.from_url(url, decode_responses=True)
        # P1-8 (2026-07-21 audit): the old hardcoded count=10 meant 1 XREADGROUP
        # round-trip per 10 messages -- at real production rates this was
        # measured as ~10-15% RTT overhead in the audit's perf review. Raising
        # the batch size cuts read RTTs roughly proportionally with no
        # correctness change (still delivered-not-yet-acked into the group's
        # PEL exactly as before, just more per read). Configurable since a very
        # large batch trades read-RTT count for per-batch memory/latency.
        self._read_count = int(os.getenv("BUS_XREADGROUP_COUNT", "100"))

    def produce(self, topic, key, payload):
        self.r.xadd(topic, {"key": key or "", "payload": json.dumps(payload)})

    def _ensure_group(self, topic, group):
        try:
            self.r.xgroup_create(topic, group, id="0", mkstream=True)
        except Exception:
            pass  # group exists

    def _consumer_name(self, group):
        return f"{group}-{os.getpid()}"

    def _decode_entry(self, topic, group, eid, fields):
        """Parse one stream entry into a Message, or quarantine it and return None.

        A stream entry can be un-parseable — a foreign/corrupt producer, a truncated
        payload, or a non-JSON body. Letting ``json.loads`` raise here is a denial of
        service: the exception kills the consume/claim generator mid-iteration, so
        (a) valid entries already read into the PEL in the same batch are never
        yielded to the handler, and (b) the poison entry never reaches the runner's
        DLQ path, so it is redelivered forever and every reclaim pass re-raises on it
        — permanently wedging the whole topic. Instead we route the raw entry to
        ``<topic>.deadletter`` and XACK it so it leaves the PEL, then skip it.
        """
        try:
            return Message(topic, fields.get("key"),
                           json.loads(fields["payload"]), eid)
        except (KeyError, ValueError, TypeError):
            try:
                self.r.xadd(f"{topic}.deadletter", {
                    "key": fields.get("key") or "",
                    "payload": json.dumps({
                        "topic": topic, "group": group, "id": eid,
                        "parse_error": True, "raw": fields.get("payload"),
                    }),
                })
            except Exception as exc:
                # Gap-hunt #55 (2026-08-26): a failed DLQ write must NOT skip
                # the xack. Before, the xadd and xack shared one try block, so
                # a DLQ outage left the poison entry permanently pending --
                # reclaimed forever, re-raised on every claim pass, wedging the
                # whole topic. The quarantine is best-effort; the ACK is not:
                # once we've decided this entry is poison it must leave the PEL
                # either way (a copy was attempted above; if the DLQ itself is
                # down the entry is dropped rather than re-wedging the stream).
                _log.error(
                    "DLQ write failed for poison entry; xacking it anyway so "
                    "it is not reclaimed forever",
                    topic=topic, group=group, id=eid, error=str(exc))
            try:
                self.r.xack(topic, group, eid)
            except Exception:
                # If even the xack fails the entry stays pending and the next
                # claim pass retries the whole quarantine -- at-least-once,
                # never a silent double-quarantine.
                pass
            return None

    def consume(self, topic, group="cg-default", block_ms=5000) -> Iterator[Message]:
        """Read NEW messages ('>') into the group's PEL and yield them WITHOUT
        acking. The caller is responsible for calling ack(msg, group) after the
        handler succeeds; unacked messages stay in the PEL for redelivery via
        claim_pending(). Returns (the iterator ends) on the first empty read so
        the runner can re-enter the loop and interleave claim_pending().
        """
        import redis  # cached import; needed for redis.exceptions below
        self._ensure_group(topic, group)
        consumer = self._consumer_name(group)
        try:
            resp = self.r.xreadgroup(group, consumer, {topic: ">"},
                                     count=self._read_count, block=block_ms)
        except redis.exceptions.TimeoutError:
            # A blocking XREADGROUP can race its own socket read-timeout against the
            # BLOCK window (redis-py raises before the empty-result comes back). An
            # expired block with nothing new == an empty read, so return cleanly and
            # let the runner re-enter + interleave claim_pending() instead of logging
            # a traceback every few seconds.
            #
            # Gap-hunt #64 (2026-08-26): this swallow used to be fully silent, so a
            # MISCONFIGURED socket_timeout (< block_ms) made every read time out,
            # consume() return empty forever, and the runner sit idle -- consumption
            # silently stopped with zero signal. Log a warning so the misconfig (or
            # the genuine benign race) is visible. Genuine ConnectionErrors are NOT
            # caught here -> they still surface via the runner's handler.
            _log.warn(
                "XREADGROUP timed out (socket_timeout racing the block window, "
                "or socket_timeout misconfigured < block_ms); treating as an "
                "empty read",
                topic=topic, group=group, block_ms=block_ms)
            return
        if not resp:
            return
        for _stream, entries in resp:
            for eid, fields in entries:
                msg = self._decode_entry(topic, group, eid, fields)
                if msg is not None:
                    yield msg

    def ack(self, msg, group="cg-default"):
        """Acknowledge a message after the handler has succeeded, removing it from
        the group's pending-entries list (PEL) so it is not redelivered."""
        self.r.xack(msg.topic, group, msg.id)

    def ack_batch(self, msgs, group="cg-default"):
        """XACK every message in ``msgs`` over ONE pipelined round-trip
        instead of one XACK per message (P1-8 remainder, 2026-07-21 audit;
        deferred at the time because it needed a safe place to accumulate
        messages across a batch -- runner.py's _topic_worker now does that,
        flushing at the same XREADGROUP-batch boundary BUS_XREADGROUP_COUNT
        already reads in).

        Deliberately NOT a Redis MULTI/EXEC transaction (``transaction=False``):
        XACK calls are independent and idempotent (acking an already-acked or
        unknown id is a no-op, not an error), so there is nothing to roll
        back and no reason to pay for atomicity none of the callers need.

        If the pipeline itself fails partway (connection drop mid-flush), the
        unacked entries simply stay in the PEL and get redelivered later --
        the same at-least-once/idempotent-handler contract every other path
        in this bus already relies on. Nothing here can silently ack a
        message this call never actually acked.
        """
        if not msgs:
            return
        pipe = self.r.pipeline(transaction=False)
        for msg in msgs:
            pipe.xack(msg.topic, group, msg.id)
        pipe.execute()

    def claim_pending(self, topic, group="cg-default", min_idle_ms=60000,
                      max_redeliveries=5):
        """Reclaim messages idle in the PEL (crashed/slow consumer) and yield
        (Message, times_delivered) so the runner can redeliver or DLQ.

        times_delivered comes from XPENDING's per-message delivery counter, which
        lives in Redis and therefore survives a consumer restart — the redelivery
        cap is not an in-memory counter.
        """
        self._ensure_group(topic, group)
        consumer = self._consumer_name(group)
        # XAUTOCLAIM transfers ownership of idle pending entries to us and also
        # bumps their delivery count. We then read the authoritative count via
        # XPENDING (times_delivered) per id.
        #
        # Yield each round's entries immediately rather than accumulating every
        # round into one list first: a PEL backlog built up during a real
        # consumer outage can be large, and materializing all of it in memory
        # before the runner processes even the first message means a big
        # backlog costs a big, avoidable memory spike right when the system is
        # already catching up from an outage. count=50 per round already
        # bounds each individual XAUTOCLAIM call; this just stops re-bounding
        # it upward by buffering every round together afterward.
        start = "0-0"
        while True:
            res = self.r.xautoclaim(topic, group, consumer, min_idle_ms, start,
                                    count=50)
            # redis-py returns (next_start, entries) on 6.2+, or
            # (next_start, entries, deleted) on 7.x.
            next_start = res[0]
            entries = res[1]
            for eid, fields in entries:
                if not fields:  # entry was deleted from the stream; skip
                    continue
                msg = self._decode_entry(topic, group, eid, fields)
                if msg is not None:
                    times = self._times_delivered(topic, group, msg.id)
                    yield msg, times
            if next_start in ("0-0", 0, "0"):
                break
            start = next_start

    def _times_delivered(self, topic, group, eid):
        # XPENDING <stream> <group> <start> <end> <count> returns rows of
        # [id, consumer, idle_ms, times_delivered].
        rows = self.r.xpending_range(topic, group, min=eid, max=eid, count=1)
        if not rows:
            return 0
        row = rows[0]
        # redis-py returns dicts: {'message_id','consumer','time_since_delivered','times_delivered'}
        if isinstance(row, dict):
            return int(row.get("times_delivered", 0))
        return int(row[3])

    def depth(self, topic) -> int:
        """B2: total stream length (unconsumed + already-acked entries still
        retained). No MAXLEN trim is applied here — trimming a stream mid-
        pipeline would drop unconsumed events, an audit-completeness violation
        for a bank; see the ingest-edge shedding in SyslogUDPServer instead.
        Missing stream (never produced to) reads as depth 0, not an error
        (XLEN returns 0 for a nonexistent key natively).

        Gap-hunt #56 (2026-08-26): a Redis OUTAGE used to read identically to
        "no backlog" (every exception swallowed into a 0). Now real Redis
        errors propagate -- all runners (depth watchdog, /metrics provider)
        already guard with try/except and report the failure as degraded
        instead of a false healthy 0.
        """
        return int(self.r.xlen(topic))

    def lag(self, topic) -> int:
        """P1-7 (2026-07-21 audit): the real per-topic backlog signal for
        backpressure alerting, as opposed to ``depth()``/XLEN which -- even
        with P0-5's reaper running -- reflects the SLOWEST registered
        group's frontier, not "how far behind is anyone actually". Worse,
        before P0-5 existed, XLEN only ever grew: once a topic passed
        ``warn_at`` from lifetime volume alone, the depth watchdog warned
        forever regardless of whether any consumer was actually behind.

        A group's true backlog is TWO independent numbers that must be
        SUMMED, not chosen between -- an earlier version of this method got
        that wrong (verified live, see test_bus_lag.py's "behind" case):
          - **undelivered**: entries added to the stream this group hasn't
            even read yet. Redis 7's native ``lag`` field on ``XINFO GROUPS``
            (entries-added minus entries-read) when the server can track it.
          - **pending**: entries this group HAS read (XREADGROUP) but not
            yet acked -- native ``lag`` does NOT include these (it only
            tracks delivery, not acknowledgment), so a group that has read
            everything but acked nothing would otherwise report a
            misleadingly healthy lag of 0. Always fetched via XPENDING's
            summary form regardless of whether native lag was available.
        Returns the MAX, across every consumer group on this stream, of
        (undelivered + pending) for that group. A topic with no consumer
        groups yet falls back to ``depth()`` (nothing has read it, so total
        length IS the backlog).

        Gap-hunt #56 (2026-08-26): a Redis OUTAGE used to read identically to
        "no backlog" (outer exception swallowed into 0). Only a genuinely
        missing stream (ResponseError "no such key") reads as 0; real Redis
        errors propagate to the guarded callers (depth watchdog, /metrics).
        """
        import redis  # cached import; needed for redis.exceptions below
        try:
            groups = self.r.xinfo_groups(topic)
        except redis.exceptions.ResponseError:
            # Stream doesn't exist yet (never produced to) -> no backlog.
            return 0
        if not groups:
            return self.depth(topic)
        worst = 0
        for g in groups:
            if not isinstance(g, dict):
                continue
            name = g.get("name")
            if not name:
                continue
            native_lag = g.get("lag")
            undelivered = native_lag if isinstance(native_lag, int) else 0
            try:
                summary = self.r.xpending(topic, name)
            except Exception:
                # One group's per-group detail read failed mid-loop -- treat
                # that group's pending as 0 rather than losing every other
                # group's contribution. The outer xinfo_groups() above already
                # proved Redis is reachable, so this is a per-group anomaly
                # (e.g. group deleted mid-scan), not an outage.
                summary = None
            pending = 0
            if summary is not None:
                pending = int((summary.get("pending") if isinstance(summary, dict)
                              else summary[0]) or 0)
            worst = max(worst, undelivered + pending)
        return worst

    def trim_acked(self, topic) -> int:
        """P0-5 (2026-07-21 audit): trim entries every consumer group has
        already finished with, so the stream doesn't retain acked history
        forever. ``depth()``'s docstring above is about NOT trimming
        unconsumed events (an audit-completeness violation); this is the
        opposite case -- entries no group can ever need again -- so it's a
        different (and safe) operation from that "no MAXLEN" decision.

        Live-proven root cause: after a full send-then-drain cycle on the
        real Docker stack, ``raw.events`` XLEN stayed frozen (7968) even
        though every entry had been consumed AND acked by every group --
        nothing ever called XTRIM. Redis memory grows monotonically with
        every event ever produced, across every topic, forever; a long
        soak run OOMs Redis even though every stage keeps up with its rate.

        Safety: only entries strictly older than the SAFE boundary are
        removed, where SAFE = the minimum, across every consumer group
        currently registered on this stream, of:
          - the smallest still-PENDING (delivered but not yet acked) entry
            id for that group, if it has any pending entries -- because
            that entry must survive for redelivery/DLQ; or
          - that group's own last-delivered id, if it has nothing pending
            (everything it's read so far is acked) -- entries at or before
            that are done for this group.
        A topic with ZERO consumer groups (nothing has ever consumed from
        it) is left untouched -- there is no "acked" boundary to compute,
        and trimming would risk dropping data before anyone has read it.
        A concurrent producer/consumer racing this computation can only make
        the computed boundary MORE conservative (an entry becomes pending or
        a new group appears after the snapshot), never less -- so a stale
        read is safe, just possibly under-trims until the next pass.

        Returns the number of entries removed (0 if nothing was eligible or
        the topic doesn't exist yet).

        Gap-hunt #56 (2026-08-26): a Redis OUTAGE used to read identically to
        "nothing to trim" (every exception swallowed into 0). Only a
        genuinely missing stream (ResponseError) or a per-group safety
        detail that can't be proven reads as 0; real Redis errors propagate
        to the guarded caller (start_stream_reaper logs them as a reaper
        failure instead of pretending nothing needed trimming).
        """
        import redis  # cached import; needed for redis.exceptions below
        try:
            groups = self.r.xinfo_groups(topic)
        except redis.exceptions.ResponseError:
            return 0  # stream doesn't exist yet -> nothing to trim
        if not groups:
            return 0  # nobody has ever consumed this topic -- don't touch it

        safe_boundary = None  # smallest-so-far "everything before this is done"
        for g in groups:
            name = g.get("name") if isinstance(g, dict) else None
            if not name:
                continue
            try:
                # XPENDING <key> <group> (summary form): (count, min_id, max_id, consumers)
                summary = self.r.xpending(topic, name)
            except Exception:
                return 0  # can't prove safety for this group -> don't trim at all
            count = summary.get("pending") if isinstance(summary, dict) else summary[0]
            if count:
                # This id is still PENDING (delivered, not yet acked) -- it must
                # be KEPT. XTRIM MINID is inclusive-keep, so using it directly as
                # the boundary is correct: nothing at or after it gets removed.
                min_id = summary.get("min") if isinstance(summary, dict) else summary[1]
                boundary = min_id
            else:
                # Nothing pending -> this group is fully done through (and
                # including) last-delivered-id, so THAT entry itself is safe to
                # remove too. XTRIM MINID keeps entries >= the boundary, so the
                # boundary must be advanced past it or it survives forever.
                last_delivered = g.get("last-delivered-id") if isinstance(g, dict) else None
                if last_delivered is None:
                    return 0  # can't prove safety -> don't trim at all
                boundary = _next_stream_id(last_delivered)
            if not isinstance(boundary, str):
                continue  # can't prove safety without a real stream id -> skip this group
            if safe_boundary is None or _stream_id_lt(boundary, safe_boundary):
                safe_boundary = boundary

        if safe_boundary is None:
            return 0
        try:
            # approximate=False: exact trim, so the safety proof above (nothing
            # pending or undelivered is ever below safe_boundary) holds precisely
            # rather than Redis's "~" approximate variant retaining an unknown
            # few extra entries near the boundary (harmless, but untestable).
            return int(self.r.xtrim(topic, minid=safe_boundary, approximate=False))
        except redis.exceptions.ResponseError:
            # Stream vanished between the safety computation and the trim
            # (deleted/concurrent reaper) -> nothing left to trim, not an
            # outage. Anything else (ConnectionError etc.) propagates (#56).
            return 0


class _RedisSentinelBus:
    """Redis Streams bus backed by Sentinel master discovery, for the HA
    opt-in profile (see infra/docker-compose.ha.yml). Delegates every
    Streams operation to a plain _RedisBus pointed at the current master;
    re-resolves the master through Sentinel after any call fails, so a
    failover is picked up on the next operation rather than requiring a
    process restart. Default single-instance deployments never construct
    this class -- BUS_BACKEND stays "redis" unless HA is explicitly opted
    into via BUS_BACKEND=redis-sentinel.
    """

    def __init__(self, url: str) -> None:
        self._url = url
        self._password = os.getenv("REDIS_PASSWORD", "")
        sentinel_hosts = []
        for part in os.getenv("REDIS_SENTINEL_HOSTS", "").split(","):
            part = part.strip()
            if not part:
                continue
            host, _, port = part.partition(":")
            sentinel_hosts.append((host.strip(), int(port.strip()) if port else 26379))
        self._master_name = os.getenv("REDIS_SENTINEL_MASTER", "mymaster")
        if not sentinel_hosts:
            # Gap-hunt #51 (2026-08-26): fail LOUDLY. Before, an empty
            # REDIS_SENTINEL_HOSTS silently left _sentinel=None and this class
            # degraded to a plain non-HA _RedisBus pinned to REDIS_URL -- zero
            # failover, zero signal, exactly the failure mode HA was opted into
            # to avoid. A service that asked for sentinel HA must not start as
            # a non-HA service pretending nothing is wrong.
            raise RuntimeError(
                "BUS_BACKEND=redis-sentinel requested but REDIS_SENTINEL_HOSTS "
                "is unset/empty -- refusing to silently degrade to a non-HA bus "
                "pinned to REDIS_URL. Set REDIS_SENTINEL_HOSTS "
                "(comma-separated host:port[,host:port...]) or use "
                "BUS_BACKEND=redis instead.")
        from redis.sentinel import Sentinel  # type: ignore
        self._sentinel = Sentinel(
            sentinel_hosts, password=self._password or None,
            socket_timeout=1, decode_responses=True,
        )
        # Probe master discovery NOW (gap-hunt #51): a Sentinel that can't
        # resolve the master at startup is a broken HA configuration, and
        # starting a "sentinel" bus that points at a dead master -- or, worse,
        # recovering by silently pinning to REDIS_URL -- is the same silent
        # degradation. discover_master raising here crashes startup.
        host, port = self._sentinel.discover_master(self._master_name)
        new_url = f"redis://:{self._password or ''}@{host}:{port}/0"
        self._url = new_url
        self._bus = _RedisBus(new_url)

    @property
    def r(self):
        return self._bus.r

    def _refresh_master(self) -> bool:
        if self._sentinel is None:
            return False
        try:
            host, port = self._sentinel.discover_master(self._master_name)
            new_url = f"redis://:{self._password or ''}@{host}:{port}/0"
            if new_url != self._url:
                self._url = new_url
                self._bus = _RedisBus(new_url)
            return True
        except Exception as exc:
            # Sentinel temporarily unreachable -- keep using the last known bus
            # rather than raise; the next failing call retries discovery. But
            # NEVER silently: gap-hunt #51's "zero signal" complaint applies to
            # runtime rediscovery failure just as much as to init failure.
            _log.error(
                "Sentinel master discovery failed; keeping the last known "
                "master bus (no failover until discovery recovers)",
                master=self._master_name, error=str(exc))
            return False

    def _with_failover(self, method, *args, **kwargs):
        """Failover wrapper for the PLAIN (non-generator) bus methods.

        Only valid when ``method`` actually performs its I/O during the call.
        For a generator function the call merely builds the generator and does
        no I/O at all, so nothing can raise here and this wrapper silently
        degrades to a no-op -- see ``_iter_with_failover``.
        """
        try:
            return getattr(self._bus, method)(*args, **kwargs)
        except Exception:
            self._refresh_master()
            return getattr(self._bus, method)(*args, **kwargs)

    def _iter_with_failover(self, method, *args, **kwargs):
        """Failover wrapper for the GENERATOR bus methods (consume,
        claim_pending).

        Live-verified bug (2026-08-05, found by killing the primary under the
        full HA stack rather than a produce-only test client): ``_RedisBus
        .consume`` and ``_RedisBus.claim_pending`` are generator functions, so
        ``getattr(self._bus, method)(...)`` returns a generator object without
        executing a single line of the body. No connection is touched, nothing
        can raise, and ``_with_failover``'s ``except`` is therefore unreachable
        for them. The ConnectionError surfaces later, when the RUNNER iterates
        the generator -- outside the try block -- so ``_refresh_master()`` was
        never called on the two methods every long-running service spends its
        entire life in. The runner's own retry then called ``consume()`` again,
        which built another generator against the SAME stale ``self._bus``, and
        the service stayed pinned to the dead primary forever.

        Observed on the full stack: Redis-side failover completed in 1.2s, but
        ws2/ws3/ws4/ws5 all went unhealthy looping on
        ``ConnectionError: Error 113 connecting to <old primary>:6379. No route
        to host.`` while 12 messages sat unconsumed at ``lag=12`` on the new
        primary. A produce-only client recovered fine in the same scenario,
        which is exactly what made this invisible: ``produce``/``ack``/``depth``
        /``lag``/``trim_acked`` are ordinary functions and were genuinely
        covered by ``_with_failover``.

        Delegating with ``yield from`` puts the ITERATION inside the try, which
        is where the I/O actually happens. A retry may redeliver entries the
        first generator already yielded; that is consistent with the
        at-least-once contract this bus documents (consumers are idempotent on
        ingest_id/event_id/alert_id), and is strictly better than wedging.
        """
        try:
            yield from getattr(self._bus, method)(*args, **kwargs)
        except Exception:
            self._refresh_master()
            yield from getattr(self._bus, method)(*args, **kwargs)

    def produce(self, topic, key, payload):
        return self._with_failover("produce", topic, key, payload)

    def consume(self, topic, group="cg-default", block_ms=5000):
        return self._iter_with_failover("consume", topic, group=group,
                                        block_ms=block_ms)

    def ack(self, msg, group="cg-default"):
        return self._with_failover("ack", msg, group=group)

    def ack_batch(self, msgs, group="cg-default"):
        return self._with_failover("ack_batch", msgs, group=group)

    def claim_pending(self, topic, group="cg-default", min_idle_ms=60000,
                      max_redeliveries=5):
        return self._iter_with_failover("claim_pending", topic, group=group,
                                        min_idle_ms=min_idle_ms,
                                        max_redeliveries=max_redeliveries)

    def depth(self, topic) -> int:
        return self._with_failover("depth", topic)

    def lag(self, topic) -> int:
        return self._with_failover("lag", topic)

    def trim_acked(self, topic) -> int:
        return self._with_failover("trim_acked", topic)


def Bus():
    backend = os.getenv("BUS_BACKEND", "memory").lower()
    if backend == "redis":
        try:
            return _RedisBus(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
        except ImportError:
            # Code-quality #1 (2026-07-29 audit): only the documented case --
            # the redis-py lib isn't installed, e.g. a zero-infra dev env --
            # falls back silently. Any other constructor failure (malformed
            # REDIS_URL, a non-numeric BUS_XREADGROUP_COUNT) used to be
            # swallowed here too, silently downgrading a service that asked
            # for BUS_BACKEND=redis to an isolated in-memory bus with no log
            # line -- every produce()/consume() after that point talks to a
            # bus nothing else reads. Let those propagate instead: a broken
            # config should crash loudly at startup, not degrade silently.
            from shared.log import get_logger
            get_logger("bus").warn(
                "BUS_BACKEND=redis requested but redis-py is not installed; "
                "falling back to in-memory bus (not shared across processes)")
    elif backend == "redis-sentinel":
        try:
            return _RedisSentinelBus(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
        except ImportError:
            from shared.log import get_logger
            get_logger("bus").warn(
                "BUS_BACKEND=redis-sentinel requested but redis-py is not installed; "
                "falling back to in-memory bus (not shared across processes)")
    return _MemoryBus()
