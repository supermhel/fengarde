"""Shared message-bus abstraction (Contract B).

Backends: an in-memory bus (tests / zero-infra dev) and Redis Streams (real
deployments), selected by env BUS_BACKEND; falls back to in-memory when the redis
lib is unavailable. Kafka is a CANDIDATE for the central/scaled tier, not yet
implemented (there is no _KafkaBus) — the two-backend abstraction proves the shape
that a third backend would slot into, but do not build on Kafka until it exists.

NOTE on backend fidelity: _MemoryBus.consume() drains-and-returns with a no-op ack
(no persistent PEL), while _RedisBus has a real pending-entries list, blocking
reads, and XAUTOCLAIM redelivery. Redelivery/DLQ semantics are therefore only
partially exercised on MemoryBus (the runner tests re-create them via a re-produce
loop). Anything that depends on real PEL behavior must be verified against Redis.

    from shared.bus import Bus
    bus = Bus()
    bus.produce("normalized.events", key=evt["src_endpoint"]["ip"], payload=evt)
    for msg in bus.consume("normalized.events", group="cg-index"):
        handle(msg.payload)
"""
from __future__ import annotations
import json
import os
from dataclasses import dataclass
from collections import defaultdict, deque
from typing import Iterator, Optional


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


class _MemoryBus:
    """Process-local bus for tests / no-infra dev."""
    def __init__(self):
        self._streams: dict[str, deque] = defaultdict(deque)
        self._seq = 0

    def produce(self, topic, key, payload):
        self._seq += 1
        self._streams[topic].append(Message(topic, key, payload, str(self._seq)))

    def consume(self, topic, group=None, block_ms=0) -> Iterator[Message]:
        # drains everything currently queued, then stops (test-friendly)
        q = self._streams[topic]
        while q:
            yield q.popleft()

    def ack(self, msg, group=None):
        # consume() already removed the message from the deque; nothing to ack.
        return None

    def claim_pending(self, topic, group=None, min_idle_ms=0, max_redeliveries=5):
        # MemoryBus has no persistent PEL: consume() removes-on-yield, so there is
        # nothing to reclaim. Returns no messages and a 0 redelivery count. The
        # runner's redelivery semantics are exercised against MemoryBus by the
        # tests via a re-produce loop (see test_runner.py), not via this hook.
        return iter(())

    def drain(self, topic):
        return list(self._streams[topic])

    def depth(self, topic) -> int:
        """B2: unconsumed-message count, for the ingest-edge depth watchdog."""
        return len(self._streams[topic])

    def trim_acked(self, topic) -> int:
        """MemoryBus has no PEL / no retained-after-consume entries (see the
        module docstring's NOTE on backend fidelity) -- consume() already
        removes a message the moment it's yielded, so there is nothing an
        acked-entry reaper could ever find to trim. No-op, always 0."""
        return 0

    def lag(self, topic) -> int:
        """P1-7: MemoryBus.consume() removes an entry the instant it's
        yielded (no retained-after-consume history, no PEL) -- so depth()
        already IS the true unconsumed backlog here, unlike _RedisBus where
        depth()/XLEN also counts everything ever acked. Just reuse it."""
        return self.depth(topic)


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
                self.r.xack(topic, group, eid)
            except Exception:
                # Best-effort quarantine; if the DLQ write itself fails we still must
                # not re-raise (that would re-wedge the consumer). Drop this entry.
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
            # a traceback every few seconds. Genuine ConnectionErrors are NOT caught
            # here -> they still surface via the runner's handler.
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
        start = "0-0"
        claimed: list[Message] = []
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
                    claimed.append(msg)
            if next_start in ("0-0", 0, "0"):
                break
            start = next_start
        for msg in claimed:
            times = self._times_delivered(topic, group, msg.id)
            yield msg, times

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
        Missing stream (never produced to) reads as depth 0, not an error."""
        try:
            return int(self.r.xlen(topic))
        except Exception:
            return 0

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
        """
        try:
            groups = self.r.xinfo_groups(topic)
        except Exception:
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
        the topic doesn't exist yet)."""
        try:
            groups = self.r.xinfo_groups(topic)
        except Exception:
            return 0  # stream doesn't exist yet, or a transient Redis error
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
        except Exception:
            return 0


def Bus():
    backend = os.getenv("BUS_BACKEND", "memory").lower()
    if backend == "redis":
        try:
            return _RedisBus(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
        except Exception:
            pass
    return _MemoryBus()
