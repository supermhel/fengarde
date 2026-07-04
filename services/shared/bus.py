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


class _RedisBus:
    def __init__(self, url):
        import redis  # type: ignore
        self.r = redis.Redis.from_url(url, decode_responses=True)

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
            resp = self.r.xreadgroup(group, consumer, {topic: ">"}, count=10,
                                     block=block_ms)
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


def Bus():
    backend = os.getenv("BUS_BACKEND", "memory").lower()
    if backend == "redis":
        try:
            return _RedisBus(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
        except Exception:
            pass
    return _MemoryBus()
