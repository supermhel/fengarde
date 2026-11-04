"""Protocol-agnostic syslog dispatch shared by the UDP and TCP listeners.

WP-1.2 extracted the per-datagram dispatch core of ``syslog_udp_server.py``
into this module so the TCP listener (RFC 6587 framing) and the UDP listener
share ONE rate-limiting / spool / counter / per-source-metrics implementation:
the token buckets (``TenantTokenBuckets``), the zero-loss spool fallback, the
``events_produced/dropped/shed/spooled/lost/empty`` counters, the bounded
per-source breakdown and the throttled shed/produce-failure logs.

Behaviour is byte-identical to the pre-extraction UDP path (the 929-line
``test_syslog_udp.py`` suite pins it; ``SyslogUDPServer`` keeps its public
surface — counters as properties, ``_handle_datagram``, ``build_raw_event`` —
so no existing test or caller changes).
"""
from __future__ import annotations

import hashlib
import threading
import time
import uuid
from collections import OrderedDict
from typing import Optional

from shared.envelope import stamp_meta
from .spool import BoundedSpool


class _TokenBucket:
    """Token bucket: capacity == rate, refills continuously by elapsed time.

    A burst up to `rate` tokens is allowed instantly (a source flushing a
    small backlog shouldn't get throttled just for existing); sustained
    traffic above `rate`/sec sheds the excess. `rate <= 0` disables limiting
    (every take() succeeds) -- the default state for tests and any deployment
    that hasn't opted in yet.

    F4 (per-tenant throughput isolation): a bucket can be keyed by tenant
    so one tenant's flood cannot consume another tenant's share. Unknown
    tenants are grouped into a single shared bucket under the reserved key
    ``_default`` to preserve the previous global behavior without an
    unbounded number of in-memory bucket objects.
    """

    def __init__(self, rate_per_sec: float):
        self.rate = rate_per_sec
        self.capacity = max(rate_per_sec, 0)
        self.tokens = self.capacity
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def take(self) -> bool:
        if self.rate <= 0:
            return True
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._last = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            if self.tokens >= 1:
                self.tokens -= 1
                return True
            return False


class TenantTokenBuckets:
    """Thin tenant-scoped facade over a shared `_TokenBucket` rate.

    A fixed per-tenant cap is required for true isolation. Sharing one
    bucket instance across tenants and branching on `take()` would still
    let one tenant's burst steal all tokens; instead each tenant gets its
    own bucket so the configured rate is a per-tenant ceiling, not a pool.
    """

    def __init__(self, rate_per_sec: float, logger=None):
        self._rate = max(rate_per_sec, 0)
        self._buckets: "dict[str, _TokenBucket]" = {}
        self._default_bucket = _TokenBucket(self._rate)
        # F4 gap fix: the tenant-level bucket alone collapses to one shared
        # budget whenever every real network source shares one tenant_id --
        # the default, single-tenant deployment. A flooding host can then
        # rate-limit away a genuine concurrent attacker's events on the same
        # collector, since both share the sole tenant bucket. A nested
        # per-source-IP bucket at the same rate caps any ONE source's share
        # of the tenant budget without weakening the tenant-wide ceiling.
        self._source_buckets: "dict[str, _TokenBucket]" = {}
        self._lock = threading.Lock()
        self._log = logger

    def take(self, tenant_id: str, source_ip: "Optional[str]" = None) -> bool:
        bucket = self._default_bucket if not tenant_id else self._buckets.get(tenant_id)
        if bucket is None:
            bucket = _TokenBucket(self._rate)
            # keep map bounded: never grow without limit on a poisoned header.
            if len(self._buckets) < 4096:
                with self._lock:
                    if tenant_id not in self._buckets:
                        self._buckets[tenant_id] = bucket
            else:
                bucket = self._default_bucket
                if self._log is not None:
                    self._log.warn("tenant bucket map full, degrading to shared default",
                                   tenant_id=tenant_id, source_ip=source_ip)
        if not bucket.take():
            return False
        if not source_ip:
            return True
        src_bucket = self._source_buckets.get(source_ip)
        if src_bucket is None:
            src_bucket = _TokenBucket(self._rate)
            if len(self._source_buckets) < 4096:
                with self._lock:
                    if source_ip not in self._source_buckets:
                        self._source_buckets[source_ip] = src_bucket
            else:
                src_bucket = self._default_bucket  # bounded map; degrade rather than grow forever
                if self._log is not None:
                    self._log.warn("source bucket map full, degrading to shared default",
                                   tenant_id=tenant_id, source_ip=source_ip)
        return src_bucket.take()


def _deterministic_ingest_id(line: str) -> str:
    """SHA-256-derived UUID-like id (mirrors WS-2's generic_syslog parser)."""
    digest = hashlib.sha256(line.encode("utf-8", errors="replace")).hexdigest()
    return f"{digest[0:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"


def build_raw_event(line: str, *, deterministic_id: bool = False) -> dict:
    """Wrap a decoded syslog line into a WS-2-parseable raw event."""
    if deterministic_id:
        ingest_id = _deterministic_ingest_id(line)
    else:
        ingest_id = str(uuid.uuid4())
    return {
        "source_type": "generic_syslog",
        "raw": line,
        "meta": stamp_meta({
            "received_at": int(time.time()),
            "ingest_id": ingest_id,
        }),
    }


# FENGARDE E6: the per-source (/metrics) breakdown is a bounded map -- cap on
# how many distinct peer IPs we retain per-source counters for, so a slow
# trickle of log sources plus a spike of novel/one-off senders can't grow the
# map without bound. When full, the least-recently-updated source is evicted
# (true LRU via dict insertion order + reinsert). This is inherently a
# visibility tradeoff: an operator sees the recent, active sources in detail
# and the aggregate counters still account for EVERY event, evicted or not.
DEFAULT_PEER_METRICS_MAX = 1024


class SyslogDispatcher:
    """One shared dispatch pipeline for every syslog listener (UDP + TCP).

    ``handle_line(line, peer_ip)`` is the whole ingest-edge decision: empty
    guard -> token buckets (tenant then source) -> bus produce, with the
    bounded-spool fallback for rate-limited or bus-down events and one set of
    aggregate counters plus a bounded per-source breakdown for /metrics.
    """

    def __init__(self, bus, *, topic: str = "raw.events",
                 max_events_per_sec: float = 0,
                 spool: Optional[BoundedSpool] = None,
                 deterministic_id: bool = False,
                 peer_metrics_max: int = DEFAULT_PEER_METRICS_MAX,
                 logger=None):
        self.bus = bus
        self.topic = topic
        self.deterministic_id = deterministic_id
        self.log = logger
        # B2: one bucket per tenant_id so one tenant's flood cannot shed another
        # tenant's datagrams. Events with no tenant_id fall into the shared
        # default bucket, preserving prior global behavior for unknown sources.
        self._buckets = TenantTokenBuckets(max_events_per_sec, logger=self.log)
        self._spool = spool
        self.events_produced = 0
        self.events_dropped = 0     # bus produce failed AND no spool (or spool full)
        self.events_shed = 0        # rate-limited AND no spool (or spool full)
        self.events_spooled = 0     # written to the fallback spool, pending replay
        self.events_lost = 0        # spool configured but itself at capacity
        # Gap-hunt (2026-08-26) #81: an empty payload is NOT a bus produce
        # failure -- incrementing events_dropped for it meant a flood of empty
        # datagrams read on /metrics exactly like a Redis outage. Distinct
        # counter so an operator can tell "empty garbage on the wire" from
        # "the bus is down".
        self.events_empty = 0
        self._last_shed_log = 0.0      # throttles the shed-warning log itself:
                                       # a real flood must not turn into a log flood
        # Gap-hunt (2026-08-26) #77: the bus-produce-failure log had no throttle
        # (unlike the shed path) -- a Redis outage at the configured event rate
        # produced thousands of log lines/sec, burying every other signal. Same
        # 1/sec throttle posture as _last_shed_log.
        self._last_produce_fail_log = 0.0
        # Dispatch used to run from genuinely concurrent threads (the UDP worker
        # pool, the TCP per-connection threads), so this lock is load-bearing.
        self._shed_lock = threading.Lock()
        self._peer_metrics_max = max(1, peer_metrics_max)
        self._peer_metrics: "OrderedDict[str, dict[str, int]]" = OrderedDict()

    def handle_line(self, line: str, peer_ip: str) -> None:
        """Dispatch one decoded syslog line from ``peer_ip`` (no exceptions)."""
        if not line:
            # An empty frame/datagram carries no event but still costs a real
            # collect cycle. Consume a rate-limit token and count it so a flood
            # of trivial payloads is throttled and visible in per_source_metrics
            # instead of bypassing both invisibly. Counted in the DISTINCT
            # events_empty counter, not events_dropped (see its comment).
            self._buckets.take("")
            with self._shed_lock:
                self.events_empty += 1
                self._count_peer(peer_ip, "empty")
            return
        # FIX 21 (reverted 2026-08-06): a prior version hardcoded
        # deterministic_id=True on the theory that "UDP retransmission is
        # normal." It isn't -- UDP has no retransmission mechanism, so
        # duplicate payloads are rare (network-level duplication/relay loops),
        # while genuinely distinct repeated log lines (identical
        # appliance/firewall messages, e.g. repeated auth failures) are common.
        # Content-hashing collapsed every distinct-but-identical-text payload to
        # ONE meta.ingest_id, which stateful window rules dedup by member -- N
        # separate brute-force attempts counted as 1 and the threshold rule
        # silently never fired. Honor the configured flag (default False =
        # per-event uuid4).
        event = build_raw_event(line, deterministic_id=self.deterministic_id)
        tenant_id = event.get("meta", {}).get("tenant_id")
        if not self._buckets.take(tenant_id or "", source_ip=peer_ip):
            if self._try_spool(peer_ip, event):
                with self._shed_lock:
                    self.events_spooled += 1
                return
            self._count_shed(peer_ip, lost_to_full_spool=self._spool is not None)
            return
        try:
            self.bus.produce(self.topic, key=peer_ip, payload=event)
        except Exception as exc:  # bus/Redis unreachable -> try the spool before dropping
            if self._try_spool(peer_ip, event):
                with self._shed_lock:
                    self.events_spooled += 1
                return
            should_log = False
            with self._shed_lock:
                self.events_dropped += 1
                self._count_peer(peer_ip, "dropped")
                # Gap-hunt (2026-08-26) #77: throttle the produce-failure log
                # (at most 1/sec), exactly like the shed path does.
                now = time.monotonic()
                if now - self._last_produce_fail_log >= 1.0:
                    self._last_produce_fail_log = now
                    should_log = True
            if should_log and self.log is not None:
                self.log.warn("dropped syslog event: bus produce failed",
                              src=peer_ip, error=str(exc),
                              spool_full=self._spool is not None)
            return
        with self._shed_lock:
            self.events_produced += 1
            self._count_peer(peer_ip, "produced")

    def _count_peer(self, peer_ip: str, kind: str) -> None:
        """Increment ``kind`` (produced/dropped/shed/empty) for ``peer_ip``.

        MUST be called with ``self._shed_lock`` held (it's only ever invoked
        from the already-locked counter blocks in ``handle_line``). Bounds the
        map: at ``_peer_metrics_max`` distinct sources the least-recently-
        updated one is evicted (true LRU via dict insertion order + reinsert).
        Eviction only affects this visibility map, never the aggregate
        counters: every event remains accounted for by the totals.
        """
        metrics = self._peer_metrics
        if peer_ip not in metrics:
            if len(metrics) >= self._peer_metrics_max:
                # evict the oldest key (OrderedDict preserves insertion order)
                metrics.pop(next(iter(metrics)))
            metrics[peer_ip] = {"produced": 0, "dropped": 0, "shed": 0, "empty": 0}
        metrics[peer_ip][kind] += 1
        metrics.move_to_end(peer_ip)

    def per_source_metrics(self) -> dict:
        """Snapshot of the bounded per-source breakdown for /metrics."""
        with self._shed_lock:
            return {ip: dict(m) for ip, m in self._peer_metrics.items()}

    def _try_spool(self, peer_ip: str, event: dict) -> bool:
        """Best-effort spool write. False on no-spool-configured, spool-full,
        OR any unexpected error (BoundedSpool.append() already treats OSError
        as "not spooled", but this belt-and-suspenders catch means a bug in
        the spool itself degrades to "count as shed/dropped" rather than
        crashing the dispatch thread and losing the event's accounting)."""
        if self._spool is None:
            return False
        try:
            return self._spool.append({"key": peer_ip, "event": event})
        except Exception as exc:
            if self.log is not None:
                self.log.warn("spool append failed unexpectedly", src=peer_ip,
                              error=str(exc))
            return False

    def _count_shed(self, peer_ip: str, *, lost_to_full_spool: bool) -> None:
        # Throttle the warning itself (at most once/sec) so a flood can't
        # turn into a logging DoS too. Locked so the counters and the
        # log-throttle timestamp stay correct under concurrent dispatchers.
        should_log = False
        with self._shed_lock:
            if lost_to_full_spool:
                self.events_lost += 1
            else:
                self.events_shed += 1
            self._count_peer(peer_ip, "shed")
            now = time.monotonic()
            if now - self._last_shed_log >= 1.0:
                self._last_shed_log = now
                should_log = True
            shed_total, lost_total = self.events_shed, self.events_lost
        if should_log and self.log is not None:
            self.log.warn(
                "shedding syslog events: rate limit exceeded",
                src=peer_ip, events_shed_total=shed_total,
                events_lost_total=lost_total, spool_full=lost_to_full_spool)