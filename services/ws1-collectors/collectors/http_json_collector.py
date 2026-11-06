"""HTTP/JSON ingest collector for WS-1 (WP-1.1, 2026-11-04).

Real-input path #2: a developer with Vector, Fluent Bit, Filebeat, n8n or an
AI-agent gateway pushes JSON to FENGARDE with one config line::

    POST /v1/ingest?source_type=windows_eventlog          (body: NDJSON)
    POST /v1/ingest?source_type=sysmon&format=json-array  (body: [ {...}, ... ])
    Authorization: Bearer <FENGARDE_INGEST_TOKEN>

Each record becomes a ``raw.events`` message shaped exactly like the syslog
path (``{source_type, raw, meta}``, partition key = the request's peer IP):

    {"source_type": "windows_eventlog",
     "raw": {"EventID": 4625, "TimeCreated": "...", ...},   # the wire record
     "meta": {"received_at": <epoch_s>, "ingest_id": <hex-derived>,
              "format": "ndjson", "trace_id": ..., "tenant_id": ...}}

``raw`` is the wire record itself, so the value handed to WS-2 uses the
parser's own key convention (EventID, TimeCreated, ...) -- input ADAPTERS
for real shipper shapes are WP-1.3's job, not this listener's.

Auth: a bearer token from ``FENGARDE_INGEST_TOKEN`` is REQUIRED; the listener
refuses to start without it unless an explicit loopback-only dev switch
(``FENGARDE_INGEST_DEV_LOOPBACK``) is set.  TLS is the reverse proxy's job
(docs/deployment.md, Caddy section), not this listener's.

Idempotent redelivery: when the client sends an ``X-Fengarde-Idempotency-Key``
header, ``ingest_id`` is derived (SHA-256 of key + line ordinal + canonical
record JSON + source_type) so redelivering the SAME batch with the SAME key
produces the SAME ids.  Without the key, ingest_id is a random uuid4 --
deliberately: a pure content hash would collapse N distinct-but-identical
records to one id (the syslog listener's FIX 21 lesson, see
syslog_udp_server.py), so the content-hash hazard is only opted into via an
explicit client promise.  The line ordinal is part of the digest so two
identical lines inside one batch stay distinct; redelivery must preserve
line order to get identical ids.

Limits and failure modes (all counted; a malformed record never aborts the
batch):
  * body > INGEST_HTTP_MAX_BODY_BYTES  -> 413, refused before parsing
  * unknown source_type / format       -> 400
  * malformed JSON line/element        -> counted in ``skipped``, batch continues
  * per-source rate limit (reuses the syslog path's TenantTokenBuckets,
    keyed by the client IP)            -> 429 when any record was shed
  * bus down + spool configured        -> 202 "accepted for later delivery"
  * bus down + no spool                -> 503, dropped records counted

Response status precedence: 503 (any dropped) > 202 (all spooled) > 429
(any rate-limited) > 200.  The body always carries the per-request counts.

The HTTP surface is authenticated (``Authorization`` bearer token), so the
lane-coverage assertion #5 (tools/check_lane_coverage.py) is satisfied by
the auth check below -- no FENGARDE-OPEN-BY-DESIGN marker needed.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import parse_qs

from shared.envelope import stamp_meta
from .spool import BoundedSpool
from collections import OrderedDict

from .syslog_udp_server import TenantTokenBuckets, _TokenBucket

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8554
DEFAULT_MAX_BODY_BYTES = 1024 * 1024      # 1 MiB cap on one POST body
DEFAULT_MAX_EVENTS_PER_SEC = 2000         # per-source, same shape as syslog
DEFAULT_MAX_CONCURRENT = 16               # ThreadingHTTPServer thread guard
_READ_CHUNK = 64 * 1024
DEFAULT_MAX_SOURCES = 4096                # bound on the per-source bucket map (LRU)
# A sender may label the device a batch came from (X-Fengarde-Source / ?source=). The label is only trusted as far as the
# bearer token: it keys the per-source rate limit, the bus partition and the metrics, never an authorization decision.
_SOURCE_ID_RE = re.compile(r"^[A-Za-z0-9._:@\-]{1,128}$")
#: Optional shipper self-label (X-Fengarde-Shipper / ?shipper=), e.g.
#: ``fluentbit-winevtlog``, ``winlogbeat``, ``fluentbit-journald``, ``docker-json``.
#: Stamped into meta.shipper for the WS-2 adapter stage (WP-1.3). Same
#: character class as the device label; advisory only (keys the adapter
#: selection, never an authorization decision).
_SHIPPER_ID_RE = re.compile(r"^[A-Za-z0-9._:\-]{1,64}$")

# Frozen snapshot of services/ws2-normalization/parsers/_REGISTRY keys: the
# daemon validates source_type WITHOUT importing ws2 (separate image; the
# ws2 directory name contains a hyphen and is not importable).  Gate-time
# drift is caught by test_http_json_ingest.py, which imports ws2's registry
# and FAILS when these two sets diverge -- keep them in the same PR.
REGISTERED_SOURCE_TYPES: frozenset[str] = frozenset({
    "active_directory", "cef", "cisco_asa", "cloudtrail", "db_audit",
    "dns_query", "generic_syslog", "inventory_diff", "k8s_audit", "linux_ssh",
    "m365_audit", "mail_gateway", "mcp_agent", "modbus_anomaly", "n8n_audit",
    "opcua_audit", "suricata_eve", "sysmon", "vmware_vsphere", "windows_eventlog",
    "zeek_json",
})

FORMATS = ("ndjson", "json-array")


def _deterministic_ingest_id(*parts: str) -> str:
    """UUID-shaped SHA-256 digest (same shape as the syslog listener's)."""
    digest = hashlib.sha256(
        "|".join(parts).encode("utf-8", errors="replace")).hexdigest()
    return f"{digest[0:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"


def _canonical_json(value: dict) -> str:
    """Stable serialization for the idempotency digest (key order fixed)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


class HttpJsonCollector:
    """WS-1 HTTP/JSON ingest listener (in-process, threaded, counted).

    Mirrors SyslogUDPServer's shape: ``start()``/``stop()`` on background
    threads, aggregate counters, optional BoundedSpool fallback, per-source
    token-bucket rate limiting.
    """

    def __init__(self, bus, *, ingest_token: Optional[str],
                 dev_loopback: bool = False,
                 host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                 topic: str = "raw.events",
                 max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
                 max_events_per_sec: float = DEFAULT_MAX_EVENTS_PER_SEC,
                 max_concurrent: int = DEFAULT_MAX_CONCURRENT,
                 max_events_per_sec_per_source: float = 0,
                 spool: Optional[BoundedSpool] = None,
                 extra_source_types=(),
                 logger=None):
        if not ingest_token and not (dev_loopback and _is_loopback(host)):
            # Unauthenticated ingest on a non-loopback bind is a data-injection
            # hole: refuse to construct (main.py logs and stays up for /health,
            # same posture as a failed UDP bind).
            raise ValueError(
                "FENGARDE_INGEST_TOKEN is required for the HTTP/JSON ingest "
                "listener (refusing to start unauthenticated); set it, or bind "
                "loopback-only with FENGARDE_INGEST_DEV_LOOPBACK=1 for local dev")
        if max_body_bytes <= 0:
            raise ValueError("INGEST_HTTP_MAX_BODY_BYTES must be > 0")
        self.bus = bus
        self.token = ingest_token or None
        # Parser plugins register source types ws1 cannot see (separate image); the operator lists them here
        # (INGEST_HTTP_EXTRA_SOURCE_TYPES) so the edge does not 400 a type ws2 would parse.
        self.source_types = REGISTERED_SOURCE_TYPES | frozenset(
            str(s).strip() for s in extra_source_types if str(s).strip())
        self.dev_loopback = dev_loopback
        self.host = host
        self.port = int(port)
        self.topic = topic
        self.max_body_bytes = int(max_body_bytes)
        self.max_concurrent = max(1, int(max_concurrent))
        self.log = logger
        self._buckets = TenantTokenBuckets(max_events_per_sec, logger=logger)
        # Per-source cap, separate from the tenant ceiling. The nested per-IP bucket inside TenantTokenBuckets runs at the
        # SAME rate as the tenant bucket, so it can never bind first; a lower per-source rate is what actually stops one
        # noisy device from using the whole tenant budget. 0 = off.
        self._source_rate = max(0.0, float(max_events_per_sec_per_source))
        self._source_buckets: "OrderedDict[str, _TokenBucket]" = OrderedDict()
        self._source_lock = threading.Lock()
        self._spool = spool

        # Aggregate counters (flat numeric leaves -> real Prometheus gauges).
        self.events_accepted = 0
        self.events_malformed = 0
        self.events_rate_limited = 0
        self.events_spooled = 0
        self.events_dropped = 0
        self.body_over_cap = 0
        self.requests_ok = 0
        self.requests_accepted = 0     # 202
        self.requests_limited = 0      # 429
        self.requests_rejected = 0      # 4xx
        self.requests_failed = 0       # 503

        self._server: Optional[_HttpIngestServer] = None
        self._thread: Optional[threading.Thread] = None
        self._running = threading.Event()

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> None:
        if self._running.is_set():
            return
        self._server = _HttpIngestServer(
            (self.host, self.port), _IngestHandler, self,
            max_concurrent=self.max_concurrent)
        server = self._server
        # Reflect the real bound address (port 0 -> ephemeral in tests).
        # server_address is a broad stdlib union (host may be bytes for AF_UNIX,
        # an IPv6 tuple has 4 items) -- convert explicitly to (str, int).
        self.host = str(server.server_address[0])
        self.port = int(server.server_address[1])
        self._running.set()
        self._thread = threading.Thread(target=self._serve_loop,
                                        name="http-json-ingest", daemon=True)
        self._thread.start()
        if self.log is not None:
            self.log.info("http json ingest listening", host=self.host,
                          port=self.port, token_set=bool(self.token),
                          dev_loopback=self.dev_loopback)

    def _serve_loop(self) -> None:
        server = self._server
        if server is None:
            self._running.clear()
            return
        try:
            server.serve_forever(poll_interval=0.5)
        finally:
            self._running.clear()

    def is_running(self) -> bool:
        return self._running.is_set() and bool(
            self._thread and self._thread.is_alive())

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        self._running.clear()

    # -- batch handling -----------------------------------------------------

    def handle_batch(self, source_type: str, format_name: str,
                     records: list, errors: list, *,
                     idempotency_key: Optional[str], peer_ip: str,
                     source_id: Optional[str] = None,
                     shipper_id: Optional[str] = None) -> dict:
        """Process one validated batch; returns THIS request's counts.

        Never raises on a malformed record -- a JSON parse error (collected
        in ``errors``) or a non-dict record is counted in ``skipped`` and the
        batch continues (WP-1.1: "a malformed line is counted and skipped,
        never aborts the batch").
        """
        tenant_id = os.getenv("TENANT_ID", "default")
        # The device label when the sender gave one, else the TCP peer (behind a published Docker port or a relay every
        # sender shares one peer address). It keys the rate limit, the bus partition and the spool entry.
        key = source_id or peer_ip
        accepted = skipped = dropped = spooled = rate_limited = 0
        all_errors = list(errors)
        skipped = len(all_errors)  # parse-level failures are skipped records
        for ordinal, record in enumerate(records):
            if not isinstance(record, dict):
                skipped += 1
                all_errors.append(f"record {ordinal} is not a JSON object")
                continue
            if idempotency_key is not None:
                ingest_id = _deterministic_ingest_id(
                    idempotency_key, str(ordinal), _canonical_json(record),
                    source_type)
            else:
                ingest_id = str(uuid.uuid4())
            if not self._buckets.take(tenant_id) or not self._take_source(key):
                rate_limited += 1
                continue
            event = {
                "source_type": source_type,
                "raw": record,
                "meta": stamp_meta({
                    "received_at": int(time.time()),
                    "ingest_id": ingest_id,
                    "format": format_name,
                    "shipper_ip": peer_ip,
                    **({"source": source_id} if source_id else {}),
                    **({"shipper": shipper_id} if shipper_id else {}),
                }),
            }
            try:
                self.bus.produce(self.topic, key=key, payload=event)
                accepted += 1
            except Exception:
                if self._try_spool(key, event):
                    spooled += 1
                else:
                    dropped += 1
        with _COUNTER_LOCK:
            self.events_accepted += accepted
            self.events_malformed += skipped
            self.events_rate_limited += rate_limited
            self.events_spooled += spooled
            self.events_dropped += dropped
        return {
            "accepted": accepted,
            "skipped": skipped,
            "dropped": dropped,
            "spooled": spooled,
            "rate_limited": rate_limited,
            "errors": all_errors,
        }

    def _take_source(self, key: str) -> bool:
        """Per-source token bucket (LRU-bounded map); always True when no per-source rate is configured."""
        if self._source_rate <= 0:
            return True
        with self._source_lock:
            bucket = self._source_buckets.get(key)
            if bucket is None:
                bucket = _TokenBucket(self._source_rate)
                self._source_buckets[key] = bucket
                if len(self._source_buckets) > DEFAULT_MAX_SOURCES:
                    self._source_buckets.popitem(last=False)
            else:
                self._source_buckets.move_to_end(key)
        return bucket.take()

    def _try_spool(self, peer_ip: str, event: dict) -> bool:
        if self._spool is None:
            return False
        try:
            return self._spool.append({"key": peer_ip, "event": event})
        except Exception as exc:
            if self.log is not None:
                self.log.warn("http ingest spool append failed unexpectedly",
                              src=peer_ip, error=str(exc))
            return False

    def bump(self, name: str, n: int = 1) -> None:
        """Thread-safe counter increment (handler threads share these)."""
        with _COUNTER_LOCK:
            setattr(self, name, getattr(self, name) + n)

    # -- metrics ------------------------------------------------------------

    def metrics(self) -> dict:
        """Flat ingest-edge counters for the /metrics provider (same shape
        contract as _syslog_metrics in main.py)."""
        return {
            "http_events_accepted": self.events_accepted,
            "http_events_malformed": self.events_malformed,
            "http_events_rate_limited": self.events_rate_limited,
            "http_events_spooled": self.events_spooled,
            "http_events_dropped": self.events_dropped,
            "http_body_over_cap": self.body_over_cap,
            "http_requests_ok": self.requests_ok,
            "http_requests_202": self.requests_accepted,
            "http_requests_429": self.requests_limited,
            "http_requests_4xx": self.requests_rejected,
            "http_requests_503": self.requests_failed,
        }


class _HttpIngestServer(ThreadingHTTPServer):
    daemon_threads = True
    # socketserver listens with a backlog of 5: a burst of shippers connecting at once saw ECONNREFUSED/ECONNABORTED
    # (found as a flaky counter test). The concurrency cap, not the accept queue, should decide who is served.
    request_queue_size = 128

    def __init__(self, addr, handler, collector: HttpJsonCollector, *,
                 max_concurrent: int):
        super().__init__(addr, handler)
        self.collector = collector
        # Bound the thread-per-connection cost of ThreadingHTTPServer: a
        # slow client may hold one slot, but never unbounded workers.
        self._slots = threading.BoundedSemaphore(max_concurrent)

    def process_request(self, request, client_address):
        # Gap-hunt review of PR 142: ThreadingHTTPServer spawns one thread per ACCEPTED connection before any handler
        # runs, so a semaphore inside do_POST never bounded slow-header or idle connections. Take the slot here, answer
        # 503 on the accept thread when full, and release it when the connection thread ends.
        if not self._slots.acquire(blocking=False):
            self.collector.bump("requests_failed")
            try:
                request.sendall(b"HTTP/1.0 503 Service Unavailable\r\nContent-Length: 0\r\n"
                                b"Connection: close\r\n\r\n")
            except OSError:
                pass
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


class _IngestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"    # close per request: no keep-alive ambiguity
    server_version = "FENGARDE-ingest/1.0"
    timeout = 15                     # slow client holds one slot, then drops

    @property
    def collector(self) -> HttpJsonCollector:
        server = self.server
        assert isinstance(server, _HttpIngestServer)
        return server.collector

    def log_message(self, fmt, *args):  # noqa: A003 -- stdlib hook
        logger = getattr(self.collector, "log", None)
        if logger is not None:
            logger.info("http ingest access", path=self.path,
                        status=fmt % args)

    # -- routes -------------------------------------------------------------

    def do_GET(self):  # noqa: N802
        self._send_json(405, {"error": "method not allowed; POST /v1/ingest"})

    do_PUT = do_DELETE = do_PATCH = do_GET  # noqa: N815 -- stdlib naming

    def do_POST(self):  # noqa: N802
        self._handle_post()

    def _handle_post(self) -> None:
        c = self.collector
        self._body_consumed = False
        if self.path.split("?", 1)[0] != "/v1/ingest":
            c.bump("requests_rejected")
            self._send_json(404, {"error": "not found; POST /v1/ingest"})
            return

        # --- auth (load-bearing: the negative control in test_http_json_ingest
        # --- proves the 401 surface dies when this check is removed) --------
        token = self._bearer_token()
        if c.token is not None:
            if not token or not hmac.compare_digest(token.encode("utf-8", "replace"),
                                                    c.token.encode("utf-8", "replace")):
                c.bump("requests_rejected")
                self._send_json(401, {"error": "unauthorized"})
                return
        else:  # dev_loopback mode: loopback peers only
            if not _is_loopback(self.client_address[0]):
                c.bump("requests_rejected")
                self._send_json(403, {"error": "dev switch is loopback-only"})
                return

        # --- source_type / format (query or header; conflict = 400) ----------
        parsed = self._query()
        try:
            source_type = self._param(parsed.get("source_type"),
                                      self.headers.get("X-Fengarde-Source-Type"))
            format_name = self._param(parsed.get("format"),
                                      self.headers.get("X-Fengarde-Format"),
                                      default="ndjson")
        except _BadRequest as exc:
            c.bump("requests_rejected")
            self._send_json(400, {"error": str(exc)})
            return
        try:
            source_id = self._source_id(parsed.get("source"), self.headers.get("X-Fengarde-Source"))
            shipper_id = self._shipper_id(parsed.get("shipper"), self.headers.get("X-Fengarde-Shipper"))
        except _BadRequest as exc:
            c.bump("requests_rejected")
            self._send_json(400, {"error": str(exc)})
            return
        if source_type not in c.source_types:
            c.bump("requests_rejected")
            self._send_json(
                400, {"error": f"unknown source_type {source_type!r}; "
                               f"registered: {sorted(c.source_types)}"})
            return
        if format_name not in FORMATS:
            c.bump("requests_rejected")
            self._send_json(400, {"error": f"unknown format {format_name!r}; "
                                           f"valid: {FORMATS}"})
            return

        # --- body size cap (413 before any parsing) --------------------------
        try:
            body = self._read_body()
        except _TooLarge:
            c.bump("body_over_cap")
            c.bump("requests_rejected")
            self._send_json(413, {"error": f"request body exceeds "
                                           f"{c.max_body_bytes} bytes"})
            return
        except _BadRequest as exc:
            c.bump("requests_rejected")
            self._send_json(400, {"error": str(exc)})
            return

        # --- parse (malformed records counted, never aborts) -----------------
        try:
            records, parse_errors = self._parse_body(body, format_name)
        except _BadRequest as exc:
            c.bump("requests_rejected")
            self._send_json(400, {"error": str(exc)})
            return

        idem_key = self.headers.get("X-Fengarde-Idempotency-Key") or None
        counts = c.handle_batch(source_type, format_name, records,
                                parse_errors, idempotency_key=idem_key,
                                peer_ip=self.client_address[0], source_id=source_id,
                                shipper_id=shipper_id)
        payload = {
            "source_type": source_type,
            "format": format_name,
            "accepted": counts["accepted"],
            "skipped": counts["skipped"],
            "errors": counts["errors"][:20],
        }

        if counts["accepted"] > 0 and idem_key is None and (counts["dropped"] or counts["rate_limited"]):
            payload["note"] = ("partial accept: resend the batch with X-Fengarde-Idempotency-Key to avoid "
                               "duplicating the accepted records")
        # Status precedence: 503 (dropped) > 202 (all spooled) > 429 > 200.
        if counts["dropped"] > 0:
            c.bump("requests_failed")
            self._send_json(503, {**payload,
                                  "error": "bus unavailable and no spool; "
                                           "records dropped"})
            return
        if counts["spooled"] > 0 and counts["accepted"] == 0:
            c.bump("requests_accepted")
            self._send_json(202, {**payload, "spooled": counts["spooled"],
                                  "note": "accepted for later delivery (bus down)"})
            return
        if counts["rate_limited"] > 0:
            c.bump("requests_limited")
            self._send_json(429, {**payload,
                                  "rate_limited": counts["rate_limited"]})
            return
        c.bump("requests_ok")
        self._send_json(200, payload)

    # -- helpers ------------------------------------------------------------

    def _query(self) -> dict:
        if "?" not in self.path:
            return {}
        out = {}
        for k, vals in parse_qs(self.path.split("?", 1)[1],
                                keep_blank_values=False).items():
            out[k] = vals[0] if vals else ""
        return out

    def _source_id(self, query_val, header_val):
        """Optional device label from ?source= or X-Fengarde-Source (None when absent; conflict or bad characters = 400)."""
        if query_val and header_val and query_val != header_val:
            raise _BadRequest("conflicting source between query parameter and header")
        value = (query_val or header_val or "").strip()
        if not value:
            return None
        if not _SOURCE_ID_RE.match(value):
            raise _BadRequest("source must be 1-128 characters of [A-Za-z0-9._:@-]")
        return value

    def _shipper_id(self, query_val, header_val):
        """Optional shipper self-label from ?shipper= or X-Fengarde-Shipper
        (None when absent; conflict or bad characters = 400). Advisory only —
        it selects the WS-2 adapter, never an authorization decision."""
        if query_val and header_val and query_val != header_val:
            raise _BadRequest("conflicting shipper between query parameter and header")
        value = (query_val or header_val or "").strip()
        if not value:
            return None
        if not _SHIPPER_ID_RE.match(value):
            raise _BadRequest("shipper must be 1-64 characters of [A-Za-z0-9._:-]")
        return value

    def _param(self, query_val, header_val, *, default=None):
        if query_val and header_val and query_val != header_val:
            raise _BadRequest("conflicting value between query parameter and "
                              "header")
        value = query_val or header_val or default
        if value is None or not str(value).strip():
            raise _BadRequest("missing required parameter")
        return str(value).strip()

    def _bearer_token(self) -> Optional[str]:
        scheme, _, rest = self.headers.get("Authorization", "").partition(" ")
        if scheme.lower() != "bearer":      # RFC 9110: the auth scheme is case-insensitive
            return None
        return rest.strip() or None

    def _read_body(self) -> bytes:
        c = self.collector
        self._body_consumed = True
        if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
            return self._read_chunked()
        raw_length = self.headers.get("Content-Length")
        if raw_length is not None:
            try:
                length = int(raw_length)
            except ValueError:
                raise _BadRequest("invalid Content-Length") from None
            if length < 0:
                raise _BadRequest("invalid Content-Length")
            if length > c.max_body_bytes:
                raise _TooLarge()
            return self.rfile.read(length) if length else b""
        # No Content-Length (chunked/close-delimited): read incrementally,
        # enforcing the cap mid-transfer.
        body = b""
        while True:
            chunk = self.rfile.read(_READ_CHUNK)
            if not chunk:
                break
            body += chunk
            if len(body) > c.max_body_bytes:
                raise _TooLarge()
        return body

    def _read_chunked(self) -> bytes:
        """Decode a Transfer-Encoding: chunked body, enforcing the size cap before buffering each chunk."""
        c = self.collector
        body = bytearray()
        while True:
            line = self.rfile.readline(1024)
            if not line.endswith(b"\n"):
                raise _BadRequest("malformed chunked encoding")
            try:
                size = int(line.split(b";", 1)[0].strip(), 16)
            except ValueError:
                raise _BadRequest("malformed chunk size") from None
            if size < 0:
                raise _BadRequest("malformed chunk size")
            if size == 0:
                while True:                      # discard trailers up to the blank line
                    trailer = self.rfile.readline(1024)
                    if trailer in (b"\r\n", b"\n", b""):
                        return bytes(body)
            if len(body) + size > c.max_body_bytes:
                raise _TooLarge()
            chunk = self.rfile.read(size)
            if len(chunk) != size or self.rfile.read(2) != b"\r\n":
                raise _BadRequest("truncated chunk")
            body += chunk

    def _parse_body(self, body: bytes, format_name: str):
        text = body.decode("utf-8", errors="replace")
        if format_name == "json-array":
            try:
                root = json.loads(text)
            except json.JSONDecodeError as exc:
                raise _BadRequest(f"body is not a JSON array: {exc.msg}") from None
            except (ValueError, RecursionError) as exc:      # >4300-digit int, absurd nesting
                raise _BadRequest(f"body is not parseable JSON ({type(exc).__name__})") from None
            if not isinstance(root, list):
                raise _BadRequest("format=json-array expects a JSON array root")
            return root, []
        # NDJSON (default): a line that fails JSON is counted, not fatal.
        records, errors = [], []
        # NDJSON separates records on \n only; str.splitlines() would also cut at U+2028/U+0085/\x1c-\x1e, all legal
        # unescaped inside a JSON string.
        for lineno, line in enumerate(text.split("\n"), start=1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                errors.append(f"line {lineno}: {exc.msg}")
            except (ValueError, RecursionError) as exc:      # >4300-digit int, absurd nesting: skip the line, keep the batch
                errors.append(f"line {lineno}: unparseable ({type(exc).__name__})")
        return records, errors

    def _send_json(self, status: int, payload: dict) -> None:
        if status >= 400 and not getattr(self, "_body_consumed", True):
            # Answering before the request body was read and then closing makes the kernel send RST, which on some
            # platforms discards the response the client has not read yet (client sees ConnectionAborted instead of 401).
            # Swallow a small declared body first; bigger ones are not worth reading.
            try:
                n = int(self.headers.get("Content-Length") or 0)
                if 0 < n <= 65536:
                    self.rfile.read(n)
            except (ValueError, OSError):
                pass
            self._body_consumed = True
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass  # client went away; counters were recorded before this


# Module scope so concurrent handler threads serialize only the counter block
# (handle_batch aggregates a batch, then bumps once -- one lock per batch).
_COUNTER_LOCK = threading.Lock()


class _BadRequest(Exception):
    pass


class _TooLarge(Exception):
    pass
