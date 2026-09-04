"""OpenSearch StorageAdapter.

Builds the correct HTTP requests against ``OPENSEARCH_URL`` using only the
Python standard library (``http.client``/``urllib``). Live-verified against a
real OpenSearch 2.13 cluster (idempotent upsert, real 409 CAS conflict,
transient-retry) via ``storage/test_opensearch_live.py`` (``make test-live``).

Idempotency is delegated to OpenSearch: documents are indexed with an explicit
``_id`` (the ``ingest_id`` / ``alert_id``). Re-indexing the same ``_id`` updates
the document in place rather than creating a duplicate, satisfying the
at-least-once contract.

P1-4 (2026-07-21 audit): two perf fixes, one deliberately NOT attempted here:

  - **Persistent connection** (``_request`` below): every call used to go
    through ``urllib.request.urlopen``, which opens a fresh TCP+HTTP
    connection per call -- no keep-alive reuse across separate calls. Now a
    single ``http.client`` connection is kept open on ``self`` and reused,
    with one transparent reconnect-and-retry if the peer closed it (idle
    keep-alive timeout, cluster restart, etc.) -- this benefits every call
    site, including the daemon's per-message ``index()`` path, without any
    change to callers.
  - **Real ``_bulk`` API** (:meth:`bulk_index`): wired into the batch/tooling
    path (``services/ws3-indexer/main.py``'s ``run()``, used by
    ``tools/integration_e2e.py``/``demo_e2e.py``/tests), which drains a whole
    topic before returning and has no per-message ack semantics to preserve.
  - **NOT attempted: cross-message batching in the live daemon handler**
    (which would also fix the normalized.events/scored.events double-index).
    The daemon acks each message individually right after its handler
    returns (``shared/runner.py``'s ``_process_message``) -- correctness-
    critical for at-least-once redelivery. Batching indexes across MULTIPLE
    messages before acking any of them needs a runner-level redesign (buffer
    N payloads, bulk-index, ack all N together, handle a partial-bulk-
    failure correctly) that this pass does not attempt, to avoid risking the
    completeness guarantee for a perf win. Tracked as future work.
"""
from __future__ import annotations

import http.client
import json
import os
import threading
import time
import urllib.error
import urllib.parse
from typing import TypedDict

from .adapter import StorageAdapter

try:
    from shared.log import get_logger  # noqa: E402
except Exception:  # noqa: BLE001 - standalone/fallback; logging is best-effort
    get_logger = None

_LOG = get_logger("ws3-indexer-storage") if get_logger else None


def _log_rw_warn(msg: str, *args, **kwargs) -> None:
    """Log a read-path warning. Callers pass a %-style ``msg`` + positional
    ``args`` (the stdlib-logging convention) -- shared.log.Logger only takes
    a plain message plus keyword fields (no `.warning()`/positional-args
    method exists on it), so the %-formatting happens here before handing
    off to whichever logger is available.
    """
    formatted = msg % args if args else msg
    if _LOG is not None:
        _LOG.warn(formatted, **kwargs)
    else:  # pragma: no cover - only when shared.log is unavailable
        import logging  # noqa: PLC0415
        logging.getLogger("ws3-indexer-storage").warning(formatted, **kwargs)


def _read_error_is_index_missing(exc: urllib.error.HTTPError) -> bool:
    """Whether a read-path HTTPError is a benign 'index missing' that the
    read methods may swallow into an empty result (matching MemoryStore's
    return-empty-on-no-index), versus a real server failure that MUST NOT be
    silently turned into empty results.

    Gap-hunt (2026-08-26): every read path (_list, count, _search_alert,
    find_report) used to swallow ALL HTTPError -- including 5xx -- into an
    empty/None result with zero logging, so a red/recovering cluster or a
    circuit-breaker trip made GET /alerts answer 200 {alerts:[],count:0} and
    POST /alerts/{id}/triage answer 404 'alert not found'. Only the 4xx
    'index missing' cases are safe to collapse to empty; everything else
    propagates so the caller/dead-letter surface an honest error.
    """
    if exc.code == 404:
        return True  # index genuinely does not exist -> empty set
    if exc.code == 400:
        # OpenSearch raises 400 with index_not_found_exception for a pattern
        # that matches no live (non-aliased-for-search) index in some versions.
        try:
            body = exc.read() or b""
        except Exception:  # noqa: BLE001
            body = b""
        if b"index_not_found" in body or b"IndexNotFoundException" in body:
            return True
    return False

# Bounded retry for a WRITE so a brief OpenSearch blip is absorbed inside one bus
# delivery instead of leaving the message unacked -> eventually dead-lettered.
# Transient = connection error / 5xx; permanent = 4xx (bad mapping/doc) and is
# surfaced immediately (retrying it would just burn redeliveries).
_INDEX_RETRIES = 3
_INDEX_BACKOFF_S = 0.5


class _HTTPError(urllib.error.HTTPError):
    """Constructed locally (no real urlopen call to build one from) when the
    persistent-connection path gets a non-2xx response -- same shape/behavior
    every existing caller already expects from urllib.error.HTTPError (a
    `.code` attribute, raised on 4xx/5xx)."""

    def __init__(self, code: int, msg: str, body: bytes):
        super().__init__(url="", code=code, msg=msg, hdrs=None, fp=None)  # type: ignore[arg-type]
        self._body = body

    def read(self, n: int = -1) -> bytes:
        return self._body


class _Node(TypedDict):
    host: str
    port: int
    https: bool
    base: str


class OpenSearchStore(StorageAdapter):
    def __init__(self, url: str | None = None, timeout: float = 10.0) -> None:
        url_str: str = url or os.getenv("OPENSEARCH_URL") or "http://localhost:9200"
        # FIX H6 (2026-08-06): comma-separated node list for 3-node HA. Single
        # URL => one node => behavior byte-for-byte unchanged (the common
        # single-instance case). Multiple nodes => on any connection-level
        # failure we rotate to the next node, giving the writer real failover
        # instead of pinning to opensearch-1 forever (cluster green, app dead).
        self._nodes: list[_Node] = []
        for part in url_str.split(","):
            part = part.strip()
            if not part:
                continue
            parsed = urllib.parse.urlsplit(part)
            self._nodes.append({
                "host": parsed.hostname or "localhost",
                "port": parsed.port or (443 if parsed.scheme == "https" else 9200),
                "https": parsed.scheme == "https",
                "base": f"{parsed.scheme}://{parsed.netloc}".rstrip("/"),
            })
        if not self._nodes:
            self._nodes.append({
                "host": "localhost", "port": 9200, "https": False,
                "base": "http://localhost:9200",
            })
        self._node_idx = 0
        self.timeout = timeout
        # FIX (2026-08-19, found live under real multi-topic-thread load via
        # tools/fengarde_bench_live.py): this used to be a single shared
        # ``self._conn: http.client.HTTPConnection | None``. ws3-indexer's
        # real daemon (main.py) runs one worker thread PER topic against ONE
        # shared OpenSearchStore instance, and http.client.HTTPConnection is
        # NOT safe for concurrent request/response cycles on one socket --
        # two threads racing .request()/.getresponse() on the SAME
        # connection interleave on the wire and raise
        # ``http.client.ResponseNotReady: Idle``. This never showed up under
        # the low-volume single-feeder-burst traffic every prior live-Docker
        # check used; a sustained multi-thousand-event live-bench run hits
        # it routinely. Fixed with a thread-local connection: each thread
        # gets its OWN socket (see _connection()/_reset_connection_locked()
        # below), while node-selection state (_host/_port/_https/base) stays
        # shared and _node_lock-guarded exactly as before -- only the part
        # that genuinely can't be shared (the raw connection) is now per-thread.
        self._local = threading.local()
        # FIX H6 follow-up (2026-08-06): one OpenSearchStore instance is
        # shared across every topic-consumer thread. Without a lock, two
        # threads hitting a connection failure at the same moment could each
        # read/mutate _node_idx / _host / _port / _https / base concurrently
        # and corrupt which node a request actually goes to (e.g. one thread
        # reads the post-rotation host while another has only half-applied
        # the rotation). This lock guards node-selection bookkeeping; the
        # actual blocking socket I/O in _request()/bulk_index() runs OUTSIDE
        # the lock so concurrent requests aren't needlessly serialized on
        # the network round-trip -- only the bookkeeping around them is atomic.
        self._node_lock = threading.Lock()
        with self._node_lock:
            self._use_current_node()

    def _use_current_node(self) -> None:
        """Point _host/_port/_https/.base at the current node so the rest of
        the class (connection, retry, base-path building) is unchanged.
        Caller must hold self._node_lock."""
        node = self._nodes[self._node_idx]
        self._host = node["host"]
        self._port = node["port"]
        self._https = node["https"]
        self.base = node["base"]

    def _rotate_node(self) -> None:
        """Advance to the next node in the list (round-robin), resetting any
        stale connection so the next request uses the new node. Acquires
        self._node_lock itself -- callers must NOT already hold it."""
        with self._node_lock:
            self._reset_connection_locked()
            if len(self._nodes) > 1:
                self._node_idx = (self._node_idx + 1) % len(self._nodes)
                self._use_current_node()

    def _connection(self) -> http.client.HTTPConnection:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            return conn
        with self._node_lock:
            host, port, https = self._host, self._port, self._https
        cls = http.client.HTTPSConnection if https else http.client.HTTPConnection
        conn = cls(host, port, timeout=self.timeout)
        self._local.conn = conn
        return conn

    def _reset_connection(self) -> None:
        """Acquires self._node_lock itself -- callers must NOT already hold it."""
        with self._node_lock:
            self._reset_connection_locked()

    def _reset_connection_locked(self) -> None:
        """Resets the CALLING thread's own connection (thread-local, see
        __init__'s FIX note) -- held under self._node_lock only for
        consistency with node-selection bookkeeping, not because thread-local
        access itself needs the lock. Caller must hold self._node_lock."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            self._local.conn = None

    # -- low-level request helper ------------------------------------------
    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        """Persistent-connection request (P1-4). One retry on any connection-
        level failure (broken keep-alive, idle-timeout close, etc.) with a
        fresh connection -- covers the common "connection went stale between
        requests" case without the caller needing to know. Genuine transient
        failures (5xx, refused connection on the fresh attempt) still raise,
        same as before, for `index()`'s own retry loop to handle."""
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Content-Type": "application/json"}
        # FIX H6: try each node in the list (single-node list = one attempt
        # round, byte-for-byte prior behavior). A connection-level failure
        # rotates to the next node so the writer keeps working when a node
        # goes down (instead of pinning to opensearch-1 until the app restarts).
        max_attempts = len(self._nodes) * 2  # *2: a full extra lap after every node has been tried once, mirroring P1-4's rebuild
        for attempt in range(max_attempts):
            conn = self._connection()
            try:
                conn.request(method, path, body=data, headers=headers)
                resp = conn.getresponse()
                payload = resp.read()
            except (http.client.HTTPException, OSError) as exc:
                # Connection-level failure -> drop this node and try the next.
                self._rotate_node()
                if attempt == max_attempts - 1:
                    # Wrap as urllib.error.URLError: every existing caller's
                    # retry logic (index()'s `except urllib.error.URLError`)
                    # was written against urlopen()'s exception shape; this
                    # keeps that contract intact now that connections go
                    # through http.client directly instead of urlopen.
                    raise urllib.error.URLError(exc) from exc
                continue
            if resp.status >= 400:
                self._reset_connection() if resp.status >= 500 else None
                raise _HTTPError(resp.status, resp.reason, payload)
            return json.loads(payload) if payload else {}
        raise AssertionError("unreachable")  # pragma: no cover

    # -- P1-4: real NDJSON _bulk API -----------------------------------------
    def bulk_index(self, items: "list[tuple[str, str, dict]]") -> dict:
        """Index many (index, doc_id, document) tuples in ONE request via
        OpenSearch's ``/_bulk`` NDJSON endpoint -- used by the batch/tooling
        path (``run()``), not the live daemon (see module docstring).
        Returns ``{"indexed": n, "errors": [...]}``; a per-item failure
        inside the bulk response does not fail the whole call (matches
        `_bulk`'s own semantics: partial success is normal), but is
        collected in ``errors`` for the caller to inspect/retry.

        **FIX H6 scope note**: unlike ``_request()``/``index()``, a
        connection-level failure here only resets and retries the SAME node
        (``self._reset_connection()``, one retry) -- it does not rotate
        through ``self._nodes`` the way the live-daemon write path does.
        Currently harmless (only the batch/tooling path calls this, never
        ``main.py``'s daemon loop), but multi-node failover is NOT covered
        here if a caller is ever added that needs it."""
        if not items:
            return {"indexed": 0, "errors": []}
        lines = []
        for index, doc_id, document in items:
            action = {"index": {"_index": index, "_id": str(doc_id)}}
            lines.append(json.dumps(action))
            lines.append(json.dumps(document))
        body = ("\n".join(lines) + "\n").encode("utf-8")
        headers = {"Content-Type": "application/x-ndjson"}
        for attempt in (0, 1):
            conn = self._connection()
            try:
                conn.request("POST", "/_bulk", body=body, headers=headers)
                resp = conn.getresponse()
                payload = resp.read()
            except (http.client.HTTPException, OSError) as exc:
                self._reset_connection()
                if attempt == 1:
                    raise urllib.error.URLError(exc) from exc
                continue
            if resp.status >= 500:
                self._reset_connection()
                raise _HTTPError(resp.status, resp.reason, payload)
            if resp.status >= 400:
                raise _HTTPError(resp.status, resp.reason, payload)
            break
        result = json.loads(payload) if payload else {}
        errors = []
        indexed = 0
        # Per-item results IN INPUT ORDER (OpenSearch's bulk API guarantees
        # this) so a caller (run()) can map each result back to the (index,
        # doc_id) it came from -- e.g. to preserve the created-vs-updated
        # distinction index() callers already rely on.
        results = []
        for item in result.get("items", []):
            entry = item.get("index", {})
            status = entry.get("status")
            ok = isinstance(status, int) and status < 400
            if ok:
                indexed += 1
            else:
                errors.append(entry)
            results.append({"_id": entry.get("_id"), "ok": ok,
                            "created": entry.get("result") == "created"})
        return {"indexed": indexed, "errors": errors, "results": results}

    # -- StorageAdapter ----------------------------------------------------
    def ensure_template(self, name: str, template: dict) -> None:
        """PUT an index template (Contract E mapping + ILM choice)."""
        self._request("PUT", f"/_index_template/{name}", template)

    def index(self, index: str, doc_id: str, document: dict) -> bool:
        """Index a document with an explicit ``_id`` (idempotent upsert).

        Using ``op_type=index`` (the default with an explicit id) makes the
        write idempotent: the same id overwrites rather than duplicating.
        Returns ``True`` when OpenSearch reports ``created``.
        """
        path = f"/{index}/_doc/{urllib.parse.quote(doc_id, safe='')}"
        last_exc: BaseException | None = None
        for attempt in range(_INDEX_RETRIES):
            try:
                result = self._request("PUT", path, document)
                return result.get("result") == "created"
            except urllib.error.HTTPError as exc:
                if 400 <= exc.code < 500:
                    raise  # permanent: bad mapping/document, don't retry
                last_exc = exc  # 5xx: server-side transient
            except urllib.error.URLError as exc:
                last_exc = exc  # connection refused / timeout: transient
            if attempt < _INDEX_RETRIES - 1:
                time.sleep(_INDEX_BACKOFF_S * (2 ** attempt))
        assert last_exc is not None
        raise last_exc

    def index_if_absent(self, index: str, doc_id: str, document: dict) -> bool:
        """Create-only write (see StorageAdapter.index_if_absent).

        Uses ``op_type=create``, which OpenSearch rejects with a 409 when the
        document already exists. That 409 is the SUCCESS path for this
        method's contract ("someone already wrote it, leave theirs alone"),
        not an error -- it is what keeps a late normalized-events write from
        clobbering the scored copy. Race-free without a read first: the
        existence check is the write, server-side.

        Every other 4xx still raises, same as :meth:`index` -- a 409 means
        "already present", a 400 means the document itself is bad.
        """
        path = (f"/{index}/_doc/{urllib.parse.quote(doc_id, safe='')}"
                "?op_type=create")
        last_exc: BaseException | None = None
        for attempt in range(_INDEX_RETRIES):
            try:
                result = self._request("PUT", path, document)
                return result.get("result") == "created"
            except urllib.error.HTTPError as exc:
                if exc.code == 409:
                    return False  # already indexed -> suppressed, not an error
                if 400 <= exc.code < 500:
                    raise  # permanent: bad mapping/document, don't retry
                last_exc = exc  # 5xx: server-side transient
            except urllib.error.URLError as exc:
                last_exc = exc  # connection refused / timeout: transient
            if attempt < _INDEX_RETRIES - 1:
                time.sleep(_INDEX_BACKOFF_S * (2 ** attempt))
        assert last_exc is not None
        raise last_exc

    def count(self, index: str) -> int:
        try:
            result = self._request("GET", f"/{index}/_count")
        except urllib.error.HTTPError as exc:
            if _read_error_is_index_missing(exc):
                return 0
            _log_rw_warn("opensearch count %s failed (HTTP %s): %s",
                        index, exc.code, exc.reason)
            raise
        return int(result.get("count", 0))

    # -- C1 triage: cross-index lookup by alert_id --------------------------
    #
    # Multi-replica safety: triage_api.py serializes its read-modify-write with
    # an in-PROCESS lock (correct for one replica), and ALSO threads OpenSearch
    # optimistic concurrency through find_alert_versioned/index_cas below:
    # the search returns _seq_no/_primary_term, the write passes them back as
    # if_seq_no/if_primary_term, and OpenSearch rejects a stale write with 409
    # so the caller re-reads and retries. That closes the cross-replica lost-
    # update window a process lock cannot. The CAS wire format is unit-tested
    # against a fake transport (test_storage_cas.py), and the real 409 is
    # live-verified against an actual cluster by
    # storage/test_opensearch_live.py::_test_cas_conflict_on_stale_version
    # (`make test-live`).
    def _search_alert(self, alert_id: str) -> dict | None:
        # FIX (#12): the same _id can exist in two adjacent daily alerts-*
        # indices (a re-indexed/re-timed alert), and a size-1 search with no
        # sort returns either one arbitrarily. Sort by time desc so the
        # search deterministically returns the NEWEST copy.
        # unmapped_type: a fresh daily index that hasn't taken its first
        # write yet has no mapping for `time` at all -- sorting a wildcard
        # pattern where ANY matching index lacks the sort field 400s with
        # "No mapping found for [time] in order to sort on" (live-caught in
        # CI, 2026-08-27). Same idiom every other cross-index sort in this
        # codebase already uses (see find_report below, _list's sort_field).
        body = {"size": 1, "query": {"term": {"_id": alert_id}},
                "seq_no_primary_term": True,
                "sort": [{"time": {"order": "desc", "unmapped_type": "long"}}]}
        try:
            result = self._request("POST", "/alerts-*/_search", body)
        except urllib.error.HTTPError as exc:
            if _read_error_is_index_missing(exc):
                return None
            _log_rw_warn("opensearch search alert %s failed (HTTP %s): %s",
                        alert_id, exc.code, exc.reason)
            raise
        hits = result.get("hits", {}).get("hits", [])
        if not hits:
            return None
        hit = hits[0]
        source = hit.get("_source")
        if not isinstance(source, dict) or not source:
            # No/empty _source (e.g. _source disabled on the index or a
            # corrupted doc): treat as not found rather than letting a triage
            # update re-index an empty body and wipe the original alert.
            return None
        return hit

    def find_alert(self, alert_id: str) -> tuple[str, dict] | None:
        """Locate an alert doc by id across all daily alerts-* indices via a
        _search with an _id term query (a direct GET needs the exact index
        name, which the client -- only holding alert_id -- doesn't have)."""
        hit = self._search_alert(alert_id)
        if hit is None:
            return None
        index, source = hit.get("_index"), hit["_source"]
        if not isinstance(index, str) or not isinstance(source, dict):
            return None
        return index, source

    def find_events(self, event_ids) -> list[dict]:
        """Bulk cross-index lookup by id across all events-* indices
        (Phase 5, 2026-09-04) via a single `terms` query -- one round trip
        for a whole incident's worth of events, not one GET per id."""
        wanted = list({str(e) for e in event_ids})
        if not wanted:
            return []
        body = {"size": len(wanted), "query": {"terms": {"_id": wanted}}}
        try:
            result = self._request("POST", "/events-*/_search", body)
        except urllib.error.HTTPError as exc:
            if _read_error_is_index_missing(exc):
                return []
            _log_rw_warn("opensearch bulk find events failed (HTTP %s): %s",
                        exc.code, exc.reason)
            raise
        hits = result.get("hits", {}).get("hits", [])
        return [h["_source"] for h in hits if isinstance(h.get("_source"), dict)]

    def _search_by_id_wildcard(self, index_pattern: str, doc_id: str,
                                log_label: str) -> tuple[str, dict] | None:
        """Shared shape for the flat, non-date-suffixed indices added in
        Phase 5 (2026-09-04) -- entities/incident-graphs/entities-{tenant}/
        incident-graphs-{tenant}. No sort needed (unlike _search_alert):
        each is a single canonical doc per id, never re-emitted across a
        rolling day-index, so at most one real hit exists."""
        body = {"size": 1, "query": {"term": {"_id": doc_id}}}
        try:
            result = self._request("POST", f"/{index_pattern}/_search", body)
        except urllib.error.HTTPError as exc:
            if _read_error_is_index_missing(exc):
                return None
            _log_rw_warn(f"opensearch search {log_label} %s failed (HTTP %s): %s",
                        doc_id, exc.code, exc.reason)
            raise
        hits = result.get("hits", {}).get("hits", [])
        if not hits:
            return None
        index, source = hits[0].get("_index"), hits[0].get("_source")
        if not isinstance(index, str) or not isinstance(source, dict) or not source:
            return None
        return index, source

    def find_entity(self, entity_id: str) -> tuple[str, dict] | None:
        """Cross-index lookup across entities*/entities-*-tenant (Phase 5,
        2026-09-04). Wildcard covers both the flat default-tenant "entities"
        index and any "entities-{tenant}" one -- "entities*" matches both."""
        return self._search_by_id_wildcard("entities*", entity_id, "entity")

    def find_incident_graph(self, incident_id: str) -> tuple[str, dict] | None:
        """Cross-index lookup across incident-graphs*/incident-graphs-*-
        tenant (Phase 5, 2026-09-04)."""
        return self._search_by_id_wildcard("incident-graphs*", incident_id, "incident graph")

    def find_incident(self, incident_id: str) -> tuple[str, dict] | None:
        """Locate an incident doc by id across all daily incidents(-tenant)-*
        indices (Phase 5, 2026-09-04). Mirrors _search_alert's shape exactly,
        sorted by `first_seen` desc -- router.py routes a growing incident's
        re-emissions to the SAME day-index keyed off first_seen (stable, not
        `last_seen`), so this should only ever see one real match, but the
        sort keeps the same "newest wins" determinism as find_alert for the
        same reason: never let an ambiguous multi-hit resolve arbitrarily."""
        body = {"size": 1, "query": {"term": {"_id": incident_id}},
                "sort": [{"first_seen": {"order": "desc", "unmapped_type": "long"}}]}
        try:
            result = self._request("POST", "/incidents-*/_search", body)
        except urllib.error.HTTPError as exc:
            if _read_error_is_index_missing(exc):
                return None
            _log_rw_warn("opensearch search incident %s failed (HTTP %s): %s",
                        incident_id, exc.code, exc.reason)
            raise
        hits = result.get("hits", {}).get("hits", [])
        if not hits:
            return None
        hit = hits[0]
        index, source = hit.get("_index"), hit.get("_source")
        if not isinstance(index, str) or not isinstance(source, dict) or not source:
            return None
        return index, source

    # -- v0.4 Track R: cross-index lookup by report_id -----------------------
    def find_report(self, alert_id: str) -> dict | None:
        """Locate a report doc (report_id == f"{alert_id}:report") across all
        daily reports-* indices. Mirrors _search_alert's shape.

        FIX (#4): the report_id is deterministic, but the daily index rolls
        over -- regenerating a report on a later day lands in a newer daily
        index while yesterday's copy still exists. A size-1 search with no
        sort returns either arbitrarily (a stale copy). Sorting generated_at
        desc deterministically returns the NEWEST report."""
        report_id = f"{alert_id}:report"
        # unmapped_type: same cross-index sort gap as _search_alert above --
        # a daily reports-* index with no mapping for `generated_at` yet
        # 400s a wildcard-pattern sort with no fallback type.
        body = {"size": 1, "query": {"term": {"_id": report_id}},
                "sort": [{"generated_at": {"order": "desc", "unmapped_type": "long"}}]}
        try:
            result = self._request("POST", "/reports-*/_search", body)
        except urllib.error.HTTPError as exc:
            if _read_error_is_index_missing(exc):
                return None
            _log_rw_warn("opensearch find report %s failed (HTTP %s): %s",
                        alert_id, exc.code, exc.reason)
            raise
        hits = result.get("hits", {}).get("hits", [])
        if not hits:
            return None
        source = hits[0].get("_source")
        return source if isinstance(source, dict) and source else None

    def find_alert_versioned(self, alert_id: str):
        """(index, doc, version) where version carries OpenSearch's
        (_seq_no, _primary_term) for a CAS write via index_cas. Version is
        None when the cluster didn't return them (then CAS degrades to a
        plain write -- the old single-replica behavior, never worse)."""
        hit = self._search_alert(alert_id)
        if hit is None:
            return None
        seq_no, primary_term = hit.get("_seq_no"), hit.get("_primary_term")
        version = (seq_no, primary_term) \
            if isinstance(seq_no, int) and isinstance(primary_term, int) else None
        return hit.get("_index"), hit["_source"], version

    def get_versioned(self, index: str, doc_id: str):
        """Exact-(index, doc_id) read via a direct GET -- the live-stack race
        fix (2026-08-28, see StorageAdapter.get_versioned's docstring for the
        full account). `find_alert_versioned`'s `_search_alert` goes through
        `/alerts-*/_search`, which only sees documents OpenSearch has
        REFRESHED (default refresh_interval=1s) -- a caller re-reading a doc
        THIS SAME PROCESS just wrote milliseconds ago can get stale (or
        empty) results and lose every CAS retry to state that already
        landed. `GET /{index}/_doc/{id}` reads the live document directly
        (bypasses the search/refresh layer entirely -- OpenSearch's doc GET
        is real-time by default), closing the race whether the concurrent
        writer is this process or another one.
        """
        try:
            result = self._request(
                "GET", f"/{index}/_doc/{urllib.parse.quote(doc_id, safe='')}")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            _log_rw_warn("opensearch get %s/%s failed (HTTP %s): %s",
                        index, doc_id, exc.code, exc.reason)
            raise
        if not result.get("found"):
            return None
        source = result.get("_source")
        if not isinstance(source, dict) or not source:
            return None
        seq_no, primary_term = result.get("_seq_no"), result.get("_primary_term")
        version = (seq_no, primary_term) \
            if isinstance(seq_no, int) and isinstance(primary_term, int) else None
        return source, version

    def index_cas(self, index: str, doc_id: str, document: dict, version) -> bool:
        """Conditional write: only succeeds if the doc is still at `version`
        ((_seq_no, _primary_term) from find_alert_versioned). OpenSearch
        rejects a stale write with HTTP 409 -> return False so the caller
        re-reads and retries. version=None falls back to an unconditional
        write (legacy behavior)."""
        if version is None:
            self.index(index, doc_id, document)
            return True
        seq_no, primary_term = version
        path = (f"/{index}/_doc/{urllib.parse.quote(doc_id, safe='')}"
                f"?if_seq_no={int(seq_no)}&if_primary_term={int(primary_term)}")
        try:
            self._request("PUT", path, document)
        except urllib.error.HTTPError as exc:
            if exc.code == 409:  # version conflict: someone wrote in between
                return False
            raise
        return True

    # -- M4.3 versioned REST API: bounded list/browse -----------------------
    # The offline contract tests exercise MemoryStore.list_alerts/list_events;
    # the OpenSearch request shape is verified against a real cluster by
    # storage/test_opensearch_live.py where relevant (`make test-live`).
    def _list(self, index_pattern: str, term_filters: dict, limit: int,
              sort_field: str = "time",
              default_filters: dict | None = None) -> list[dict]:
        # `default_filters` (e.g. {"tenant_id": "default", "triage.status":
        # "new"}): when a caller asks for the DEFAULT value of a field that
        # MemoryStore materializes (default tenant / initial triage) but
        # OpenSearch may have STORED ABSENT, a bare {term:...} query matches
        # nothing. Emit {bool: {should: [{term}, {bool:{must_not:[{exists}]}}]}}
        # so docs that carry the explicit value OR never had the field both
        # match -- the MemoryStore-equivalent semantics. Gap-hunt (2026-08-26)
        # #WS3-9/#WS6-9.
        default_filters = default_filters or {}
        must: list[dict] = []
        for k, v in term_filters.items():
            if v is None:
                continue
            if k in default_filters and v == default_filters[k]:
                # also match docs that simply never set the field
                clause = {"bool": {"should": [
                    {"term": {k: v}},
                    {"bool": {"must_not": [{"exists": {"field": k}}]}},
                ]}}
            else:
                clause = {"term": {k: v}}
            must.append(clause)
        query = {"bool": {"must": must}} if must else {"match_all": {}}
        body = {
            "size": max(1, min(int(limit), 200)),
            "query": query,
            "sort": [{sort_field: {"order": "desc", "unmapped_type": "long"}}],
        }
        try:
            result = self._request("POST", f"/{index_pattern}/_search", body)
        except urllib.error.HTTPError as exc:
            if _read_error_is_index_missing(exc):
                return []
            _log_rw_warn("opensearch list on %s failed (HTTP %s): %s",
                        index_pattern, exc.code, exc.reason)
            raise
        return [hit["_source"] for hit in result.get("hits", {}).get("hits", [])
                if isinstance(hit.get("_source"), dict)]

    def list_alerts(self, *, tenant_id: str | None = None,
                     status: str | None = None, limit: int = 50,
                     actor: str | None = None, src_ip: str | None = None) -> list[dict]:
        # Design-C (2026-07-29 audit): a full cross-alert correlation engine
        # (rolling risk score per actor/ip across hours-to-days, surfaced as
        # an "incident") is a real, larger design effort -- deferred, see
        # SSOT.md. This is the safe scoped improvement in the meantime: let
        # an analyst manually pull every alert for one actor/source IP,
        # newest-first, across the retention window -- the exact query a
        # human needs to spot a low-and-slow multi-stage attack that stays
        # under any single rule's own threshold, without inventing a new
        # aggregation subsystem or window state.
        filters = {"tenant_id": tenant_id, "triage.status": status,
                  "actor.user.name": actor, "src_endpoint.ip": src_ip}
        return self._list("alerts-*", filters, limit,
                          default_filters={"tenant_id": "default",
                                           "triage.status": "new"})

    def list_incidents(self, *, tenant_id: str | None = None,
                        entity_type: str | None = None, entity_value: str | None = None,
                        limit: int = 50) -> list[dict]:
        filters = {"tenant_id": tenant_id, "entity_type": entity_type,
                   "entity_value": entity_value}
        # Gap-hunt (2026-08-27) #WS3-1 read-plane: MemoryStore.list_incidents
        # materializes the default tenant ("default") for a doc whose
        # tenant_id is ABSENT; OpenSearch may store it absent, so a bare
        # {"term": {"tenant_id":"default"}} matches nothing. Emit the
        # default-filter should-clause so docs that carry the explicit value
        # OR never had the field both match.
        return self._list("incidents-*", filters, limit, sort_field="last_seen",
                          default_filters={"tenant_id": "default"})

    def list_events(self, *, family: str | None = None, tenant_id: str | None = None,
                     limit: int = 50) -> list[dict]:
        pattern = f"events-{family}*" if family else "events-*"
        filters = {"siem.tenant": tenant_id}
        # Same default-tenant materialization parity as list_incidents above
        # (MemoryStore.list_events reads (siem.tenant or "default")); events
        # carry tenant under siem.tenant, not top-level tenant_id.
        return self._list(pattern, filters, limit,
                          default_filters={"siem.tenant": "default"})
