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
import time
import urllib.error
import urllib.parse

from .adapter import StorageAdapter

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

    def read(self) -> bytes:
        return self._body


class OpenSearchStore(StorageAdapter):
    def __init__(self, url: str | None = None, timeout: float = 10.0) -> None:
        parsed = urllib.parse.urlsplit(
            url or os.getenv("OPENSEARCH_URL", "http://localhost:9200"))
        self._host = parsed.hostname or "localhost"
        self._port = parsed.port or (443 if parsed.scheme == "https" else 9200)
        self._https = parsed.scheme == "https"
        self.base = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
        self.timeout = timeout
        self._conn: http.client.HTTPConnection | None = None

    def _connection(self) -> http.client.HTTPConnection:
        if self._conn is None:
            cls = http.client.HTTPSConnection if self._https else http.client.HTTPConnection
            self._conn = cls(self._host, self._port, timeout=self.timeout)
        return self._conn

    def _reset_connection(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

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
        for attempt in (0, 1):
            conn = self._connection()
            try:
                conn.request(method, path, body=data, headers=headers)
                resp = conn.getresponse()
                payload = resp.read()
            except (http.client.HTTPException, OSError) as exc:
                self._reset_connection()
                if attempt == 1:
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
        collected in ``errors`` for the caller to inspect/retry."""
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

    def count(self, index: str) -> int:
        try:
            result = self._request("GET", f"/{index}/_count")
        except urllib.error.HTTPError:
            return 0
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
    # against a fake transport (test_storage_cas.py); like the rest of this
    # skeleton module it has not been exercised against a LIVE OpenSearch yet.
    def _search_alert(self, alert_id: str) -> dict | None:
        body = {"size": 1, "query": {"term": {"_id": alert_id}},
                "seq_no_primary_term": True}
        try:
            result = self._request("POST", "/alerts-*/_search", body)
        except urllib.error.HTTPError:
            return None
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
        return hit.get("_index"), hit["_source"]

    # -- v0.4 Track R: cross-index lookup by report_id -----------------------
    def find_report(self, alert_id: str) -> dict | None:
        """Locate a report doc (report_id == f"{alert_id}:report") across all
        daily reports-* indices. Mirrors _search_alert's shape."""
        report_id = f"{alert_id}:report"
        body = {"size": 1, "query": {"term": {"_id": report_id}}}
        try:
            result = self._request("POST", "/reports-*/_search", body)
        except urllib.error.HTTPError:
            return None
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
    # Same "not yet exercised against a live cluster" caveat as the rest of
    # this skeleton module -- the request shape is correct, but the offline
    # contract tests exercise MemoryStore.list_alerts/list_events instead.
    def _list(self, index_pattern: str, term_filters: dict, limit: int) -> list[dict]:
        must = [{"term": {k: v}} for k, v in term_filters.items() if v is not None]
        body = {
            "size": max(1, min(int(limit), 200)),
            "query": {"bool": {"must": must}} if must else {"match_all": {}},
            "sort": [{"time": {"order": "desc", "unmapped_type": "long"}}],
        }
        try:
            result = self._request("POST", f"/{index_pattern}/_search", body)
        except urllib.error.HTTPError:
            return []
        return [hit["_source"] for hit in result.get("hits", {}).get("hits", [])
                if isinstance(hit.get("_source"), dict)]

    def list_alerts(self, *, tenant_id: str | None = None,
                     status: str | None = None, limit: int = 50) -> list[dict]:
        filters = {"tenant_id": tenant_id, "triage.status": status}
        return self._list("alerts-*", filters, limit)

    def list_events(self, *, family: str | None = None, tenant_id: str | None = None,
                     limit: int = 50) -> list[dict]:
        pattern = f"events-{family}*" if family else "events-*"
        filters = {"siem.tenant": tenant_id}
        return self._list(pattern, filters, limit)
