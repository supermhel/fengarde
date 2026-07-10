"""OpenSearch StorageAdapter (skeleton).

Builds the correct HTTP requests against ``OPENSEARCH_URL`` using only the
Python standard library (``urllib``). It is intentionally a thin skeleton: it is
*not* exercised by the offline contract tests (those use :class:`MemoryStore`),
but it constructs the exact requests a real deployment needs.

Idempotency is delegated to OpenSearch: documents are indexed with an explicit
``_id`` (the ``ingest_id`` / ``alert_id``). Re-indexing the same ``_id`` updates
the document in place rather than creating a duplicate, satisfying the
at-least-once contract.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request

from .adapter import StorageAdapter


class OpenSearchStore(StorageAdapter):
    def __init__(self, url: str | None = None, timeout: float = 10.0) -> None:
        self.base = (url or os.getenv("OPENSEARCH_URL", "http://localhost:9200")).rstrip("/")
        self.timeout = timeout

    # -- low-level request helper ------------------------------------------
    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        data = None
        headers = {"Content-Type": "application/json"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base}{path}", data=data, method=method, headers=headers
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
            payload = resp.read().decode("utf-8")
            return json.loads(payload) if payload else {}

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
        result = self._request("PUT", path, document)
        return result.get("result") == "created"

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
