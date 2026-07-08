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
    # KNOWN LIMITATION (multi-replica lost update): triage_api.py serializes its
    # find_alert -> merge -> index sequence with an in-PROCESS write lock, which
    # is correct for a single ws3 replica against this backend (and for the
    # default MemoryStore). It does NOT protect against two SEPARATE ws3
    # processes/replicas racing find_alert+index on the same alert_id at
    # OpenSearch -> the later write silently overwrites the earlier one. A real
    # multi-replica deployment must use OpenSearch optimistic concurrency
    # (thread _seq_no/_primary_term from find_alert into the index PUT via
    # if_seq_no/if_primary_term and retry on 409). Not implemented here because
    # this backend is a skeleton (no live OpenSearch in the test env) and
    # multi-replica ws3 is unbuilt (HA is design-only, plan B5). Tracked in
    # SECURITY.md and SSOT.md §2. Single-replica deployments are unaffected.
    def find_alert(self, alert_id: str) -> tuple[str, dict] | None:
        """Locate an alert doc by id across all daily alerts-* indices via a
        _search with an _id term query (a direct GET needs the exact index
        name, which the client -- only holding alert_id -- doesn't have).
        Skeleton, like the rest of this module: not exercised by offline
        tests, but constructs the real request a live deployment needs."""
        body = {"size": 1, "query": {"term": {"_id": alert_id}}}
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
        return hit.get("_index"), source
