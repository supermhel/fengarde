"""In-memory StorageAdapter (default, test-friendly).

Stores documents in a nested dict keyed by ``index -> doc_id -> document``.
Re-indexing the same ``(index, doc_id)`` overwrites the slot but never grows the
count, which is exactly the idempotency guarantee the bus relies on.
"""
from __future__ import annotations

import threading

from .adapter import StorageAdapter


class MemoryStore(StorageAdapter):
    def __init__(self) -> None:
        # index name -> {doc_id: document}
        self._indices: dict[str, dict[str, dict]] = {}
        # (index, doc_id) -> monotonically increasing write version, backing
        # the optimistic-concurrency hooks (find_alert_versioned/index_cas).
        self._versions: dict[tuple[str, str], int] = {}
        # template name -> template body (for inspection / assertions)
        self.templates: dict[str, dict] = {}
        # H3 (2026-07-29 audit): guards _indices/_versions across index()
        # and index_cas() -- triage_api.py's threaded HTTP server calls both
        # concurrently, and index_cas's check-then-write was previously
        # unsynchronized, so two concurrent CAS writes on the same version
        # could both pass the version check and both report True while one
        # silently overwrote the other. A plain index() interleaving between
        # a CAS's check and write would cause the same lost-update shape, so
        # both methods share this one lock rather than just index_cas.
        self._lock = threading.Lock()

    def ensure_template(self, name: str, template: dict) -> None:
        self.templates[name] = template

    def index(self, index: str, doc_id: str, document: dict) -> bool:
        with self._lock:
            return self._index_locked(index, doc_id, document)

    def _index_locked(self, index: str, doc_id: str, document: dict) -> bool:
        bucket = self._indices.setdefault(index, {})
        is_new = doc_id not in bucket
        bucket[doc_id] = document
        self._versions[(index, doc_id)] = self._versions.get((index, doc_id), 0) + 1
        return is_new

    def index_if_absent(self, index: str, doc_id: str, document: dict) -> bool:
        """Create-only write (see StorageAdapter.index_if_absent).

        The existence check and the write happen under the SAME lock hold --
        a check-then-act split here would reintroduce exactly the race this
        method exists to close.
        """
        with self._lock:
            if doc_id in self._indices.get(index, {}):
                return False
            return self._index_locked(index, doc_id, document)

    def count(self, index: str) -> int:
        with self._lock:
            return len(self._indices.get(index, {}))

    # -- test/inspection helpers -------------------------------------------
    def indices(self) -> list[str]:
        """Names of every index that has received at least one document."""
        with self._lock:
            return [name for name, docs in self._indices.items() if docs]

    def get(self, index: str, doc_id: str) -> dict | None:
        with self._lock:
            return self._indices.get(index, {}).get(doc_id)

    def all_docs(self, index: str) -> list[dict]:
        with self._lock:
            return list(self._indices.get(index, {}).values())

    # -- C1 triage: cross-index lookup by alert_id --------------------------
    def find_alert(self, alert_id: str) -> tuple[str, dict] | None:
        """Locate an alert doc by id across all daily alerts-* indices (the
        client only has alert_id, not which day's index it landed in).
        Returns (index_name, document) or None if not found.

        H3 follow-up: every read here runs under ``self._lock`` -- the same
        lock ``index()``/``index_cas()`` hold -- because a write concurrent
        with this iteration (a new index key via ``setdefault``, or a new
        doc_id key in a bucket) raises ``RuntimeError: dictionary changed
        size during iteration`` in CPython. This is the DEFAULT storage
        backend and is genuinely shared across threads (one bus-consumer
        thread per topic, the triage HTTP server, the webhook dispatcher),
        so this isn't a hypothetical race."""
        with self._lock:
            for index in self._indices:
                if not index.startswith("alerts-"):
                    continue
                doc = self._indices[index].get(alert_id)
                if doc is not None:
                    return index, doc
            return None

    # -- v0.4 Track R: cross-index lookup by report_id -----------------------
    def find_report(self, alert_id: str) -> dict | None:
        """Locate a report doc (report_id == f"{alert_id}:report") across all
        daily reports-* indices. Mirrors find_alert's lookup shape."""
        report_id = f"{alert_id}:report"
        with self._lock:
            for index in self._indices:
                if not index.startswith("reports-"):
                    continue
                doc = self._indices[index].get(report_id)
                if doc is not None:
                    return doc
            return None

    # -- optimistic concurrency (mirrors OpenSearchStore's seq_no CAS) ------
    def find_alert_versioned(self, alert_id: str):
        found = self.find_alert(alert_id)
        if found is None:
            return None
        index, doc = found
        return index, doc, self._versions.get((index, alert_id), 0)

    def index_cas(self, index: str, doc_id: str, document: dict, version) -> bool:
        with self._lock:
            if version is None:  # legacy unconditional write
                self._index_locked(index, doc_id, document)
                return True
            if self._versions.get((index, doc_id), 0) != version:
                return False  # someone else wrote in between -> caller retries
            self._index_locked(index, doc_id, document)
            return True

    # -- M4.3 versioned REST API: bounded list/browse -----------------------
    def list_alerts(self, *, tenant_id: str | None = None,
                     status: str | None = None, limit: int = 50,
                     actor: str | None = None, src_ip: str | None = None) -> list[dict]:
        # Design-C (2026-07-29 audit): actor/src_ip let an analyst manually
        # pull every alert for one actor/source IP across time -- see
        # opensearch.py's list_alerts for the full rationale (the safe scoped
        # improvement in place of a full cross-alert correlation engine).
        docs: list[dict] = []
        with self._lock:
            for index, bucket in self._indices.items():
                if not index.startswith("alerts"):
                    continue
                docs.extend(bucket.values())
        if tenant_id is not None:
            docs = [d for d in docs if (d.get("tenant_id") or "default") == tenant_id]
        if status is not None:
            docs = [d for d in docs if (d.get("triage") or {}).get("status", "new") == status]
        if actor is not None:
            docs = [d for d in docs if (d.get("actor") or {}).get("user", {}).get("name") == actor]
        if src_ip is not None:
            docs = [d for d in docs if (d.get("src_endpoint") or {}).get("ip") == src_ip]
        docs.sort(key=lambda d: d.get("time") or 0, reverse=True)
        return docs[:limit]

    def list_incidents(self, *, tenant_id: str | None = None,
                        entity_type: str | None = None, entity_value: str | None = None,
                        limit: int = 50) -> list[dict]:
        docs: list[dict] = []
        with self._lock:
            for index, bucket in self._indices.items():
                if not index.startswith("incidents"):
                    continue
                docs.extend(bucket.values())
        if tenant_id is not None:
            docs = [d for d in docs if (d.get("tenant_id") or "default") == tenant_id]
        if entity_type is not None:
            docs = [d for d in docs if d.get("entity_type") == entity_type]
        if entity_value is not None:
            docs = [d for d in docs if d.get("entity_value") == entity_value]
        docs.sort(key=lambda d: d.get("last_seen") or 0, reverse=True)
        return docs[:limit]

    def list_events(self, *, family: str | None = None, tenant_id: str | None = None,
                     limit: int = 50) -> list[dict]:
        docs: list[dict] = []
        with self._lock:
            for index, bucket in self._indices.items():
                if not index.startswith("events"):
                    continue
                if family is not None and f"events-{family}" not in index:
                    continue
                docs.extend(bucket.values())
        if tenant_id is not None:
            docs = [d for d in docs if ((d.get("siem") or {}).get("tenant") or "default") == tenant_id]
        docs.sort(key=lambda d: d.get("time") or 0, reverse=True)
        return docs[:limit]
