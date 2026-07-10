"""In-memory StorageAdapter (default, test-friendly).

Stores documents in a nested dict keyed by ``index -> doc_id -> document``.
Re-indexing the same ``(index, doc_id)`` overwrites the slot but never grows the
count, which is exactly the idempotency guarantee the bus relies on.
"""
from __future__ import annotations

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

    def ensure_template(self, name: str, template: dict) -> None:
        self.templates[name] = template

    def index(self, index: str, doc_id: str, document: dict) -> bool:
        bucket = self._indices.setdefault(index, {})
        is_new = doc_id not in bucket
        bucket[doc_id] = document
        self._versions[(index, doc_id)] = self._versions.get((index, doc_id), 0) + 1
        return is_new

    def count(self, index: str) -> int:
        return len(self._indices.get(index, {}))

    # -- test/inspection helpers -------------------------------------------
    def indices(self) -> list[str]:
        """Names of every index that has received at least one document."""
        return [name for name, docs in self._indices.items() if docs]

    def get(self, index: str, doc_id: str) -> dict | None:
        return self._indices.get(index, {}).get(doc_id)

    def all_docs(self, index: str) -> list[dict]:
        return list(self._indices.get(index, {}).values())

    # -- C1 triage: cross-index lookup by alert_id --------------------------
    def find_alert(self, alert_id: str) -> tuple[str, dict] | None:
        """Locate an alert doc by id across all daily alerts-* indices (the
        client only has alert_id, not which day's index it landed in).
        Returns (index_name, document) or None if not found."""
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
        if version is None:  # legacy unconditional write
            self.index(index, doc_id, document)
            return True
        if self._versions.get((index, doc_id), 0) != version:
            return False  # someone else wrote in between -> caller retries
        self.index(index, doc_id, document)
        return True
