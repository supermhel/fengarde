"""StorageAdapter interface (WS-3 Indexer).

The indexer is decoupled from any concrete search backend through this small
interface. Two implementations ship in this package:

* :class:`storage.memory.MemoryStore` -- process-local, used by the contract
  tests so they run with zero infrastructure.
* :class:`storage.opensearch.OpenSearchStore` -- a thin skeleton that builds the
  correct OpenSearch bulk/index requests against ``OPENSEARCH_URL``. It is not
  exercised by the offline tests.

Idempotency
-----------
Delivery on the bus is *at-least-once* (Contract B), so the same document may be
handed to :meth:`StorageAdapter.index` more than once. Implementations MUST be
idempotent on ``doc_id``: indexing the same ``(index, doc_id)`` twice results in
exactly one stored document. ``doc_id`` is the event ``siem.ingest_id`` or the
``alert_id`` -- the router supplies it.
"""
from __future__ import annotations

import abc


class StorageAdapter(abc.ABC):
    """Abstract document sink keyed by ``(index, doc_id)``."""

    @abc.abstractmethod
    def ensure_template(self, name: str, template: dict) -> None:
        """Register an index template / ILM choice (Contract E).

        Called once per logical index family at startup. The in-memory store
        records it; the OpenSearch store PUTs it to ``_index_template``.
        """

    @abc.abstractmethod
    def index(self, index: str, doc_id: str, document: dict) -> bool:
        """Store ``document`` under ``(index, doc_id)``.

        :returns: ``True`` if this call actually wrote a new document,
            ``False`` if it was suppressed as a duplicate (idempotency).
        """

    @abc.abstractmethod
    def count(self, index: str) -> int:
        """Number of distinct documents currently stored in ``index``."""

    @abc.abstractmethod
    def find_alert(self, alert_id: str) -> tuple[str, dict] | None:
        """Locate an alert doc by ``alert_id`` across indices.

        Returns ``(index, doc)`` or ``None``. The triage API holds only an
        ``alert_id``, not the daily index the alert landed in, so it needs a
        cross-index lookup. The default :meth:`find_alert_versioned` builds on
        this, so every adapter must provide it.
        """

    # -- optimistic concurrency (C1 triage read-modify-write) ---------------
    #
    # The triage API mutates an EXISTING alert doc (find -> merge -> write).
    # An in-process lock serializes that within one replica, but two replicas
    # against a shared backend can interleave and silently lose one update.
    # These two hooks close that: ``find_alert_versioned`` returns an opaque
    # ``version`` token alongside the doc, and ``index_cas`` only writes if the
    # doc is still at that version (compare-and-swap), returning ``False`` on
    # a lost race so the caller can re-read and retry.
    #
    # Default implementations degrade to the unversioned behavior (version
    # ``None`` == unconditional write) so a third-party adapter that predates
    # this contract still works -- with the old single-replica guarantee only.

    def find_alert_versioned(self, alert_id: str):
        """Return ``(index, doc, version)`` or ``None`` if not found.

        ``version`` is an opaque token to pass to :meth:`index_cas`; ``None``
        means this adapter cannot version the read (CAS degrades to a plain
        write)."""
        found = self.find_alert(alert_id)
        if found is None:
            return None
        index, doc = found
        return index, doc, None

    def index_cas(self, index: str, doc_id: str, document: dict, version) -> bool:
        """Write ``document`` only if ``(index, doc_id)`` is still at
        ``version``. Returns ``True`` on success, ``False`` on a version
        conflict (someone else wrote in between -- re-read and retry).
        ``version=None`` writes unconditionally (legacy adapters)."""
        self.index(index, doc_id, document)
        return True
