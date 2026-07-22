"""Unit tests for StorageAdapter's DEFAULT method implementations.

MemoryStore/OpenSearchStore override find_alert_versioned/index_cas, so the
abstract base's default bodies (the "legacy adapter that predates the CAS
contract" degradation path, adapter.py) are never exercised by the other
suites. This drives them directly through a minimal adapter that overrides
only the abstract methods and inherits the CAS defaults -- proving the
documented degrade-to-unconditional-write behavior.

Run: python services/ws3-indexer/test_adapter_defaults.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from storage.adapter import StorageAdapter  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


class _LegacyAdapter(StorageAdapter):
    """Implements only the abstract methods -- inherits the CAS/versioning
    defaults, exactly like a third-party adapter written before that contract."""

    def __init__(self):
        self.docs: dict[tuple[str, str], dict] = {}

    def ensure_template(self, name, template):  # pragma: no cover - trivial
        pass

    def index(self, index, doc_id, document):
        key = (index, doc_id)
        new = key not in self.docs
        self.docs[key] = document
        return new

    def count(self, index):  # pragma: no cover - trivial
        return sum(1 for (i, _) in self.docs if i == index)

    def find_alert(self, alert_id):
        for (index, doc_id), doc in self.docs.items():
            if doc_id == alert_id:
                return index, doc
        return None

    def list_alerts(self, *, tenant_id=None, status=None, limit=50):  # pragma: no cover
        return []

    def list_events(self, *, family=None, tenant_id=None, limit=50):  # pragma: no cover
        return []


def test_find_alert_versioned_default_returns_none_version():
    a = _LegacyAdapter()
    a.index("alerts-2026.07.22", "alert-1", {"alert_id": "alert-1"})
    result = a.find_alert_versioned("alert-1")
    check(result is not None, "find_alert_versioned must locate an existing alert")
    index, doc, version = result
    check(index == "alerts-2026.07.22", f"wrong index: {index}")
    check(doc["alert_id"] == "alert-1", f"wrong doc: {doc}")
    check(version is None, "the default (legacy) adapter must report version=None")


def test_find_alert_versioned_default_missing_returns_none():
    a = _LegacyAdapter()
    check(a.find_alert_versioned("nope") is None,
          "a missing alert must return None, not a tuple")


def test_index_cas_default_writes_unconditionally():
    a = _LegacyAdapter()
    ok = a.index_cas("alerts-x", "alert-2", {"alert_id": "alert-2", "v": 1}, version=None)
    check(ok is True, "index_cas with version=None must succeed (unconditional write)")
    check(a.docs[("alerts-x", "alert-2")]["v"] == 1, "document must be written")
    # a second CAS write with any version token still writes (legacy = no real check)
    ok2 = a.index_cas("alerts-x", "alert-2", {"alert_id": "alert-2", "v": 2}, version="ignored")
    check(ok2 is True, "legacy index_cas ignores the version token and writes")
    check(a.docs[("alerts-x", "alert-2")]["v"] == 2, "second write must land")


def main():
    test_find_alert_versioned_default_returns_none_version()
    test_find_alert_versioned_default_missing_returns_none()
    test_index_cas_default_writes_unconditionally()
    if FAILS:
        print(f"[FAIL] adapter defaults: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] StorageAdapter defaults: legacy adapter (CAS methods not overridden) "
          "reports version=None, returns None for a missing alert, and index_cas "
          "degrades to an unconditional write")


if __name__ == "__main__":
    main()
