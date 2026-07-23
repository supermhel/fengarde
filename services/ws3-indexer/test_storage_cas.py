"""Optimistic-concurrency (CAS) tests for the WS-3 triage write path.

Closes the multi-replica lost-update window: a process lock can't serialize two
SEPARATE ws3 replicas racing find_alert+index on a shared OpenSearch, so the
adapter now threads OpenSearch's _seq_no/_primary_term through
find_alert_versioned -> index_cas (if_seq_no/if_primary_term; 409 = conflict).

Three layers proven here, zero infra:
1. MemoryStore CAS semantics (real version counter): a stale version is
   rejected, a fresh one wins, and the triage retry loop converges.
2. OpenSearchStore CAS WIRE FORMAT against a fake transport: the search asks
   for seq_no_primary_term, the conditional PUT carries if_seq_no/
   if_primary_term, and an HTTP 409 maps to conflict (False) -- the exact
   requests a live cluster needs, per this module's skeleton discipline.
   (Still not exercised against a LIVE OpenSearch -- same standing caveat as
   the rest of the adapter.)
3. triage_api's bounded retry: a conflicted write re-reads and re-applies on
   the fresh doc (no lost update); permanent conflict surfaces as HTTP 409,
   never a silent drop.

Run: python services/ws3-indexer/test_storage_cas.py
"""
from __future__ import annotations

import io
import json
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from storage.memory import MemoryStore  # noqa: E402
from storage.opensearch import OpenSearchStore  # noqa: E402
import triage_api  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


# --------------------------------------------------------------------------- #
# 1. MemoryStore CAS semantics
# --------------------------------------------------------------------------- #
def test_memory_cas():
    s = MemoryStore()
    s.index("alerts-2026.07.08", "a1", {"alert_id": "a1", "score": 70})

    found = s.find_alert_versioned("a1")
    check(found is not None, "versioned find must locate the alert")
    index, doc, v1 = found
    check(v1 == 1, f"first write should be version 1, got {v1}")

    # a write with the CURRENT version succeeds and bumps the version
    check(s.index_cas(index, "a1", {**doc, "triage": {"status": "triaged"}}, v1) is True,
          "CAS with the current version must succeed")
    # re-using the OLD version must now be rejected (someone else wrote)
    check(s.index_cas(index, "a1", {**doc, "triage": {"status": "closed"}}, v1) is False,
          "CAS with a stale version must be rejected")
    # the rejected write must not have landed
    check(s.find_alert("a1")[1]["triage"]["status"] == "triaged",
          "the stale write must not overwrite the newer document")
    # None version = legacy unconditional write
    check(s.index_cas(index, "a1", {"alert_id": "a1"}, None) is True,
          "version=None must degrade to an unconditional write")


# --------------------------------------------------------------------------- #
# 2. OpenSearchStore CAS wire format (fake transport, no live cluster)
# --------------------------------------------------------------------------- #
class _FakeTransport:
    """Records every request; returns scripted responses / raises scripted
    HTTPErrors, so the adapter's request CONSTRUCTION is what's under test."""

    def __init__(self):
        self.calls: list[tuple[str, str, dict | None]] = []
        self.responses: list = []

    def __call__(self, method, path, body=None):
        self.calls.append((method, path, body))
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def _http_409():
    return urllib.error.HTTPError("http://x", 409, "Conflict", {}, io.BytesIO(b"{}"))


def test_opensearch_cas_wire_format():
    store = OpenSearchStore(url="http://fake:9200")
    fake = _FakeTransport()
    store._request = fake  # patch the transport seam

    # -- versioned find: search body must ask for seq_no_primary_term,
    #    and _seq_no/_primary_term must come back as the version token
    fake.responses = [{"hits": {"hits": [{
        "_index": "alerts-2026.07.08", "_seq_no": 42, "_primary_term": 3,
        "_source": {"alert_id": "a1", "score": 70}}]}}]
    found = store.find_alert_versioned("a1")
    check(found is not None, "versioned find must return the hit")
    index, doc, version = found
    check(version == (42, 3), f"version must be (_seq_no, _primary_term), got {version}")
    _, _, search_body = fake.calls[0]
    check(search_body.get("seq_no_primary_term") is True,
          "the search MUST request seq_no_primary_term or CAS has nothing to compare")

    # -- conditional write: URL must carry if_seq_no/if_primary_term
    fake.responses = [{"result": "updated"}]
    ok = store.index_cas(index, "a1", doc, version)
    check(ok is True, "CAS write with the current version must succeed")
    _, put_path, _ = fake.calls[1]
    check("if_seq_no=42" in put_path and "if_primary_term=3" in put_path,
          f"CAS PUT must carry if_seq_no/if_primary_term, got {put_path}")

    # -- a 409 from the cluster maps to conflict (False), not an exception
    fake.responses = [_http_409()]
    check(store.index_cas(index, "a1", doc, version) is False,
          "HTTP 409 must map to a CAS conflict (False)")

    # -- a non-409 HTTP error must NOT be swallowed as a mere conflict
    fake.responses = [urllib.error.HTTPError("http://x", 500, "boom", {}, io.BytesIO(b"{}"))]
    try:
        store.index_cas(index, "a1", doc, version)
        check(False, "a 500 must propagate, not be silently treated as a conflict")
    except urllib.error.HTTPError:
        pass

    # -- version=None degrades to the plain unconditional PUT (no if_seq_no)
    fake.responses = [{"result": "updated"}]
    store.index_cas(index, "a1", doc, None)
    _, legacy_path, _ = fake.calls[-1]
    check("if_seq_no" not in legacy_path,
          "version=None must fall back to an unconditional write")

    # -- missing _seq_no in the search hit -> version None (degrade, not crash)
    fake.responses = [{"hits": {"hits": [{
        "_index": "alerts-2026.07.08", "_source": {"alert_id": "a1"}}]}}]
    found = store.find_alert_versioned("a1")
    check(found is not None and found[2] is None,
          "a hit without _seq_no/_primary_term must yield version=None")


# --------------------------------------------------------------------------- #
# 3. triage_api bounded retry over CAS conflicts
# --------------------------------------------------------------------------- #
class _ConflictingStore(MemoryStore):
    """Simulates another replica writing between our read and our write for
    the first N attempts (CAS returns False), then lets the write through."""

    def __init__(self, conflicts: int):
        super().__init__()
        self.conflicts_left = conflicts
        self.cas_attempts = 0

    def index_cas(self, index, doc_id, document, version) -> bool:
        self.cas_attempts += 1
        if self.conflicts_left > 0:
            self.conflicts_left -= 1
            # emulate the other replica's interleaved write bumping the version
            found = self.find_alert(doc_id)
            assert found is not None
            super().index(index, doc_id, dict(found[1]))
            return False
        return super().index_cas(index, doc_id, document,
                                 self._versions.get((index, doc_id), 0))


def _serve(store):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), triage_api.make_handler(store))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _post(port, alert_id, body):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/alerts/{alert_id}/triage",
        data=json.dumps(body).encode(), method="POST",
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def test_triage_retry_on_conflict():
    # two conflicts, then success: the retry loop must converge with 200
    store = _ConflictingStore(conflicts=2)
    store.index("alerts-2026.07.08", "a1", {"alert_id": "a1", "score": 70})
    srv, port = _serve(store)
    try:
        code, body = _post(port, "a1", {"status": "triaged"})
        check(code == 200, f"retry loop must converge after transient conflicts, got {code}")
        check(store.cas_attempts == 3, f"expected 3 CAS attempts (2 conflicts + 1 win), "
                                       f"got {store.cas_attempts}")
        check(store.find_alert("a1")[1]["triage"]["status"] == "triaged",
              "the update must have landed after retrying")
    finally:
        srv.shutdown(); srv.server_close()

    # permanent conflict: bounded retries, then an honest 409 -- never a hang
    # or a silently dropped update reported as success
    store2 = _ConflictingStore(conflicts=10_000)
    store2.index("alerts-2026.07.08", "a2", {"alert_id": "a2", "score": 70})
    srv2, port2 = _serve(store2)
    try:
        code, body = _post(port2, "a2", {"status": "closed"})
        check(code == 409, f"exhausted retries must surface as 409 to the client, got {code}")
        check(store2.cas_attempts == triage_api._CAS_MAX_RETRIES,
              f"retries must be bounded at {triage_api._CAS_MAX_RETRIES}, "
              f"got {store2.cas_attempts}")
    finally:
        srv2.shutdown(); srv2.server_close()


def test_concurrent_writers_same_alert_no_lost_update():
    """P2-5 (2026-07-21 audit): triage_api no longer holds a process-wide
    lock across the CAS retry loop (removed -- see triage_api.py's comment on
    why index_cas alone is sufficient). This proves that removal didn't
    reopen the lost-update race: N real threads POSTing concurrently to the
    SAME alert_id, each via a real HTTP request against a real
    ThreadingHTTPServer + MemoryStore, must all either land (200) or get a
    honest 409 to retry -- never a silent drop, and the final version count
    must equal the number of writes that actually won (no double-counted or
    skipped versions)."""
    store = MemoryStore()
    store.index("alerts-2026.07.08", "a3", {"alert_id": "a3", "score": 70})
    srv, port = _serve(store)
    n = 20
    results = []
    results_lock = threading.Lock()

    def worker(i):
        code, body = _post(port, "a3", {"note": f"analyst-{i}"})
        with results_lock:
            results.append(code)

    try:
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        check(len(results) == n, f"expected {n} responses, got {len(results)}")
        check(all(c in (200, 409) for c in results),
              f"every concurrent write must resolve 200 or 409, got {results}")
        wins = results.count(200)
        final_version = store._versions.get(("alerts-2026.07.08", "a3"), 0)
        # version starts at 1 from the initial store.index() seed above; each
        # winning CAS write bumps it by exactly 1.
        check(final_version == 1 + wins,
              f"final version ({final_version}) must equal 1 (initial seed) + the "
              f"number of writes that actually won ({wins}) -- a mismatch means a "
              f"lost or double-applied update slipped through without the old lock")
    finally:
        srv.shutdown(); srv.server_close()


def main():
    test_memory_cas()
    test_opensearch_cas_wire_format()
    test_triage_retry_on_conflict()
    test_concurrent_writers_same_alert_no_lost_update()
    if FAILS:
        print(f"[FAIL] storage CAS: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WS-3 optimistic concurrency: MemoryStore CAS semantics, "
          "OpenSearch CAS wire format (fake transport), triage bounded retry")


if __name__ == "__main__":
    main()
