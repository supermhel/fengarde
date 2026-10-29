"""Contract test: WS-3 daemon bulk writes (BatchIndexHandler + runner batch path).

Pins the guarantees that made batching the daemon's writes safe to ship:

  * ack ONLY after the bulk result is known (every bulk_write precedes every ack);
  * a partial bulk failure acks the good items and leaves exactly the bad ones
    unacked, per item, in input order;
  * create-only 409 is a success (ack), a 400 is a failure, 429/5xx are retried
    in-process (bounded) and then reported failed;
  * a whole-request failure acks nothing;
  * redelivery of an already-written batch is idempotent (no duplicate docs, the
    scored copy's score is never stripped by a replayed normalized event);
  * alerts are read in bulk (_mget) and written with conditional bulk items,
    repeats collapsed, a stale version falls back to the per-document CAS path
    (analyst triage survives a batch, even one racing the write);
  * delivery_count > max_redeliveries still dead-letters without a write;
  * the runner worker honors batch_max when gathering a read pass.

Zero-infra: a fake store with a ``bulk_write`` that mimics OpenSearch's per-item
status codes, and the in-memory bus. The wire format against a real OpenSearch
(including create-vs-409 and what the node's index_failed counter counts) was
checked live: benchmark/loadtest.md.

Run: python services/ws3-indexer/test_bulk_handler.py
"""
from __future__ import annotations

import copy
import os
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
os.environ.setdefault("BUS_BACKEND", "memory")

from main import BatchIndexHandler, build_handlers  # noqa: E402
from router import route  # noqa: E402
from shared import runner  # noqa: E402
from shared.bus import Message, _MemoryBus  # noqa: E402
from storage.memory import MemoryStore  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


class FakeBulkStore(MemoryStore):
    """MemoryStore + a ``bulk_write`` that mimics OpenSearch per-item results.

    ``script``: optional ``f(call_no, op, doc_id) -> status | None`` to inject
    failures; ``None`` falls through to the real semantics (create on an
    existing id -> 409, otherwise write -> 201/200)."""

    def __init__(self, script=None):
        super().__init__()
        self.script = script
        self.calls: list[list[tuple]] = []
        self.log: list[str] = []

    def mget_versioned(self, keys):
        self.mgets = getattr(self, "mgets", []) + [list(keys)]
        if getattr(self, "mget_down", False):
            raise ConnectionError("mget down")
        return {k: self.get_versioned(*k) for k in keys if self.get_versioned(*k) is not None}

    def bulk_write(self, items):
        self.calls.append(list(items))
        self.log.append("bulk")
        if getattr(self, "down", False):
            raise ConnectionError("opensearch down")
        out = []
        for item in items:
            op, index, doc_id, doc = item[:4]
            version = item[4] if len(item) > 4 else None
            forced = self.script(len(self.calls), op, doc_id) if self.script else None
            if forced is not None:
                out.append({"status": forced, "error_type": "forced"})
                continue
            if version is not None:
                ok = self.index_cas(index, doc_id, doc, version)
                out.append({"status": 200 if ok else 409, "error_type": None if ok else "version_conflict"})
                continue
            if op == "create":
                created = self.index_if_absent(index, doc_id, doc)
                out.append({"status": 201 if created else 409,
                            "error_type": None if created else "version_conflict_engine_exception"})
            else:
                created = self.index(index, doc_id, doc)
                out.append({"status": 201 if created else 200, "error_type": None})
        return out


class RecordingBus:
    """Records ack and produce order against the store's own event log."""

    def __init__(self, log):
        self.log = log
        self.acked: list = []
        self.dead: list = []

    def ack(self, msg, group):
        self.log.append("ack")
        self.acked.append(msg.id)

    def produce(self, topic, key=None, payload=None, **_):
        self.dead.append((topic, payload))


def ev(i, score=None):
    d = {"time": 1_700_000_000_000 + i, "class_uid": 3002, "activity_id": 4,
         "src_endpoint": {"ip": f"203.0.113.{i % 250 + 1}"},
         "siem": {"sector": "common", "ingest_id": f"evt-{i}", "tenant": "default"}}
    if score is not None:
        d["siem"]["score"] = score
    return d


def msgs(payloads, start=0):
    return [Message(topic="t", key=str(i), payload=p, id=f"m{start + i}")
            for i, p in enumerate(payloads)]


def drive(store, handler, payloads, *, max_redeliveries=5, delivered=1):
    bus = RecordingBus(store.log)
    entries = [(m, delivered) for m in msgs(payloads)]
    counts = runner._process_batch(bus, "t", "g", entries, handler, max_redeliveries)
    return bus, counts


def test_ack_only_after_bulk_result():
    store = FakeBulkStore()
    h = BatchIndexHandler(store)
    bus, counts = drive(store, h, [ev(i, 50) for i in range(10)])
    check(counts["acked"] == 10 and counts["failed"] == 0, f"all acked: {counts}")
    check(len(store.calls) == 1 and len(store.calls[0]) == 10, "one bulk request for 10 docs")
    check(store.log[0] == "bulk" and set(store.log[1:]) == {"ack"},
          f"every ack must come after the bulk call: {store.log}")


def test_partial_failure_per_item():
    # 3rd item permanent 400, 5th item 429 forever, rest fine.
    bad_ids = {}

    def script(call_no, op, doc_id):
        if doc_id == bad_ids["perm"]:
            return 400
        if doc_id == bad_ids["throttled"]:
            return 429
        return None

    store = FakeBulkStore(script)
    payloads = [ev(i, 50) for i in range(6)]
    bad_ids["perm"] = route(payloads[2])[1]
    bad_ids["throttled"] = route(payloads[4])[1]
    h = BatchIndexHandler(store, retries=2, backoff_s=0)
    bus, counts = drive(store, h, payloads)
    check(counts == {"acked": 4, "failed": 2, "deadlettered": 0}, f"counts: {counts}")
    check(bus.acked == ["m0", "m1", "m3", "m5"], f"acked exactly the good items: {bus.acked}")
    # the 429 item was retried (initial + 2 retries), the 400 was not
    sent_throttled = sum(1 for c in store.calls for it in c if it[2] == bad_ids["throttled"])
    sent_perm = sum(1 for c in store.calls for it in c if it[2] == bad_ids["perm"])
    check(sent_throttled == 3, f"429 retried twice then given up, sent {sent_throttled}x")
    check(sent_perm == 1, f"permanent 400 not retried, sent {sent_perm}x")
    check(h.stats["failed_items"] == 2, f"stats: {h.stats}")


def test_transient_item_recovers_in_process():
    def script(call_no, op, doc_id):
        return 503 if call_no == 1 else None  # whole first attempt rejected per item

    store = FakeBulkStore(script)
    h = BatchIndexHandler(store, retries=3, backoff_s=0)
    bus, counts = drive(store, h, [ev(i, 50) for i in range(3)])
    check(counts["acked"] == 3, f"transient 503s recovered on retry: {counts}")
    check(len(store.calls) == 2, f"second attempt carried the retries: {len(store.calls)}")


def test_create_only_409_is_success():
    store = FakeBulkStore()
    scored = BatchIndexHandler(store)
    normalized = BatchIndexHandler(store, create_only=True)
    drive(store, scored, [ev(1, 77)])
    bus, counts = drive(store, normalized, [ev(1)])   # same id, no score
    check(counts["acked"] == 1 and counts["failed"] == 0, f"409 on create acked: {counts}")
    doc = store.get(*route(ev(1)))
    check(doc["siem"].get("score") == 77, "late normalized create must not strip the score")
    check(normalized.stats["conflicts_409"] == 1, f"409 counted: {normalized.stats}")


def test_whole_request_failure_acks_nothing():
    store = FakeBulkStore()
    store.down = True
    h = BatchIndexHandler(store, retries=1, backoff_s=0)
    bus, counts = drive(store, h, [ev(i, 50) for i in range(4)])
    check(counts["acked"] == 0 and counts["failed"] == 4, f"nothing acked: {counts}")
    check(bus.acked == [], "no ack when the bulk request itself failed")
    # and a later redelivery after recovery writes everything
    store.down = False
    bus2, counts2 = drive(store, h, [ev(i, 50) for i in range(4)], delivered=2)
    check(counts2["acked"] == 4, f"redelivery after recovery acks all: {counts2}")


def test_redelivery_is_idempotent():
    store = FakeBulkStore()
    h = BatchIndexHandler(store)
    payloads = [ev(i, 60) for i in range(8)]
    drive(store, h, payloads)
    n1 = sum(1 for k in store._docs) if hasattr(store, "_docs") else None
    drive(store, h, payloads, delivered=2)          # at-least-once replay
    docs = [store.get(*route(p)) for p in payloads]
    check(all(d is not None and d["siem"]["score"] == 60 for d in docs), "docs intact after replay")
    if n1 is not None:
        check(sum(1 for k in store._docs) == n1, "replay created no extra documents")
    # a replayed normalized batch after the scored one must not strip scores
    nrm = BatchIndexHandler(store, create_only=True)
    drive(store, nrm, [ev(i) for i in range(8)])
    check(all(store.get(*route(p))["siem"]["score"] == 60 for p in payloads),
          "replayed create-only normalized batch stripped a score")


def _alert(i=1, n=0):
    return {"alert_id": f"a-{i}", "time": 1_700_000_000_000 + n, "rule_id": "r", "level": "high",
            "siem": {"sector": "common", "tenant": "default"}, "src_endpoint": {"ip": "203.0.113.9"}}


def test_alert_batch_preserves_triage_and_collapses_repeats():
    store = FakeBulkStore()
    h = BatchIndexHandler(store)
    drive(store, h, [_alert(1)])                       # brand-new id -> per-document create path
    idx, did = route(_alert(1))
    stored = store.get(idx, did)
    stored["triage"] = {"status": "investigating", "by": "analyst"}   # analyst wrote triage
    store.index(idx, did, stored)
    store.calls.clear()
    store.mgets = []
    # a burst: the same alert_id three times plus another event, one batch
    bus, counts = drive(store, h, [_alert(1, 1), _alert(1, 2), _alert(1, 3), ev(5, 40)])
    check(counts["acked"] == 4 and counts["failed"] == 0, f"all four acked: {counts}")
    doc = store.get(idx, did)
    check(doc.get("triage", {}).get("status") == "investigating", "batched alert update clobbered analyst triage")
    check(doc["time"] == 1_700_000_000_003, "end state is the LAST payload of the burst")
    check(len(store.mgets) == 1 and len(store.mgets[0]) == 1, f"one mget, repeats collapsed: {store.mgets}")
    sent = [it for c in store.calls for it in c]
    alert_items = [it for it in sent if it[3].get("alert_id")]
    check(len(alert_items) == 1 and alert_items[0][4] is not None,
          f"one conditional (versioned) bulk item for the burst: {alert_items}")


def test_alert_stale_version_falls_back_to_cas_and_keeps_triage():
    store = FakeBulkStore()
    h = BatchIndexHandler(store)
    drive(store, h, [_alert(2)])
    idx, did = route(_alert(2))
    real_mget = store.mget_versioned

    def racing_mget(keys):
        out = real_mget(keys)
        # between the read and the bulk write an analyst triages the alert
        doc = store.get(idx, did)
        doc["triage"] = {"status": "closed", "by": "analyst"}
        store.index(idx, did, doc)
        return out

    store.mget_versioned = racing_mget
    bus, counts = drive(store, h, [_alert(2, 9)])
    check(counts["acked"] == 1, f"acked after CAS fallback: {counts}")
    check(h.stats["cas_conflicts"] == 1, f"stale version counted: {h.stats}")
    doc = store.get(idx, did)
    check(doc.get("triage", {}).get("status") == "closed" and doc["time"] == 1_700_000_000_009,
          "analyst triage written during the race must survive and the new alert data must land")


def test_alert_read_failure_leaves_unacked():
    store = FakeBulkStore()
    store.mget_down = True
    bus, counts = drive(store, BatchIndexHandler(store), [_alert(3), ev(1, 10)])
    check(counts == {"acked": 1, "failed": 1, "deadlettered": 0},
          f"alert unacked when its read failed, event still acked: {counts}")


def _incident(version, i=1):
    return {"incident_id": f"inc-{i}", "time": 1_700_000_000_000, "version": version,
            "siem": {"sector": "common", "tenant": "default"}}


def test_same_id_versions_coalesce_and_retry_never_overwrites_newer():
    """Review finding: v1 429, v2 ok, retry wrote v1 over v2 and both were acked."""
    seen: list = []

    def script(call_no, op, doc_id):
        seen.append(call_no)
        return None

    store = FakeBulkStore(script)
    h = BatchIndexHandler(store, retries=3, backoff_s=0)
    bus, counts = drive(store, h, [_incident(1), _incident(2), _incident(3)])
    idx, did = route(_incident(1))
    sent = [it for c in store.calls for it in c]
    check(counts["acked"] == 3, f"all three messages acked: {counts}")
    check(len(sent) == 1, f"one bulk item for one id, got {len(sent)}")
    check(store.get(idx, did)["version"] == 3, "the last version is what is stored")

    # the exact review scenario: the item for the id is throttled once, then ok
    flaky = {"n": 0}

    def throttle_first(call_no, op, doc_id):
        flaky["n"] += 1
        return 429 if flaky["n"] == 1 else None

    store2 = FakeBulkStore(throttle_first)
    h2 = BatchIndexHandler(store2, retries=3, backoff_s=0)
    drive(store2, h2, [_incident(1), _incident(2)])
    check(store2.get(idx, did)["version"] == 2, "a retried item must not leave an older version stored")
    # and different ids in one batch are untouched by coalescing
    store3 = FakeBulkStore()
    drive(store3, BatchIndexHandler(store3), [_incident(1, 1), _incident(1, 2)])
    check(len([it for c in store3.calls for it in c]) == 2, "distinct ids are not merged")


def test_stale_cas_fallback_does_not_resurrect_cleared_triage():
    store = FakeBulkStore()
    h = BatchIndexHandler(store)
    drive(store, h, [_alert(7)])
    idx, did = route(_alert(7))
    doc = store.get(idx, did)
    doc["triage"] = {"status": "investigating", "by": "analyst"}
    store.index(idx, did, doc)
    real_mget = store.mget_versioned

    def racing_mget(keys):
        out = real_mget(keys)           # we have read the triage... (MemoryStore hands out live
        out = {k: (copy.deepcopy(d), v) for k, (d, v) in out.items()}   # references: snapshot it)
        cur = store.get(idx, did)
        cur.pop("triage", None)         # ...then the analyst clears it before our write
        store.index(idx, did, cur)
        return out

    store.mget_versioned = racing_mget
    bus, counts = drive(store, h, [_alert(7, 5)])
    check(counts["acked"] == 1 and h.stats["cas_conflicts"] == 1, f"{counts} {h.stats}")
    check("triage" not in store.get(idx, did), "a triage cleared during the race must stay cleared")
    check(store.get(idx, did)["time"] == 1_700_000_000_005, "the new alert data still lands")


class _AlwaysStaleStore(FakeBulkStore):
    def index_cas(self, index, doc_id, document, version):
        return False if version is not None else super().index_cas(index, doc_id, document, version)


def test_exhausted_alert_cas_is_not_acked():
    store = _AlwaysStaleStore()
    h = BatchIndexHandler(store, backoff_s=0)
    import main as ws3_main
    saved = ws3_main._ALERT_CAS_MAX_RETRIES
    ws3_main._ALERT_CAS_MAX_RETRIES = 2
    try:
        drive(store, h, [_alert(9)])                                   # create path (version None) works
        bus, counts = drive(store, h, [_alert(9, 3), ev(2, 20)])      # update path always loses the CAS
        check(counts == {"acked": 1, "failed": 1, "deadlettered": 0},
              f"exhausted CAS is unacked, the event beside it acked: {counts}")
        check(bus.acked == ["m1"], f"only the event was acked: {bus.acked}")
        raised = False
        try:
            h(_alert(9, 4))                                            # per-document daemon path
        except Exception as exc:  # noqa: BLE001
            raised = type(exc).__name__ == "AlertCasExhausted"
        check(raised, "per-document daemon handler must raise, not ack, on exhausted CAS")
        # the batch/tooling path keeps its documented no-raise behavior
        check(ws3_main.index_doc(store, _alert(9, 6)) is False, "run()-path index_doc still returns False")
    finally:
        ws3_main._ALERT_CAS_MAX_RETRIES = saved


def test_unroutable_dropped_and_dead_letter_cap():
    store = FakeBulkStore()
    h = BatchIndexHandler(store)
    bus, counts = drive(store, h, [{"no": "route"}, ev(1, 10)])
    check(counts["acked"] == 2, f"unroutable doc acked (dropped): {counts}")
    store2 = FakeBulkStore()
    bus2, counts2 = drive(store2, BatchIndexHandler(store2), [ev(1, 10)], max_redeliveries=5, delivered=6)
    check(counts2["deadlettered"] == 1 and store2.calls == [], f"exhausted -> DLQ, no write: {counts2}")
    check(bus2.dead and bus2.dead[0][0] == "t.deadletter", "dead-letter produced")


def test_worker_respects_batch_max():
    bus = _MemoryBus()
    sizes: list[int] = []

    class H:
        batch_max = 3

        def __call__(self, p):  # pragma: no cover - batch path expected
            raise AssertionError("single path used")

        def handle_batch(self, payloads):
            sizes.append(len(payloads))
            return [None] * len(payloads)

    for i in range(7):
        bus.produce("t", key=str(i), payload={"i": i})
    shutdown = threading.Event()
    t = threading.Thread(target=runner._topic_worker, daemon=True, args=(lambda: bus, "t", "g", H()),
                         kwargs=dict(max_redeliveries=5, shutdown=shutdown, claim_idle_ms=60000,
                                     idle_sleep_s=0.01, consume_block_ms=10, service_name="x"))
    t.start()
    deadline = time.time() + 5
    while sum(sizes) < 7 and time.time() < deadline:
        time.sleep(0.02)
    shutdown.set()
    t.join(timeout=3)
    check(sum(sizes) == 7 and max(sizes) <= 3, f"batch sizes bounded by batch_max=3: {sizes}")


def test_bus_error_mid_pass_does_not_strand_gathered_batch():
    """Review item: messages gathered for a batch before a bus error used to be
    dropped unprocessed (waiting out the 60 s claim window)."""
    handled: list = []
    acked: list = []

    class H:
        batch_max = 100

        def handle_batch(self, payloads):
            handled.extend(p["i"] for p in payloads)
            return [None] * len(payloads)

    class FlakyBus:
        def __init__(self):
            self.n = 0

        def claim_pending(self, *a, **k):
            return iter(())

        def consume(self, topic, group=None, block_ms=0):
            self.n += 1
            if self.n == 1:
                for i in range(3):
                    yield Message(topic=topic, key=str(i), payload={"i": i}, id=f"m{i}")
                raise ConnectionError("redis went away mid-read")
            return

        def ack_batch(self, msgs, group):
            acked.extend(m.id for m in msgs)

        def produce(self, *a, **k):
            pass

    bus = FlakyBus()
    shutdown = threading.Event()
    t = threading.Thread(target=runner._topic_worker, daemon=True, args=(lambda: bus, "t", "g", H()),
                         kwargs=dict(max_redeliveries=5, shutdown=shutdown, claim_idle_ms=60000,
                                     idle_sleep_s=0.01, consume_block_ms=10, service_name="x"))
    t.start()
    deadline = time.time() + 5
    while len(handled) < 3 and time.time() < deadline:
        time.sleep(0.02)
    shutdown.set()
    t.join(timeout=3)
    check(sorted(handled) == [0, 1, 2], f"messages gathered before the bus error were processed: {handled}")
    check(sorted(acked) == ["m0", "m1", "m2"], f"and acked: {acked}")


def test_build_handlers_wiring_and_kill_switch():
    store = FakeBulkStore()
    hs = build_handlers(store)
    check(all(callable(getattr(h, "handle_batch", None)) for _, h in hs.values()),
          "every topic handler is batch-capable when the store has bulk_write")
    check(hs["normalized.events"][1].create_only and not hs["scored.events"][1].create_only,
          "only normalized.events is create-only")
    os.environ["WS3_BULK"] = "0"
    try:
        off = build_handlers(store)
    finally:
        del os.environ["WS3_BULK"]
    check(all(getattr(h, "handle_batch", None) is None for _, h in off.values()),
          "WS3_BULK=0 removes batching")
    off["scored.events"][1](ev(3, 33))
    check(store.calls == [] and store.get(*route(ev(3)))["siem"]["score"] == 33,
          "kill switch still writes, per document")
    plain = build_handlers(MemoryStore())
    check(all(getattr(h, "handle_batch", None) is None for _, h in plain.values()),
          "MemoryStore (no bulk_write) stays on the per-document path")


def test_opensearch_bulk_write_wire_format():
    """bulk_write: NDJSON with a create/index action per item, per-item status
    mapped back in input order, whole-request HTTP errors raised."""
    import json
    from storage.opensearch import OpenSearchStore

    class Resp:
        def __init__(self, status, body):
            self.status, self.reason, self._b = status, "x", json.dumps(body).encode()

        def read(self):
            return self._b

    class Conn:
        def __init__(self, resp):
            self.resp, self.reqs = resp, []

        def request(self, method, path, body=None, headers=None):
            self.reqs.append((method, path, body, headers))

        def getresponse(self):
            return self.resp

    os_store = OpenSearchStore(url="http://fake:9200")
    conn = Conn(Resp(200, {"errors": True, "items": [
        {"create": {"_id": "a", "status": 201}},
        {"create": {"_id": "b", "status": 409,
                    "error": {"type": "version_conflict_engine_exception"}}},
        {"index": {"_id": "c", "status": 429, "error": {"type": "es_rejected_execution_exception"}}},
    ]}))
    os_store._connection = lambda: conn
    out = os_store.bulk_write([("create", "events-x", "a", {"n": 1}),
                               ("create", "events-x", "b", {"n": 2}),
                               ("index", "events-x", "c", {"n": 3})])
    check([o["status"] for o in out] == [201, 409, 429], f"statuses in input order: {out}")
    check(out[1]["error_type"] == "version_conflict_engine_exception", "error type surfaced")
    method, path, body, headers = conn.reqs[0]
    lines = body.decode().strip("\n").split("\n")
    check(method == "POST" and path == "/_bulk" and len(conn.reqs) == 1, "one POST /_bulk")
    check(headers["Content-Type"] == "application/x-ndjson", "ndjson content type")
    check(json.loads(lines[0]) == {"create": {"_index": "events-x", "_id": "a"}}, f"create action: {lines[0]}")
    check(json.loads(lines[4]) == {"index": {"_index": "events-x", "_id": "c"}}, f"index action: {lines[4]}")
    # versioned item -> conditional bulk action; mget_versioned parses _seq_no/_primary_term
    conn_cas = Conn(Resp(200, {"items": [{"index": {"_id": "a", "status": 409,
                                                    "error": {"type": "version_conflict_engine_exception"}}}]}))
    os_store._connection = lambda: conn_cas
    out = os_store.bulk_write([("index", "alerts-x", "a", {"n": 1}, (7, 2))])
    action = json.loads(conn_cas.reqs[0][2].decode().split("\n")[0])
    check(action == {"index": {"_index": "alerts-x", "_id": "a", "if_seq_no": 7, "if_primary_term": 2}},
          f"CAS bulk action: {action}")
    check(out[0]["status"] == 409, "stale CAS item reported as 409")
    conn_mg = Conn(Resp(200, {"docs": [
        {"_index": "alerts-x", "_id": "a", "found": True, "_seq_no": 3, "_primary_term": 1, "_source": {"k": 1}},
        {"_index": "alerts-x", "_id": "b", "found": False}]}))
    os_store._connection = lambda: conn_mg
    got = os_store.mget_versioned([("alerts-x", "a"), ("alerts-x", "b")])
    check(got == {("alerts-x", "a"): ({"k": 1}, (3, 1))}, f"mget_versioned: {got}")
    check(conn_mg.reqs[0][0:2] == ("POST", "/_mget"), f"one POST /_mget: {conn_mg.reqs[0][0:2]}")
    # request-level failure raises (caller leaves the whole batch unacked)
    os_store._connection = lambda: Conn(Resp(503, {}))
    raised = False
    try:
        os_store.bulk_write([("index", "events-x", "a", {"n": 1})])
    except Exception:
        raised = True
    check(raised, "HTTP 503 for the whole request must raise")
    # response shorter than the request is a protocol error, not silent success
    os_store._connection = lambda: Conn(Resp(200, {"items": []}))
    raised = False
    try:
        os_store.bulk_write([("index", "events-x", "a", {"n": 1})])
    except RuntimeError:
        raised = True
    check(raised, "item-count mismatch must raise")


def main() -> int:
    for fn in (test_ack_only_after_bulk_result, test_partial_failure_per_item,
               test_transient_item_recovers_in_process, test_create_only_409_is_success,
               test_whole_request_failure_acks_nothing, test_redelivery_is_idempotent,
               test_alert_batch_preserves_triage_and_collapses_repeats,
               test_alert_stale_version_falls_back_to_cas_and_keeps_triage,
               test_alert_read_failure_leaves_unacked,
               test_same_id_versions_coalesce_and_retry_never_overwrites_newer,
               test_stale_cas_fallback_does_not_resurrect_cleared_triage,
               test_exhausted_alert_cas_is_not_acked, test_unroutable_dropped_and_dead_letter_cap,
               test_worker_respects_batch_max, test_bus_error_mid_pass_does_not_strand_gathered_batch,
               test_build_handlers_wiring_and_kill_switch,
               test_opensearch_bulk_write_wire_format):
        before = len(FAILS)
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            FAILS.append(f"{fn.__name__} raised {type(exc).__name__}: {exc}")
        print(f"{'FAIL' if len(FAILS) > before else 'PASS'}: {fn.__name__}")
    if FAILS:
        print("\nFAILURES:")
        for f in FAILS:
            print(" -", f)
        return 1
    print("\nbulk handler contract test OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
