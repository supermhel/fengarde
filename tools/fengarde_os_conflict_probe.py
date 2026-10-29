"""Does OpenSearch's node-level ``indexing.index_failed`` count 409 conflicts?

The 2026-10-28 soak ended with index_failed=183 and no failures in the
service logs. WS-3 writes ``normalized.events`` with ``op_type=create`` and
treats HTTP 409 as success, so the suspicion was that the counter is just
those. This probe settles the counter's semantics directly against a scratch
index on the isolated load-test stack: for each write kind it records the HTTP
status OpenSearch returned and the delta of ``index_failed``.

Run:  python tools/fengarde_os_conflict_probe.py --os-port 19200
"""
import argparse
import json
import urllib.error
import urllib.request
import uuid

ap = argparse.ArgumentParser()
ap.add_argument("--os-port", type=int, default=19200)
a = ap.parse_args()
base = f"http://127.0.0.1:{a.os_port}"


def call(method, path, body=None):
    r = urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None,
                               method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def failed():
    n = next(iter(call("GET", "/_nodes/stats/indices")[1]["nodes"].values()))
    return n["indices"]["indexing"]["index_failed"]


idx = f"conflictprobe-{uuid.uuid4().hex[:6]}"
call("PUT", f"/{idx}", {"mappings": {"properties": {"n": {"type": "integer"}}}})
rows = []


def step(name, method, path, body):
    before = failed()
    status, resp = call(method, path, body)
    err = (resp.get("error") or {}).get("type") if isinstance(resp.get("error"), dict) else None
    rows.append({"write": name, "http_status": status, "error_type": err, "index_failed_delta": failed() - before})


step("create new id (op_type=create)", "PUT", f"/{idx}/_doc/a?op_type=create", {"n": 1})
step("create SAME id again (op_type=create)", "PUT", f"/{idx}/_doc/a?op_type=create", {"n": 1})
step("index (upsert) same id", "PUT", f"/{idx}/_doc/a", {"n": 2})
step("index doc violating the mapping", "PUT", f"/{idx}/_doc/b", {"n": "not-a-number"})
before = failed()
nd = "\n".join([json.dumps({"create": {"_index": idx, "_id": "a"}}), json.dumps({"n": 1}),
                json.dumps({"create": {"_index": idx, "_id": "c"}}), json.dumps({"n": 3})]) + "\n"
r = urllib.request.Request(base + "/_bulk", data=nd.encode(), method="POST",
                           headers={"Content-Type": "application/x-ndjson"})
with urllib.request.urlopen(r, timeout=30) as resp:
    items = json.loads(resp.read())["items"]
rows.append({"write": "_bulk create [existing id, new id]", "http_status": [i["create"]["status"] for i in items],
             "error_type": [(i["create"].get("error") or {}).get("type") for i in items],
             "index_failed_delta": failed() - before})
call("DELETE", f"/{idx}")
print(json.dumps(rows, indent=2))
