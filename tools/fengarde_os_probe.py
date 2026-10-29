"""OpenSearch ceiling probe for the live load test (benchmark/loadtest.md).

Separates "OpenSearch is slow" from "ws3-indexer's one-doc-per-request path
is slow": writes docs to a scratch index with (a) serial single-doc PUTs on
a fresh connection each (what ws3's daemon does), (b) serial PUTs on one
keep-alive connection, (c) _bulk of 500. Reports docs/s for each, then
deletes the scratch index. Run against the isolated load-test stack only.

Run:  python tools/fengarde_os_probe.py --os-port 19200
"""
import argparse
import http.client
import json
import time
import urllib.request
import uuid

ap = argparse.ArgumentParser()
ap.add_argument("--os-port", type=int, default=19200)
ap.add_argument("--n", type=int, default=600)
a = ap.parse_args()
base = f"http://127.0.0.1:{a.os_port}"
idx = f"loadprobe-{uuid.uuid4().hex[:6]}"
def doc(i):
    return {"class_uid": 3002, "time": int(time.time() * 1000), "msg": "x" * 300, "n": i}



def req(method, path, body=None):
    r = urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None,
                               method=method, headers={"Content-Type": "application/json"})
    return urllib.request.urlopen(r, timeout=30).read()


req("PUT", f"/{idx}", {"settings": {"number_of_shards": 1, "number_of_replicas": 1}})
out = {}
t = time.perf_counter()
for i in range(a.n):
    req("PUT", f"/{idx}/_doc/a{i}", doc(i))
out["serial_fresh_conn_docs_per_s"] = round(a.n / (time.perf_counter() - t), 1)
c = http.client.HTTPConnection("127.0.0.1", a.os_port)
t = time.perf_counter()
for i in range(a.n):
    c.request("PUT", f"/{idx}/_doc/b{i}", json.dumps(doc(i)), {"Content-Type": "application/json"})
    c.getresponse().read()
out["serial_keepalive_docs_per_s"] = round(a.n / (time.perf_counter() - t), 1)
t = time.perf_counter()
tot = 0
for k in range(6):
    lines = []
    for i in range(500):
        lines += [json.dumps({"index": {"_id": f"c{k}-{i}"}}), json.dumps(doc(i))]
    c.request("POST", f"/{idx}/_bulk", "\n".join(lines) + "\n", {"Content-Type": "application/x-ndjson"})
    c.getresponse().read(); tot += 500
out["bulk500_docs_per_s"] = round(tot / (time.perf_counter() - t), 1)
req("DELETE", f"/{idx}")
print(json.dumps(out))
