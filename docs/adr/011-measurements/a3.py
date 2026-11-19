import json, statistics
import cap


def pct(xs, p):
    xs = sorted(xs)
    k = max(0, min(len(xs) - 1, int(round(p * (len(xs) - 1)))))
    return xs[k]


def ser(o):
    return len(json.dumps(o, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8"))


today, new, per_story, extra_per_edge, edges_per = [], [], {}, [], []
for s in cap.reg.ALL:
    c = cap.capture(s)
    for g in c["graph_list"]:
        base = {k: v for k, v in g.items()}
        base["edges"] = [{k: v for k, v in e.items() if not k.startswith("_")} for e in g["edges"]]
        grown = dict(base)
        grown["edges"] = [dict(e) for e in base["edges"]]
        for e, src in zip(grown["edges"], g["edges"]):
            e["first_ts_ms"] = src["_first_ts_ms"]; e["last_ts_ms"] = src["_last_ts_ms"]
            e["evidence_count"] = src["_evidence_count"]; e["timed_evidence_count"] = src["_timed_evidence_count"]
        a, b = ser(base), ser(grown)
        today.append(a); new.append(b); edges_per.append(len(base["edges"]))
        per_story.setdefault(s.name, []).append((a, b, len(base["edges"])))
        for e, e2 in zip(base["edges"], grown["edges"]):
            extra_per_edge.append(ser(e2) - ser(e))
n = len(today)
print("incident graphs measured:", n, "across", len(per_story), "storylines (cloud_iam_abuse promotes none)")
f = lambda xs: f"mean={statistics.mean(xs):.1f} p95={pct(xs,0.95)} max={max(xs)}"
print("today bytes :", f(today))
print("with 4 flds :", f(new))
print("delta bytes :", f([b - a for a, b in zip(today, new)]))
print("mean growth %:", round(100 * (statistics.mean(new) / statistics.mean(today) - 1), 1))
print("edges/graph :", f(edges_per))
print("extra bytes per edge: mean=%.1f max=%d min=%d" % (statistics.mean(extra_per_edge), max(extra_per_edge), min(extra_per_edge)))
print("arithmetic worst case at 600 edges (3 x 200-member cap): extra <= %d bytes" % (600 * max(extra_per_edge)))
for k, v in per_story.items():
    print(k, [(a, b, e) for a, b, e in v])
