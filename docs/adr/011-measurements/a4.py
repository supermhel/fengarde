"""Do the four extra edge fields move any graded value? Compare full grade dicts, with vs without the fields."""
import copy, json
import cap

cap._init()
plain_build = cap._orig_build   # un-instrumented original


def with_fields(self, tenant, entity_type, entity_value, incident, side):
    g = cap._build(self, tenant, entity_type, entity_value, incident, side)   # original graph returned
    g2 = cap._state["graphs"][incident["incident_id"]]
    for e, e2 in zip(g["edges"], g2["edges"]):
        e["first_ts_ms"] = e2["_first_ts_ms"]; e["last_ts_ms"] = e2["_last_ts_ms"]
        e["evidence_count"] = e2["_evidence_count"]; e["timed_evidence_count"] = e2["_timed_evidence_count"]
    return g


def diff(a, b, path=""):
    out = []
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b), key=str):
            if k not in a or k not in b:
                out.append(f"{path}/{k}: key only on one side")
            else:
                out += diff(a[k], b[k], f"{path}/{k}")
    elif isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        for i, (x, y) in enumerate(zip(a, b)):
            out += diff(x, y, f"{path}[{i}]")
    elif a != b:
        out.append(f"{path}: {str(a)[:60]} != {str(b)[:60]}")
    return out


tot = 0
for s in cap.reg.ALL:
    cap.CORR._build_incident_graph_v2 = plain_build
    g1 = cap.reg.grade(s, 7, strict=False)
    cap.CORR._build_incident_graph_v2 = with_fields
    g2 = cap.reg.grade(s, 7, strict=False)
    d_all = diff(g1, g2)
    # graph_edges echoes the edges (expected: new keys); assembly_* are wall-clock samples (documented informational)
    d = [x for x in d_all if not x.startswith("/graph_edges") and "assembly_" not in x]
    tot += len(d)
    print(s.name, "differing paths total:", len(d_all), "after excluding edge echo + wall-clock:", len(d), d[:6])
print("TOTAL differing paths", tot)
