import cap, json, collections
import causal_order as co

rows = []


def prep(c):
    A = c["args"]; gl = c["graph_list"]; gin = c["graphs_in"]
    for g, gi in zip(gl, gin):
        ge = [{k: v for k, v in e.items() if not k.startswith("_")} for e in g["edges"]]
        assert ge == gi["edges"]
    items = A["items"]
    mid2step = {it["alert"].get("alert_id"): it["step"] for it in items}
    for g in gl:
        for e in g["edges"]:
            e["_steps"] = collections.defaultdict(list)
            for mid, (t, fb) in e["_carriers"].items():
                st = mid2step.get(mid)
                if st is not None and not fb and isinstance(t, (int, float)):
                    e["_steps"][st].append(t)
        att = co.attribute_edges([{k: v for k, v in e.items() if not k.startswith("_")} for e in g["edges"]], items)
        for e, a in zip(g["edges"], att):
            e["_win_step"] = a["step"] if a["attributed"] else None
    return A, gl


def pair_flags(A, gl, rel):
    se, times = A["step_entities"], A["times"]
    f, t, allowed = rel["from"], rel["to"], bool(rel.get("allowed"))
    fs, ts_ = se.get(f, set()), se.get(t, set())
    r = dict(f=f, t=t, allowed=allowed)
    r["F1"] = bool(fs and ts_ and f in times and t in times)
    nodes_any = {n["entity_id"] for g in gl for n in g["nodes"]}
    r["F2any"] = bool(fs & nodes_any) and bool(ts_ & nodes_any)
    common = [g for g in gl if (fs & {n["entity_id"] for n in g["nodes"]}) and (ts_ & {n["entity_id"] for n in g["nodes"]})]
    r["F2"] = r["F1"] and bool(common)
    f3 = f4 = f3w = f4w = False
    if r["F2"]:
        for g in common:
            ef = [i for i, e in enumerate(g["edges"]) if e["_steps"].get(f)]
            et = [i for i, e in enumerate(g["edges"]) if e["_steps"].get(t)]
            if ef and et:
                f3 = True
                f4 |= any(i != j for i in ef for j in et)
            wf = [i for i, e in enumerate(g["edges"]) if e["_win_step"] == f and e["_timed_evidence_count"] > 0]
            wt = [i for i, e in enumerate(g["edges"]) if e["_win_step"] == t and e["_timed_evidence_count"] > 0]
            if wf and wt:
                f3w = True
                f4w |= any(i != j for i in wf for j in wt)
    r["F3"], r["F4"], r["F3w"], r["F4w"] = f3, f4, f3w, f4w
    return r


if __name__ == "__main__":
    stories = []
    for s in cap.reg.ALL:
        c = cap.capture(s)
        A, gl = prep(c)
        stories.append(s.name)
        for rel in A["rels"]:
            r = pair_flags(A, gl, rel)
            r["story"] = s.name
            rows.append(r)
    keys = ["F1", "F2any", "F2", "F3", "F4", "F3w", "F4w"]
    print("story | raw A/F | " + " | ".join(keys))
    T = {k: [0, 0] for k in keys}; TR = [0, 0]
    for st in stories:
        rr = [r for r in rows if r["story"] == st]
        ra = sum(r["allowed"] for r in rr); rf = len(rr) - ra
        TR[0] += ra; TR[1] += rf
        out = []
        for k in keys:
            a = sum(1 for r in rr if r[k] and r["allowed"]); f_ = sum(1 for r in rr if r[k] and not r["allowed"])
            T[k][0] += a; T[k][1] += f_
            out.append(f"{a}/{f_}")
        print(st, f"| {ra}/{rf} |", " | ".join(out))
    print("TOTAL", f"| {TR[0]}/{TR[1]} |", " | ".join(f"{T[k][0]}/{T[k][1]}" for k in keys))
