import sys, json
import cap
out = {}
for s in cap.reg.ALL:
    c = cap.capture(s)
    out[s.name] = [[{k: v for k, v in e.items() if k in ("from","to","kind","event_id","ts_ms") or k in ("_first_ts_ms","_last_ts_ms","_evidence_count","_timed_evidence_count")} for e in g["edges"]] for g in c["graph_list"]]
json.dump(out, open(sys.argv[1], "w"), sort_keys=True)
