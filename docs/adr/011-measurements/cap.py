"""ADR 011 manual measurement aid (not a test, not run by CI): run the twin pipeline in-process and capture graph inputs. Repo files are not modified; the four proposed edge fields are computed here only."""
import copy, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]  # docs/adr/011-measurements/cap.py -> repo root
for p in (ROOT / "eval/adversarial", ROOT / "eval/twin", ROOT / "services"):
    sys.path.insert(0, str(p))
import mutate_generic as mg  # noqa
import scenario_registry as reg  # noqa
import report  # noqa
import causal_order  # noqa

_state = {}
ws8 = CORR = _orig_build = _orig_grade = None


def _build(self, tenant, entity_type, entity_value, incident, side):
    g = _orig_build(self, tenant, entity_type, entity_value, incident, side)
    # extra fields computed IN THE SCRIPT ONLY, mirroring the ADR definition
    ev = {}  # (f,t) -> list[(mid, time, fallback)]
    for mid, entry in side.items():
        refs = [(entity_type, entity_value)] + list(entry.get("cooccur") or [])
        for i in range(len(refs)):
            for j in range(i + 1, len(refs)):
                spec = ws8._edge_spec(refs[i][0], refs[j][0]) if hasattr(ws8, "_edge_spec") else None
                if spec is None:
                    continue
                kind, ft, tt = spec
                a, b = refs[i], refs[j]
                fv = a[1] if a[0] == ft else b[1]
                tv = b[1] if b[0] == tt else a[1]
                f = ws8.canonical_entity_id(tenant, ft, fv)
                t = ws8.canonical_entity_id(tenant, tt, tv)
                if f is None or t is None:
                    continue
                ev.setdefault((f, t), {})[mid] = (entry.get("time"), bool(entry.get("time_fallback")))
    g2 = copy.deepcopy(g)
    for e in g2["edges"]:
        m = ev.get((e["from"], e["to"]), {})
        times = [t for (t, fb) in m.values() if not fb and isinstance(t, (int, float)) and not isinstance(t, bool)]
        e["_first_ts_ms"] = min(times) if times else None
        e["_last_ts_ms"] = max(times) if times else None
        e["_carriers"] = {k: list(v) for k, v in m.items()}
        e["_evidence_count"] = len(m)
        e["_timed_evidence_count"] = len(times)
    _state.setdefault("graphs", {})[incident["incident_id"]] = g2
    return g


def _grade(graphs, step_entities, rels, step_order, times, items, join_fn):
    _state["args"] = dict(step_entities={k: set(v) for k, v in step_entities.items()}, rels=copy.deepcopy(rels),
                          step_order=list(step_order), times=copy.deepcopy(times), items=copy.deepcopy(items))
    _state["join_fn"] = join_fn
    _state["graphs_in"] = copy.deepcopy(graphs)
    _state["graph_ids"] = [g.get("incident_id") for g in graphs]
    return _orig_grade(graphs, step_entities, rels, step_order, times, items, join_fn)


def _init():
    global ws8, CORR, _orig_build, _orig_grade
    if ws8 is not None:
        return
    reg.run(reg.ALL[0], 7, strict=False)   # warm ws2 import before ws8 path pollution (see report.py trap note)
    ws8 = report._ensure_ws8()
    CORR = ws8.Correlator
    _orig_build = CORR._build_incident_graph_v2
    _orig_grade = causal_order.grade_causal_order
    CORR._build_incident_graph_v2 = _build
    causal_order.grade_causal_order = _grade


def capture(sdef, seed=7, payloads=None):
    _init()
    _state.clear()
    if payloads is None:
        g = reg.grade(sdef, seed, strict=False)
    else:
        def _src(_s, payloads=payloads):
            return payloads, {}, {}, None
        g = reg.grade(sdef, seed, payload_source=_src, strict=False)
    # the Correlator caches the graph; _build may be called many times, keep last per incident id
    out = dict(_state)
    out["grade"] = g
    # graphs exactly as handed to the grader (by incident id), with extras
    out["graph_list"] = [out["graphs"][i] for i in out["graph_ids"] if i in out["graphs"]]
    return out
