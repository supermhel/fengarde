"""ADR 011 manual measurement aid: candidate predicate directional_discrimination_timed + order controls."""
import copy, json, sys
import cap
import a1
import order_controls as oc
import mutate_generic as mg


def edge_sets(gl, step, mode):
    """edges (graph idx, edge idx) 'owned' by a step. carrier: step has a timed carrier alert; winner: edge winner attributed to step."""
    out = []
    for gi, g in enumerate(gl):
        for ei, e in enumerate(g["edges"]):
            if e["_timed_evidence_count"] <= 0:
                continue
            if mode == "carrier" and e["_steps"].get(step):
                out.append((gi, ei))
            if mode == "winner" and e["_win_step"] == step:
                out.append((gi, ei))
    return out


def evaluate(c, mode):
    A, gl = a1.prep(c)
    res = []
    for rel in A["rels"]:
        fl = a1.pair_flags(A, gl, rel)
        f, t = rel["from"], rel["to"]
        se = A["step_entities"]
        fs, ts_ = se.get(f, set()), se.get(t, set())
        common = [gi for gi, g in enumerate(gl)
                  if (fs & {n["entity_id"] for n in g["nodes"]}) and (ts_ & {n["entity_id"] for n in g["nodes"]})]
        Ef = [x for x in edge_sets(gl, f, mode) if x[0] in common]
        Et = [x for x in edge_sets(gl, t, mode) if x[0] in common]
        rec = dict(f=f, t=t, allowed=bool(rel.get("allowed")), gradable=False)
        # gradable: F1 + a COMMON graph holds a distinct edge pair (one owned by f, one by t, same graph)
        if fl["F1"] and any(x != y and x[0] == y[0] for x in Ef for y in Et):
            rec["gradable"] = True
            first = lambda S: min(gl[g]["edges"][e]["_first_ts_ms"] for g, e in S)
            last = lambda S: max(gl[g]["edges"][e]["_last_ts_ms"] for g, e in S)
            rec["fwd_strict"] = last(Ef) < first(Et)      # ADR rule: X.last < Y.first
            rec["rev_strict"] = last(Et) < first(Ef)
            rec["fwd_start"] = first(Ef) < first(Et)      # weaker: evidence starts earlier
            rec["rev_start"] = first(Et) < first(Ef)
        res.append(rec)
    return res


def summarise(res):
    out = {}
    for name, fk, rk in (("P1_strict", "fwd_strict", "rev_strict"), ("P2_start", "fwd_start", "rev_start")):
        al = [r for r in res if r["gradable"] and r["allowed"]]
        fo = [r for r in res if r["gradable"] and not r["allowed"]]
        disc = sum(1 for r in al if r[fk] and not r[rk])
        real = sum(1 for r in fo if r[fk])
        conc = sum(1 for r in al if not r[fk] and not r[rk])
        revo = sum(1 for r in al if r[rk] and not r[fk])
        out[name] = dict(n_allowed=len(al), n_forbidden=len(fo), disc=disc, forbidden_realised=real,
                         concurrent=conc, reverse_only=revo)
    return out


def run_variants(sdef, seed=7):
    base_payloads = sdef.build(seed)[0]
    variants = {}
    c = cap.capture(sdef, seed, payloads=copy.deepcopy(base_payloads))
    variants["identity"] = (c, 0)
    ident_grade = c["grade"]
    m, mch = oc.mirror_event_time(base_payloads)
    variants["mirror"] = (cap.capture(sdef, seed, payloads=m), mch)
    pair = oc.pick_swap_pair(sdef, ident_grade, seed=seed, base_payloads=base_payloads)
    if pair:
        sw, sch = oc.swap_adjacent_steps(base_payloads, *pair)
        variants["swap"] = (cap.capture(sdef, seed, payloads=sw), sch)
    sh, shch = mg.apply(base_payloads, "timing", "shift_1h", seed=seed, sdef=sdef)
    variants["shift_1h"] = (cap.capture(sdef, seed, payloads=sh), shch)
    return variants, pair


if __name__ == "__main__":
    allres = {}
    for s in cap.reg.ALL:
        variants, pair = run_variants(s)
        allres[s.name] = {"swap_pair": pair}
        for vname, (c, ch) in variants.items():
            for mode in ("carrier", "winner"):
                res = evaluate(c, mode)
                allres[s.name][f"{vname}/{mode}"] = dict(summary=summarise(res), pairs=res, incidents=len(c["graph_list"]))
    for mode in ("carrier", "winner"):
        for pn in ("P1_strict", "P2_start"):
            print(f"\n=== mode={mode} predicate={pn}: per storyline: gradableA/F, disc(allowed), forbidden_realised")
            tot = {v: [0, 0, 0, 0, 0, 0] for v in ("identity", "mirror", "swap", "shift_1h")}
            for sname, d in allres.items():
                line = [sname.ljust(26), f"swap={d['swap_pair']}"]
                for v in ("identity", "mirror", "swap", "shift_1h"):
                    k = f"{v}/{mode}"
                    if k not in d:
                        line.append(f"{v}: -"); continue
                    sm = d[k]["summary"][pn]
                    line.append(f"{v}: n={sm['n_allowed']}/{sm['n_forbidden']} disc={sm['disc']} fr={sm['forbidden_realised']} inc={d[k]['incidents']}")
                    t = tot[v]; t[0] += sm["n_allowed"]; t[1] += sm["n_forbidden"]; t[2] += sm["disc"]; t[3] += sm["forbidden_realised"]; t[4] += sm["concurrent"]; t[5] += sm["reverse_only"]
                print(" | ".join(line))
            for v, t in tot.items():
                print(f"TOTAL {v}: gradable allowed={t[0]} forbidden={t[1]} disc={t[2]} ({(t[2]/t[0]) if t[0] else None}) forbidden_realised={t[3]} concurrent={t[4]} reverse_only={t[5]}")
