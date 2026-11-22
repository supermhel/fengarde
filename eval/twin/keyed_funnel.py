"""keyed_funnel -- the ADR-011 gradable-pair funnel and the ADR-012 candidate-link count over the twin.

A reusable form of ``docs/adr/011-measurements/a1.py`` (which stays the manual measurement aid the ADR
quotes; this module imports its ``prep`` / ``pair_flags`` unchanged, so the numbers are the same code).
Run from the repo root (no Docker, no network, ~1 min; seed 7 by default):

    python eval/twin/keyed_funnel.py [--seed 7] [--json OUT.json] [--only NAME[,NAME]]

PRINTS
  * per storyline: raw / F1 / F2 / F3 / F4 / F4w allowed-forbidden pair counts (ADR-011 Measurements 1);
  * the n bar at F4: total gradable pairs, forbidden pairs, storylines contributing, largest share;
  * ADR-012 link measurements read from the RAW payloads (``sysmon_tree``): event-level candidate links
    (spawn / acting_process / cross-step) and the oracle's step-level ``causal_links`` per storyline, with
    the largest per-storyline share.

THE BARS (owner-to-ratify numbers from the ADRs; this module reports against them, it does not ratify):
  ADR-011: n >= 30 gradable pairs, >= 10 forbidden, >= 6 storylines contribute, none > 25 %;
  ADR-012: >= 40 candidate process-tree links, >= 4 storylines, none > 40 %.

Not a ``test_*``: it is a measurement, not a gate (the per-storyline tests are the gates).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MEAS = ROOT / "docs" / "adr" / "011-measurements"
for _p in (str(MEAS), str(ROOT / "eval" / "twin")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import cap  # noqa: E402  (docs/adr/011-measurements/cap.py: puts eval/adversarial, eval/twin, services on sys.path)
import a1  # noqa: E402
import sysmon_tree  # noqa: E402
import yaml  # noqa: E402

BAR_N, BAR_FORBIDDEN, BAR_STORYLINES, BAR_SHARE = 30, 10, 6, 0.25
BAR_LINKS, BAR_LINK_STORYLINES, BAR_LINK_SHARE = 40, 4, 0.40
STAGES = ("F1", "F2", "F3", "F4", "F4w")


def funnel(seed: int = 7, only: set | None = None) -> dict:
    """``{"stories": {name: {...}}, "totals": {...}}`` for the registered storylines."""
    rows = []
    names = []
    for s in cap.reg.ALL:
        if only and s.name not in only:
            continue
        c = cap.capture(s, seed)
        A, gl = a1.prep(c)
        names.append(s.name)
        for rel in A["rels"]:
            r = a1.pair_flags(A, gl, rel)
            r["story"] = s.name
            rows.append(r)
    stories = {}
    for st in names:
        rr = [r for r in rows if r["story"] == st]
        entry = {"raw": [sum(r["allowed"] for r in rr), sum(not r["allowed"] for r in rr)]}
        for k in STAGES:
            entry[k] = [sum(1 for r in rr if r[k] and r["allowed"]), sum(1 for r in rr if r[k] and not r["allowed"])]
        entry["F4_pairs"] = [[r["f"], r["t"], r["allowed"]] for r in rr if r["F4"]]
        stories[st] = entry
    totals = {k: [sum(stories[n][k][0] for n in names), sum(stories[n][k][1] for n in names)] for k in ("raw", *STAGES)}
    return {"seed": seed, "stories": stories, "totals": totals}


def bar_report(fun: dict, stage: str = "F4") -> dict:
    """The ADR-011 bar at ``stage``: totals, contributors and the largest share."""
    per = {n: sum(e[stage]) for n, e in fun["stories"].items()}
    total = sum(per.values())
    contributing = sorted(n for n, v in per.items() if v)
    share = max(per.values()) / total if total else 0.0
    forb = fun["totals"][stage][1]
    return {"stage": stage, "n": total, "forbidden": forb, "contributing": len(contributing),
            "max_share": round(share, 4), "max_share_story": max(per, key=lambda k: per[k]) if per else None,
            "meets": {"n": total >= BAR_N, "forbidden": forb >= BAR_FORBIDDEN,
                      "storylines": len(contributing) >= BAR_STORYLINES, "share": share <= BAR_SHARE}}


def link_measure(seed: int = 7, only: set | None = None) -> dict:
    """ADR-012: candidate process-tree links read from each storyline's RAW payloads, plus the step-level
    ``causal_links`` its oracle declares. Storylines with no Sysmon key fields contribute 0."""
    out = {}
    for s in cap.reg.ALL:
        if only and s.name not in only:
            continue
        payloads = s.build(seed)[0]
        cc = sysmon_tree.candidate_counts(payloads)
        oracle = yaml.safe_load(Path(s.oracle_path).read_text(encoding="utf-8")) or {}
        links = oracle.get("causal_links") or []
        out[s.name] = {
            "candidates_spawn": cc["spawn"], "candidates_acting": cc["acting_process"],
            "candidates_total": cc["spawn"] + cc["acting_process"], "candidates_cross_step": cc["cross_step"],
            "oracle_links": len(links),
            "oracle_links_spawn": sum(1 for lk in links if lk.get("via") == "spawn")}
    return out


def link_bar(links: dict, key: str = "candidates_total") -> dict:
    tot = sum(v[key] for v in links.values())
    keyed = {n: v[key] for n, v in links.items() if v[key]}
    share = max(keyed.values()) / tot if tot else 0.0
    return {"measure": key, "total": tot, "storylines": len(keyed), "max_share": round(share, 4),
            "max_share_story": max(keyed, key=lambda k: keyed[k]) if keyed else None,
            "meets": {"links": tot >= BAR_LINKS, "storylines": len(keyed) >= BAR_LINK_STORYLINES,
                      "share": share <= BAR_LINK_SHARE}}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--json", default=None)
    ap.add_argument("--only", default=None)
    a = ap.parse_args(argv)
    only = set(a.only.split(",")) if a.only else None
    fun = funnel(a.seed, only)
    links = link_measure(a.seed, only)
    print("story | raw A/F | " + " | ".join(STAGES))
    for n, e in fun["stories"].items():
        print(f"{n} | {e['raw'][0]}/{e['raw'][1]} | " + " | ".join(f"{e[k][0]}/{e[k][1]}" for k in STAGES))
    t = fun["totals"]
    print("TOTAL | " + f"{t['raw'][0]}/{t['raw'][1]} | " + " | ".join(f"{t[k][0]}/{t[k][1]}" for k in STAGES))
    print("ADR-011 bar (F4):", json.dumps(bar_report(fun, "F4")))
    print("ADR-011 bar (F3):", json.dumps(bar_report(fun, "F3")))
    for n, v in links.items():
        if v["candidates_total"] or v["oracle_links"]:
            print(f"links {n}: {v}")
    print("ADR-012 candidate links (spawn + acting):", json.dumps(link_bar(links)))
    print("ADR-012 candidate links (spawn only):", json.dumps(link_bar(links, "candidates_spawn")))
    print("ADR-012 oracle step links:", json.dumps(link_bar(links, "oracle_links")))
    if a.json:
        Path(a.json).write_text(json.dumps({"funnel": fun, "links": links}, indent=2, sort_keys=True), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
