"""Blind-recall lane: score FENGARDE against third-party ATT&CK labels.

evtx_eval.py / splunk_eval.py compare the engine to a SELF-WRITTEN oracle
(rule logic recomputed from raw records) and throw the dataset's technique
label away. This lane does the opposite: the label comes from the dataset
author (Splunk YAML ``mitre_technique``, EVTX-to-MITRE-Attack folder name) and
the question is "did any rule in that technique's family fire?".

Read eval/detection_accuracy/README.md ("Blind-recall lane") before quoting any
number from here. In short: labels are per DATASET not per event; there is no
benign corpus so no false-positive rate; most corpus techniques have no
FENGARDE rule at all and are reported as NO_RULE, never dropped and never
counted as passes; a MISS can mean the rule was never designed for that
procedure.

Run (after ``python eval/detection_accuracy/fetch_corpora.py``):
    python eval/detection_accuracy/blind_recall.py [--require-corpus]
Zero fetched data => ``[SKIP]`` and rc 0, exactly like evtx_eval.py; with
``--require-corpus`` zero fetched data, or no dataset in a scoreable bucket
(parser AND rule), is rc 1 so a nightly cannot go green on nothing.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import corpus_adapters as CA  # noqa: E402
import technique_match as TM  # noqa: E402

DEFAULT_RULES_DIR = REPO / "contracts" / "rules"
DEFAULT_OUT = HERE / "blind_recall_results.json"
SCHEMA = "1"
_NOT_DENOMINATOR = ("NOT_FETCHED", "READER_UNAVAILABLE")


# ---------------------------------------------------------------- replay

def replay(records: list, rules_dir: Path):
    """WS-2 -> WS-4 on a fresh memory bus and a fresh Detector pointed at
    ``rules_dir`` (evtx_eval.replay_file hard-codes the default rules, so this
    lane carries its own small replay and leaves that module untouched).
    Returns (normalized_count, alerts)."""
    import time
    import uuid
    E = CA._evtx_module()
    bus = E.Bus()
    now_ms = int(time.time() * 1000)
    # Deterministic order: (event time, original index).
    ordered = [r for _, r in sorted(enumerate(records),
                                    key=lambda ir: (ir[1]["TimeCreated"], ir[0]))]
    for rec in ordered:
        raw = {k: v for k, v in rec.items() if k != "Channel"}
        meta = E.stamp_meta({"ingest_id": str(uuid.uuid4()), "received_at": now_ms})
        bus.produce("raw.events", key=None,
                    payload={"source_type": E._source_type_for(rec), "raw": raw, "meta": meta})
    c2 = E.ws2.run(bus)
    det = E.ws4.Detector(rules_dir=Path(rules_dir), plugin_rule_dirs=[])
    E.ws4.run(bus, det)
    alerts = [m.payload for m in bus.consume("alerts")]
    for t in ("scored.events", "ai.requests", "normalized.events", "raw.events.deadletter"):
        list(bus.consume(t))
    return c2["normalized"], alerts


# --------------------------------------------------------------- scoring

def _top(hist: dict, n: int = 10) -> dict:
    items = sorted(hist.items(), key=lambda kv: (-kv[1], kv[0]))[:n]
    return dict(items)


def score_scenario(sc: CA.Scenario, index: dict, rules_dir: Path, replay_fn=replay) -> list:
    """One row per (scenario, label) unit. A scenario with several labels is
    replayed ONCE and scored against each label independently (alert reuse
    across labels is allowed and reported as such). A scenario with no label is
    one UNLABELLED unit."""
    labels = list(sc.labels) or [None]
    base = {
        "corpus": sc.corpus, "dataset_id": sc.dataset_id,
        "label_source": sc.label_source, "dir_label": sc.dir_label,
        "label_dir_disagree": sc.label_dir_disagree,
        "tactics": list(sc.tactics), "fetch_state": sc.fetch_state,
        "files_declared": sc.files_declared, "files_present": sc.files_present,
        "notes": sorted(sc.notes),
    }

    def rows_with(bucket, **extra):
        out = []
        for lab in labels:
            row = dict(base)
            row.update({"label": lab, "bucket": bucket,
                        "label_flags": sorted(sc.label_flags.get(lab, [])) if lab else [],
                        "rules_in_family": [], "fired_in_family": [], "off_label_rules": [],
                        "oracle": None, "records_total": 0, "records_supported": 0,
                        "normalized": 0, "parsed_fraction": None, "partial_parse": False,
                        "unparsed_event_ids": {}, "files_unsupported": 0,
                        "unsupported_sources": []})
            row.update(extra)
            out.append(row)
        return out

    if not sc.fetched:
        return rows_with(TM.classify(fetched=False, label=None, parsed_records=0,
                                     family_rules={}, alert_levels=[]))
    if not sc.labels:
        return rows_with(TM.classify(fetched=True, label=None, parsed_records=0,
                                     family_rules={}, alert_levels=[]))

    res = sc.load()
    if not res.reader_ok:
        return rows_with(TM.classify(fetched=True, reader_ok=False, label=sc.labels[0],
                                     parsed_records=0, family_rules={}, alert_levels=[]))

    normalized, alerts = 0, []
    if res.records:
        normalized, alerts = replay_fn(res.records, rules_dir)

    frac = (len(res.records) / res.total_records) if res.total_records else None
    common = {
        "records_total": res.total_records, "records_supported": len(res.records),
        "normalized": normalized,
        "parsed_fraction": round(frac, 4) if frac is not None else None,
        "partial_parse": bool(res.records) and res.total_records > len(res.records),
        "unparsed_event_ids": _top(res.unparsed),
        "files_unsupported": res.files_unsupported,
        "unsupported_sources": list(res.unsupported_sources),
    }
    E = CA._evtx_module()
    rows = []
    for lab in labels:
        fam = TM.rules_in_family(lab, index)
        levels, fired, off = [], set(), set()
        for a in alerts:
            lvl = TM.alert_level(lab, a)
            if lvl:
                levels.append(lvl)
                fired.add(a.get("rule_id"))
            else:
                off.add(a.get("rule_id"))
        bucket = TM.classify(fetched=True, label=lab, parsed_records=normalized,
                             family_rules=fam, alert_levels=levels)
        oracle = None
        if bucket == "MISS":
            oracle_rules = sorted(set(fam) & set(E.ORACLE_RULES))
            if oracle_rules:     # only the 6 ORACLE_RULES families; else not applicable
                exp = E.oracle(sorted(res.records, key=lambda r: r["TimeCreated"]))
                oracle = ("disagrees_oracle_expects_fire" if any(exp[r] for r in oracle_rules)
                          else "agrees_no_fire")
            else:
                oracle = "not_applicable"
        row = dict(base)
        row.update(common)
        row.update({"label": lab, "bucket": bucket,
                    "label_flags": sorted(sc.label_flags.get(lab, [])),
                    "rules_in_family": sorted(fam), "fired_in_family": sorted(fired),
                    "off_label_rules": sorted(off), "oracle": oracle})
        rows.append(row)
    return rows


def unit_key(row: dict) -> str:
    return f'{row["corpus"]}::{row["dataset_id"]}::{row["label"]}'


def aggregate(rows: list, index: dict, scenarios_total: int) -> dict:
    rows = sorted(rows, key=lambda r: (r["corpus"], r["dataset_id"], r["label"] or ""))
    buckets = {b: 0 for b in TM.BUCKETS}
    for r in rows:
        buckets[r["bucket"]] += 1
    units_total = len(rows)
    # The accounting invariant: every unit lands in exactly one bucket.
    assert sum(buckets.values()) == units_total, (buckets, units_total)
    fetched = units_total - sum(buckets[b] for b in _NOT_DENOMINATOR)

    per_tech: dict = {}
    for r in rows:
        lab = r["label"]
        if lab is None:
            continue
        t = per_tech.setdefault(lab, {"n_units": 0, "n_fetched": 0,
                                      "buckets": {b: 0 for b in TM.BUCKETS}})
        t["n_units"] += 1
        t["buckets"][r["bucket"]] += 1
        if r["bucket"] not in _NOT_DENOMINATOR:
            t["n_fetched"] += 1
    for lab, t in per_tech.items():
        fam = TM.rules_in_family(lab, index)
        b = t["buckets"]
        t["hits_exact"], t["hits_family"] = b["HIT_EXACT"], b["HIT_FAMILY"]
        t["hits"] = t["hits_exact"] + t["hits_family"]
        t["reachable_n"] = t["hits"] + b["MISS"]
        # Text, never a percent: n is always visible and 1/1 is never "100%".
        t["end_to_end"] = f'{t["hits"]}/{t["n_fetched"]}'
        t["reachable"] = f'{t["hits"]}/{t["reachable_n"]}'
        t["family_rules"] = sorted(fam)
        t["exact_rule"] = any(v == "exact" for v in fam.values())
        t["sibling_gap"] = bool(fam) and not t["exact_rule"]

    fetched_techs = {lb for lb, t in per_tech.items() if t["n_fetched"] > 0}
    funnel = {
        "techniques_in_corpus": len(per_tech),
        "techniques_fetched": len(fetched_techs),
        "techniques_with_ingestible_dataset": sum(
            1 for lb in fetched_techs if (per_tech[lb]["n_fetched"]
                                         - per_tech[lb]["buckets"]["NO_PARSER"]
                                         - per_tech[lb]["buckets"]["UNLABELLED"]) > 0),
        "techniques_with_rule": sum(1 for lb in fetched_techs if per_tech[lb]["family_rules"]),
        "techniques_with_hit": sum(1 for lb in fetched_techs if per_tech[lb]["hits"] > 0),
    }
    no_rule = sorted(
        ({"technique": lb, "n_fetched": t["n_fetched"]}
         for lb, t in per_tech.items() if t["n_fetched"] > 0 and not t["family_rules"]),
        key=lambda d: (-d["n_fetched"], d["technique"]))
    no_exact_rule = sorted(
        ({"technique": lb, "n_fetched": t["n_fetched"], "family_rules": t["family_rules"]}
         for lb, t in per_tech.items() if t["n_fetched"] > 0 and t["sibling_gap"]),
        key=lambda d: (-d["n_fetched"], d["technique"]))
    return {
        "schema": SCHEMA,
        "scenarios_total": scenarios_total,
        "units_total": units_total,
        "units_fetched": fetched,
        "buckets": buckets,
        "partial_parse_units": sum(1 for r in rows if r["partial_parse"]),
        "scoreable_units": sum(buckets[b] for b in TM.SCOREABLE_BUCKETS),
        "rule_index_size": len(index),
        "funnel": funnel,
        "per_technique": {k: per_tech[k] for k in sorted(per_tech)},
        "gap_no_rule": no_rule,
        "gap_no_exact_rule": no_exact_rule,
        "rows": rows,
    }


def run(adapters: list, rules_dir: Path, replay_fn=replay) -> dict:
    index = TM.load_rule_index(rules_dir)
    rows, scenarios, expected_units = [], 0, 0
    for ad in adapters:
        for sc in ad.scenarios():
            scenarios += 1
            expected_units += max(1, len(sc.labels))
            rows.extend(score_scenario(sc, index, rules_dir, replay_fn))
    # Accounting invariant: a scenario with k labels is k units, an unlabelled
    # one is exactly 1 (UNLABELLED / NOT_FETCHED); nothing may be dropped.
    assert len(rows) == expected_units, (len(rows), expected_units)
    return aggregate(rows, index, scenarios)


def provenance(adapters: list, manifest_path: Path) -> dict:
    """Pins/licences of the corpora actually scored (no timestamps, no paths:
    the results JSON stays byte-identical for identical inputs)."""
    import fetch_corpora as FC
    try:
        manifest = FC.load_manifest(manifest_path)["corpora"]
    except (OSError, ValueError):
        manifest = {}
    out = {}
    for ad in adapters:
        m = manifest.get(ad.name, {})
        head = FC.head_sha(ad.root)
        out[ad.name] = {"manifest_pin": m.get("pin"), "checked_out": head,
                        "pin_matches": (head == m.get("pin")) if (head and m.get("pin")) else None,
                        "license_spdx": m.get("license_spdx"),
                        "label_source": m.get("label_source")}
    return out


# --------------------------------------------------------------- verdict

def verdict(results: dict, *, require_corpus: bool = False, baseline: dict | None = None):
    """(rc, messages). Pure -- the exit-code decision, testable without a corpus.

    * Zero fetched units: rc 0 with a [SKIP] line (evtx_eval's convention),
      rc 1 under ``require_corpus``.
    * ``require_corpus`` also needs >= 1 unit in a scoreable bucket (parser AND
      rule); a run where everything is NO_PARSER / NO_RULE proved nothing.
    * ``baseline`` ({unit_key: bucket}) is an optional ratchet input: a unit
      that was HIT_* may not become anything else. No absolute recall
      threshold exists and none is invented.
    """
    msgs, rc = [], 0
    if results["units_fetched"] == 0:
        if require_corpus:
            return 1, ["[FAIL] --require-corpus: no dataset was fetched/readable"]
        return 0, ["[SKIP] blind_recall: no fetched dataset -- run "
                   "eval/detection_accuracy/fetch_corpora.py. Proves nothing this run "
                   "(safe no-op, not a failure)."]
    if require_corpus and results["scoreable_units"] == 0:
        rc = 1
        msgs.append("[FAIL] --require-corpus: 0 datasets reached a scoreable bucket "
                    "(parser AND rule); the run measured nothing")
    if baseline:
        cur = {unit_key(r): r["bucket"] for r in results["rows"]}
        for k, was in sorted(baseline.items()):
            if was in TM.HIT_BUCKETS and cur.get(k) not in TM.HIT_BUCKETS:
                rc = 1
                msgs.append(f"[FAIL] regression: {k} was {was}, now {cur.get(k, 'ABSENT')}")
    return rc, msgs


# ------------------------------------------------------------------ main

def print_funnel(res: dict) -> None:
    b = res["buckets"]
    print(f'scenarios={res["scenarios_total"]} units={res["units_total"]} '
          f'fetched_units={res["units_fetched"]} rules_indexed={res["rule_index_size"]}')
    print("funnel buckets: " + " ".join(f"{k}={v}" for k, v in b.items()))
    print("technique funnel: " + " ".join(f"{k}={v}" for k, v in res["funnel"].items()))
    print(f'partial_parse_units={res["partial_parse_units"]} '
          f'scoreable_units={res["scoreable_units"]}')
    print("--- per technique (hits/n; n = fetched units with that label; never a bare %) ---")
    for lab, t in res["per_technique"].items():
        if t["n_fetched"] == 0:
            continue
        nz = {k: v for k, v in t["buckets"].items() if v}
        print(f'  {lab:<10} end_to_end={t["end_to_end"]:<6} reachable={t["reachable"]:<6} '
              f'rules_in_family={len(t["family_rules"])} {nz}')
    if res["gap_no_rule"]:
        print("--- NO_RULE gap list (no enterprise-ATT&CK rule in the family) ---")
        print("  " + ", ".join(f'{g["technique"]}(n={g["n_fetched"]})'
                               for g in res["gap_no_rule"][:40]))
    if res["gap_no_exact_rule"]:
        print("--- no exact rule (family rule exists, exact technique uncovered) ---")
        print("  " + ", ".join(f'{g["technique"]}(n={g["n_fetched"]})'
                               for g in res["gap_no_exact_rule"]))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--corpus", choices=("all", "splunk", "evtx-to-mitre"), default="all")
    ap.add_argument("--splunk-dir", type=Path, default=HERE / "splunk-attack-data")
    ap.add_argument("--evtx-dir", type=Path, default=HERE / "evtx-to-mitre")
    ap.add_argument("--rules-dir", type=Path, default=DEFAULT_RULES_DIR)
    ap.add_argument("--manifest", type=Path, default=HERE / "corpus_manifest.json")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--require-corpus", action="store_true")
    ap.add_argument("--baseline", type=Path, default=None,
                    help="optional {unit_key: bucket} JSON ratchet input (informational "
                         "unless given)")
    a = ap.parse_args(argv)

    adapters = []
    if a.corpus in ("all", "splunk"):
        adapters.append(CA.SplunkAttackData(a.splunk_dir))
    if a.corpus in ("all", "evtx-to-mitre"):
        adapters.append(CA.EvtxToMitre(a.evtx_dir))
    adapters = [ad for ad in adapters if ad.available()]

    results = run(adapters, a.rules_dir)
    results["corpora"] = provenance(adapters, a.manifest)
    a.out.write_text(json.dumps(results, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    baseline = None
    if a.baseline:
        baseline = json.loads(a.baseline.read_text(encoding="utf-8"))
    rc, msgs = verdict(results, require_corpus=a.require_corpus, baseline=baseline)
    if results["units_total"]:
        print_funnel(results)
    for m in msgs:
        print(m)
    return rc


if __name__ == "__main__":
    sys.exit(main())
