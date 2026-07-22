"""Splunk attack_data detection-accuracy eval for FENGARDE (P3 eval lane).

Reuses the EVTX harness (extract_record / oracle / replay_file) but sources
records from Splunk attack_data's raw-XML `windows-security.log` datasets
(github.com/splunk/attack_data). These purplesharp/T1110 sets carry real
brute-force / password-spray VOLUME the single-incident EVTX-ATTACK-SAMPLES
corpus lacked, so they actually exercise the stateful burst rules.

Same independent oracle: ground truth recomputed from raw records, compared
against the live engine's alerts. Per-file fresh Detector (fresh windows).

DATASET NOT VENDORED -- see this directory's README.md for how to fetch it
(and its own license, separate from EVTX-ATTACK-SAMPLES'). SKIPS CLEANLY
(prints a message, exit 0) if the corpus directory isn't present, same
convention as `make test-live`'s live-infra-gated tests.

Run: python eval/detection_accuracy/splunk_eval.py
     make eval-detection
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import evtx_eval as E  # noqa: E402

SA = HERE / "splunk-attack-data" / "datasets" / "attack_techniques"
OUT = HERE / "splunk_eval_results.json"


def iter_xml_events(text: str):
    """Yield each <Event ...>...</Event> block from a concatenated/one-per-line
    Splunk windows-security.log."""
    idx = 0
    while True:
        start = text.find("<Event ", idx)
        if start == -1:
            return
        end = text.find("</Event>", start)
        if end == -1:
            return
        yield text[start:end + len("</Event>")]
        idx = end + 1


def load_file(fp: Path):
    records = []
    try:
        text = fp.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return records
    for block in iter_xml_events(text):
        rec = E.extract_record(block)
        if rec is None:
            continue
        if rec.get("Channel") != "Security":
            continue
        if rec["EventID"] in E.SUPPORTED and rec["TimeCreated"] is not None:
            records.append(rec)
    return records


def main():
    if not SA.is_dir():
        print(f"[SKIP] splunk_eval: dataset dir not found at {SA} -- see "
              f"eval/detection_accuracy/README.md to fetch splunk/attack_data. "
              f"Proves nothing this run (safe no-op, not a failure).")
        return 0

    # every raw-<Event> windows-security.log under the cloned techniques
    files = []
    for fp in SA.rglob("*.log"):
        if "security" not in fp.name.lower():
            continue
        try:
            head = fp.open("r", encoding="utf-8", errors="replace").read(64)
        except OSError:
            continue
        if head.lstrip().startswith("<Event"):
            files.append(fp)
    files.sort()

    if not files:
        print(f"[SKIP] splunk_eval: {SA} exists but contains no raw-XML security.log files.")
        return 0

    confusion = {rid: {"tp": 0, "fn": 0, "fp": 0, "tn": 0} for rid in E.ORACLE_RULES}
    mismatches, per_file, deadletters = [], [], []
    tot_supported = 0
    eid_hist = defaultdict(int)

    for fp in files:
        records = load_file(fp)
        if not records:
            per_file.append({"file": fp.parent.name + "/" + fp.name, "supported": 0})
            continue
        for r in records:
            eid_hist[r["EventID"]] += 1
        tot_supported += len(records)
        records.sort(key=lambda r: r["TimeCreated"])
        exp = E.oracle(records)
        c2, c4, alerts, dead = E.replay_file(records)
        fired = {a["rule_id"] for a in alerts}
        per_file.append({
            "file": fp.parent.name + "/" + fp.name,
            "supported": len(records), "normalized": c2["normalized"],
            "dropped": c2["dropped"], "alerts": len(alerts),
            "fired": sorted(E.RULE_NAMES.get(r, r) for r in fired),
            "expected": sorted(E.RULE_NAMES[r] for r, v in exp.items() if v),
        })
        if dead:
            deadletters.append({"file": fp.parent.name + "/" + fp.name,
                                "count": len(dead), "sample": dead[0].get("errors")})
        for rid in E.ORACLE_RULES:
            e, f = exp[rid], rid in fired
            k = "tp" if (e and f) else "fn" if (e and not f) else \
                "fp" if (not e and f) else "tn"
            confusion[rid][k] += 1
            if e != f:
                mismatches.append({"file": fp.parent.name + "/" + fp.name,
                                   "rule": E.RULE_NAMES[rid], "expected": e, "fired": f})

    out = {"files": len(files), "supported_records": tot_supported,
           "eventid_hist": dict(sorted(eid_hist.items(), key=lambda kv: -kv[1])),
           "confusion": {E.RULE_NAMES[r]: c for r, c in confusion.items()},
           "mismatches": mismatches, "deadletters": deadletters,
           "per_file": per_file}
    OUT.write_text(json.dumps(out, indent=1))

    print(f"xml-security files={len(files)} supported_records={tot_supported}")
    print("eventid histogram:", dict(sorted(eid_hist.items(), key=lambda kv: -kv[1])))
    print("--- confusion (per-file) ---")
    for rid in E.ORACLE_RULES:
        c = confusion[rid]
        print(f"{E.RULE_NAMES[rid]:>18}: TP={c['tp']} FN={c['fn']} FP={c['fp']} TN={c['tn']}")
    print(f"mismatches={len(mismatches)} deadletter_files={len(deadletters)}")
    for m in mismatches:
        print("  MISMATCH", m)
    for d in deadletters[:12]:
        print("  DEADLETTER", d)
    print("--- files that fired ---")
    for r in per_file:
        if r.get("fired"):
            print("  ", r["file"], "FIRED", r["fired"], "| expected", r["expected"],
                  f"(supported={r['supported']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
