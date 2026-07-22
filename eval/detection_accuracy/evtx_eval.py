"""EVTX detection-accuracy evaluation for FENGARDE (P3 eval lane).

Replays real Windows Security/Sysmon events from the EVTX-ATTACK-SAMPLES
corpus (github.com/sbousseaden/EVTX-ATTACK-SAMPLES) through the zero-infra
pipeline (WS-2 normalization -> WS-4 detection, memory bus) and compares the
engine's alerts against an independent "oracle" that recomputes each rule's
ground truth directly from the raw records.

Per file: fresh Detector (fresh window counters), events sorted by time,
alerts drained and attributed to the file. Reports TP/FN/FP per rule plus
corpus coverage stats (how many records the shipped parsers can see at all).

DATASET NOT VENDORED -- see this directory's README.md for why (GPL-3.0
license) and how to fetch it. This script SKIPS CLEANLY (prints a message,
exit 0) if the corpus directory or the `python-evtx` package isn't present,
same convention as `make test-live`'s live-infra-gated tests.

Run: python eval/detection_accuracy/evtx_eval.py
     make eval-detection
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
SAMPLES = HERE / "evtx-samples"
OUT_JSON = HERE / "evtx_eval_results.json"

os.environ.setdefault("BUS_BACKEND", "memory")
SERVICES = REPO / "services"
sys.path.insert(0, str(SERVICES))

from shared.bus import Bus  # noqa: E402
from shared.envelope import stamp_meta  # noqa: E402

import importlib


def _import(ws_dir, mod="main"):
    p = str(SERVICES / ws_dir)
    if p in sys.path:
        sys.path.remove(p)
    sys.path.insert(0, p)
    return importlib.import_module(mod)


ws2 = _import("ws2-normalization")
for m in ("main",):
    sys.modules.pop(m, None)
ws4 = _import("ws4-detection")

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

AD_IDS = {4625, 4768, 4771}
WEL_IDS = {4624, 4634, 4647, 4688, 4672, 4720, 4722, 4726, 4728, 4732}
SUPPORTED = AD_IDS | WEL_IDS
# P0-3 (2026-07-21 audit): Sysmon channel, separate from Security.
SYSMON_IDS = {1, 3, 11}
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

RULE_BRUTE = "6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c01"
RULE_SPRAY = "4f8a2c61-9e3d-4b57-8a1c-6d2e5f7a8b90"
RULE_LATERAL = "2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061"
RULE_PRIV = "7d3e9a52-1f6c-4a88-9b3d-2e5c8f1a6d40"
RULE_AFTERHRS = "9b5f2d18-3c7a-4e61-8f24-5a1d7c3e9b06"
RULE_BRUTE_SOURCELESS = "8c2f5a91-4d16-4e8b-9c3a-1f6b2e7d5a83"  # P0-2, 2026-07-21
ORACLE_RULES = [RULE_BRUTE, RULE_SPRAY, RULE_LATERAL, RULE_PRIV, RULE_AFTERHRS,
                RULE_BRUTE_SOURCELESS]
RULE_NAMES = {
    RULE_BRUTE: "bruteforce", RULE_SPRAY: "password_spray",
    RULE_LATERAL: "lateral_movement", RULE_PRIV: "priv_grant",
    RULE_AFTERHRS: "after_hours_admin",
    RULE_BRUTE_SOURCELESS: "bruteforce_sourceless",
}


def parse_systemtime(s: str):
    if not s:
        return None
    s = s.strip().rstrip("Z").replace("T", " ")
    if "." in s:
        head, frac = s.split(".", 1)
        frac = re.sub(r"\D.*$", "", frac)[:6]
        s = f"{head}.{frac}" if frac else head
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def extract_record(xml_str: str):
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None
    system = root.find(f"{NS}System")
    if system is None:
        return None
    eid_el = system.find(f"{NS}EventID")
    chan_el = system.find(f"{NS}Channel")
    tc_el = system.find(f"{NS}TimeCreated")
    comp_el = system.find(f"{NS}Computer")
    try:
        event_id = int((eid_el.text or "").strip())
    except (AttributeError, ValueError):
        return None
    channel = (chan_el.text or "").strip() if chan_el is not None else ""
    ts = parse_systemtime(tc_el.get("SystemTime", "")) if tc_el is not None else None
    rec = {
        "EventID": event_id,
        "Channel": channel,
        "Computer": (comp_el.text or "").strip() if comp_el is not None else "",
        "TimeCreated": int(ts.timestamp() * 1000) if ts else None,
    }
    ed = root.find(f"{NS}EventData")
    if ed is not None:
        for d in ed.findall(f"{NS}Data"):
            name = d.get("Name")
            if name and d.text is not None:
                rec[name] = d.text.strip()
    return rec


# ---------------- oracle: independent ground-truth math ----------------

def sliding_count_max(times_ms, window_ms):
    best = 0
    lo = 0
    for hi, t in enumerate(times_ms):
        while times_ms[lo] < t - window_ms:
            lo += 1
        best = max(best, hi - lo + 1)
    return best


def sliding_distinct_max(pairs, window_ms):
    """pairs: sorted [(t_ms, value)]; max distinct values in any window."""
    best = 0
    for i, (t0, _) in enumerate(pairs):
        seen = set()
        for t, v in pairs[i:]:
            if t > t0 + window_ms:
                break
            seen.add(v)
        best = max(best, len(seen))
    return best


def in_business_hours(t_ms):
    dt = datetime.fromtimestamp(t_ms / 1000, tz=timezone.utc)
    if dt.weekday() > 4:  # sat/sun
        return False
    return 8 <= dt.hour < 18 or (dt.hour == 18 and dt.minute == 0)


def _real_ip(r):
    """Ground-truth mirror of engine.py's group_by/distinct_field fail-closed
    semantics (evaluate(): `group_value is None -> return False`;
    hit_distinct(): `value is None -> return False`). A missing OR literal
    "-" IpAddress (Windows' own placeholder for "no source recorded" --
    P0-2, live-proven on Splunk purplesharp datasets) must NOT be treated as
    a real (or even a fake-distinct) IP value here -- pooling it under a
    shared "-" bucket is exactly the placeholder-pooling anti-pattern the
    real engine's fail-closed guards exist to prevent, and doing it in the
    oracle would silently misjudge common_bruteforce/common_password_spray's
    ACTUAL (correct) behavior on this traffic shape."""
    ip = r.get("IpAddress")
    return ip if ip and ip != "-" else None


def oracle(records):
    """records: time-sorted supported Security records. Returns {rule_id: bool}."""
    exp = {}
    failed = [r for r in records if r["EventID"] in (4625, 4771)]
    by_ip = defaultdict(list)
    for r in failed:
        ip = _real_ip(r)
        if ip is not None:
            by_ip[ip].append(r["TimeCreated"])
    exp[RULE_BRUTE] = any(
        sliding_count_max(sorted(ts), 60_000) >= 10 for ts in by_ip.values())

    by_user = defaultdict(list)
    for r in failed:
        ip = _real_ip(r)
        if ip is None:
            continue  # hit_distinct() fail-closes on a missing distinct_field value
        u = r.get("TargetUserName") or ""
        by_user[u].append((r["TimeCreated"], ip))
    exp[RULE_SPRAY] = any(
        sliding_distinct_max(sorted(p), 300_000) >= 8 for p in by_user.values())

    logons = [r for r in records if r["EventID"] == 4624]
    by_user2 = defaultdict(list)
    for r in logons:
        u = r.get("TargetUserName") or ""
        host = r.get("Computer") or ""
        by_user2[u].append((r["TimeCreated"], host))
    exp[RULE_LATERAL] = any(
        sliding_distinct_max(sorted(p), 300_000) >= 5 for p in by_user2.values())

    # P0-2: mirrors common_bruteforce_sourceless.yml exactly -- group by the
    # SAME field the active_directory parser populates src_endpoint.hostname
    # from (WorkstationName if present, else Computer), distinct-count
    # TargetUserName, threshold 5 within 120s. No IP filtering here on
    # purpose: the rule doesn't filter on IP presence either (see the rule's
    # own docstring) -- it groups on hostname, which is what makes it behave
    # correctly whether or not a source IP was recorded.
    by_host = defaultdict(list)
    for r in failed:
        host = r.get("WorkstationName") or r.get("Computer") or ""
        by_host[host].append((r["TimeCreated"], r.get("TargetUserName") or ""))
    exp[RULE_BRUTE_SOURCELESS] = any(
        sliding_distinct_max(sorted(p), 120_000) >= 5 for p in by_host.values())

    exp[RULE_PRIV] = any(r["EventID"] in (4728, 4732) for r in records)
    exp[RULE_AFTERHRS] = any(
        r["EventID"] == 4672 and not in_business_hours(r["TimeCreated"])
        for r in records)
    return exp


# ---------------- replay ----------------

def _source_type_for(rec):
    if rec["Channel"] == SYSMON_CHANNEL:
        return "sysmon"
    return "active_directory" if rec["EventID"] in AD_IDS else "windows_eventlog"


def replay_file(records):
    """Feed supported records through WS-2 -> WS-4 on a fresh bus/detector."""
    bus = Bus()
    now_ms = int(time.time() * 1000)
    for rec in records:
        st = _source_type_for(rec)
        raw = {k: v for k, v in rec.items() if k != "Channel"}
        meta = stamp_meta({"ingest_id": str(uuid.uuid4()), "received_at": now_ms})
        bus.produce("raw.events", key=None,
                    payload={"source_type": st, "raw": raw, "meta": meta})
    c2 = ws2.run(bus)
    det = ws4.Detector(plugin_rule_dirs=[])
    c4 = ws4.run(bus, det)
    alerts = [m.payload for m in bus.consume("alerts")]
    dead = [m.payload for m in bus.consume("raw.events.deadletter")]
    # drain remaining topics so nothing lingers
    for t in ("scored.events", "ai.requests", "normalized.events"):
        list(bus.consume(t))
    return c2, c4, alerts, dead


def main():
    if not SAMPLES.is_dir():
        print(f"[SKIP] evtx_eval: dataset dir not found at {SAMPLES} -- see "
              f"eval/detection_accuracy/README.md to fetch EVTX-ATTACK-SAMPLES. "
              f"Proves nothing this run (safe no-op, not a failure).")
        return 0
    try:
        from Evtx.Evtx import Evtx
    except ImportError:
        print("[SKIP] evtx_eval: 'python-evtx' not installed (pip install python-evtx). "
              "Proves nothing this run (safe no-op, not a failure).")
        return 0

    files = sorted(SAMPLES.rglob("*.evtx"))
    if not files:
        print(f"[SKIP] evtx_eval: {SAMPLES} exists but contains no .evtx files.")
        return 0

    corpus = {"files": 0, "records_total": 0, "records_security": 0,
              "records_supported": 0, "xml_errors": 0,
              "records_sysmon": 0, "sysmon_supported": 0,
              "security_supported": 0}
    eventid_hist = defaultdict(int)
    confusion = {rid: {"tp": 0, "fn": 0, "fp": 0, "tn": 0} for rid in ORACLE_RULES}
    mismatches = []
    per_file = []
    parse_drops = []

    for fp in files:
        corpus["files"] += 1
        records = []
        try:
            with Evtx(str(fp)) as log:
                for xr in log.records():
                    corpus["records_total"] += 1
                    try:
                        rec = extract_record(xr.xml())
                    except Exception:
                        corpus["xml_errors"] += 1
                        continue
                    if rec is None:
                        corpus["xml_errors"] += 1
                        continue
                    eventid_hist[f'{rec["Channel"]}:{rec["EventID"]}'] += 1
                    if rec["Channel"] == "Security":
                        corpus["records_security"] += 1
                        if rec["EventID"] not in SUPPORTED or rec["TimeCreated"] is None:
                            continue
                        corpus["records_supported"] += 1
                        corpus["security_supported"] += 1
                        records.append(rec)
                    elif rec["Channel"] == SYSMON_CHANNEL:
                        # P0-3: tracked separately from Security so the "9% of
                        # Security events" number from the original audit stays
                        # honestly comparable; sysmon_supported is the NEW
                        # coverage this parser adds.
                        corpus["records_sysmon"] += 1
                        if rec["EventID"] not in SYSMON_IDS or rec["TimeCreated"] is None:
                            continue
                        corpus["sysmon_supported"] += 1
                        corpus["records_supported"] += 1
                        records.append(rec)
        except Exception as exc:
            per_file.append({"file": fp.name, "error": f"{type(exc).__name__}: {exc}"})
            continue

        if not records:
            per_file.append({"file": fp.name, "supported": 0})
            continue
        records.sort(key=lambda r: r["TimeCreated"])
        exp = oracle(records)
        c2, c4, alerts, dead = replay_file(records)
        fired = {a["rule_id"] for a in alerts}
        row = {"file": str(fp.relative_to(SAMPLES)), "supported": len(records),
               "normalized": c2["normalized"], "dropped": c2["dropped"],
               "alerts": len(alerts),
               "fired": sorted(RULE_NAMES.get(r, r) for r in fired),
               "expected": sorted(RULE_NAMES[r] for r, v in exp.items() if v)}
        per_file.append(row)
        if dead:
            parse_drops.append({"file": fp.name, "count": len(dead),
                                "sample_error": dead[0].get("errors")})
        for rid in ORACLE_RULES:
            e, f = exp[rid], rid in fired
            k = "tp" if (e and f) else "fn" if (e and not f) else \
                "fp" if (not e and f) else "tn"
            confusion[rid][k] += 1
            if e != f:
                mismatches.append({"file": fp.name, "rule": RULE_NAMES[rid],
                                   "expected": e, "fired": f})

    out = {"corpus": corpus,
           "eventid_histogram": dict(sorted(eventid_hist.items(),
                                            key=lambda kv: -kv[1])[:40]),
           "confusion": {RULE_NAMES[r]: c for r, c in confusion.items()},
           "mismatches": mismatches,
           "parser_dead_letters": parse_drops,
           "per_file": per_file}
    OUT_JSON.write_text(json.dumps(out, indent=1))

    print(f"files={corpus['files']} records={corpus['records_total']} "
          f"security={corpus['records_security']} sysmon={corpus['records_sysmon']} "
          f"supported={corpus['records_supported']}")
    sec_pct = 100 * corpus['security_supported'] / corpus['records_security'] if corpus['records_security'] else 0
    combined_relevant = corpus['records_security'] + corpus['records_sysmon']
    combined_pct = 100 * corpus['records_supported'] / combined_relevant if combined_relevant else 0
    print(f"P0-3 coverage: sysmon_supported={corpus['sysmon_supported']}/{corpus['records_sysmon']} "
          f"| coverage-of-Security-only={sec_pct:.1f}% "
          f"| coverage-of-Security+Sysmon={combined_pct:.1f}%")
    print(f"xml_errors={corpus['xml_errors']}")
    print("--- confusion (per-file granularity) ---")
    for rid in ORACLE_RULES:
        c = confusion[rid]
        print(f"{RULE_NAMES[rid]:>18}: TP={c['tp']} FN={c['fn']} FP={c['fp']} TN={c['tn']}")
    print(f"mismatches={len(mismatches)} parser_dead_letter_files={len(parse_drops)}")
    for m in mismatches[:20]:
        print("  MISMATCH", m)
    for d in parse_drops[:10]:
        print("  DEADLETTER", d)
    return 0


if __name__ == "__main__":
    sys.exit(main())
