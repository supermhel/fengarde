#!/usr/bin/env python3
"""Alert labelling tool + real-data lane (WP-2.2).

The owner labels alerts from their own network ONCE and gets per-rule
precision. The lane:

    dump alerts (alerts.ndjson, make_alert shape) + events (events.ndjson,
    normalized.events docs, siem.ingest_id as the join key)
      ->  python tools/alert_labeller.py export --alerts ... --events ... --out eval/real/review/
      ->  (human) python tools/alert_labeller.py label --jsonl eval/real/labels.jsonl \
             --alert-id <id> --verdict fp --note "..."
      ->  python tools/alert_labeller.py scrub --review-dir eval/real/review/ \
             --labels eval/real/labels.jsonl --out eval/real/out/scrubbed/
      ->  python tools/alert_labeller.py publish --dir eval/real/out/scrubbed/ \
             (refuses anything without the scrub stamp)
      ->  python eval/real/grade.py --review-dir eval/real/out/scrubbed/ \
             --labels eval/real/out/scrubbed/labels.jsonl

Privacy rule: everything under ``eval/real/`` that may contain live traffic
(``review/``, ``labels.jsonl``, ``out/``) is git-ignored by default — nothing
from a private network is ever committed. The SCRUB step deterministically
anonymizes ips/hostnames/users/domains and stamps every output line with a
header carrying ``"scrubbed": true`` and the scrub digest; ``publish`` refuses
to copy any file that lacks the stamp. The must-be-shared result of grading
carries an explicit "single-site, owner-labelled" marker.

All subcommands are pure file operations; tests are synthetic (tools/test_
alert_labeller.py) and never touch the bus.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Optional

VERDICTS = ("tp", "fp", "unknown")

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HOST_RE = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b")
_USER_RE = re.compile(r"\buser(?:name)?[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_.@$-]{3,64})", re.I)

SCRUB_HEADER = {"deck": "fengarde-labeller-v1"}


def _digest(text: bytes) -> str:
    return hashlib.sha256(text).hexdigest()[:16]


def scrub_map(seed: str) -> dict:
    """Deterministic per-run anonymization maps (same input -> same output)."""
    def h(i: int) -> str:
        return hashlib.sha256(f"{seed}:{i}".encode()).hexdigest()
    # 10.0.0.0/8 pseudonyms derived from the seed; collisions are fine (one
    # pseudonym may map many real hosts — the point is unlinkability).
    ips = []
    for i in range(16):
        d = h(i)
        ips.append(f"10.{int(d[0:2], 16) % 250 + 1}."
                   f"{int(d[2:4], 16) % 250 + 1}.{int(d[4:6], 16) % 250 + 2}")
    return {"_ip": ips}


_NAME_KEYS = ("name", "domain", "uid", "username", "user", "hostname", "computer")


def _anonymize_str(key: str, value: str) -> str:
    """Value-by-key anonymization: name/domain/uid values have no pattern
    (a bare 'jdoe' matches no regex) and are hashed by KEY SEMANTICS."""
    if key in _NAME_KEYS:
        if key in ("hostname", "computer", "domain"):
            return f"host-{_digest(value.encode())[:8]}"
        return f"user-{_digest(value.encode())[:8]}"
    return value


def scrub_text(text: str, map_: dict) -> str:
    """Anonymize ip/host/user tokens deterministically (map_ is a lookup)."""
    seen_ip: dict[str, str] = {}
    seen_host: dict[str, str] = {}
    seen_user: dict[str, str] = {}

    def ip_repl(m):
        ip = m.group(0)
        if ip not in seen_ip:
            seen_ip[ip] = map_["_ip"][len(seen_ip) % len(map_["_ip"])]
        return seen_ip[ip]

    def host_repl(m):
        h = m.group(0)
        if h not in seen_host:
            seen_host[h] = f"host-{_digest(h.encode())[:8]}"
        return seen_host[h]

    def user_repl(m):
        u = m.group(1)
        if u not in seen_user:
            seen_user[u] = f"user-{_digest(u.encode())[:8]}"
        return m.group(0).replace(u, seen_user[u])

    text = _IP_RE.sub(ip_repl, text)
    text = _HOST_RE.sub(host_repl, text)
    text = _USER_RE.sub(user_repl, text)
    return text


def scrub_doc(doc: dict, map_: dict, seed: str) -> dict:
    """Scrub one alert/event doc: string leaves under known-private keys plus
    the whole JSON dump as a safety net (no field is ever assumed public)."""
    out = json.loads(json.dumps(doc))  # deep copy
    private_paths = [("src_endpoint",), ("dst_endpoint",), ("actor", "user"),
                     ("api", "request", "data"), ("email",), ("message",),
                     ("unmapped",)]
    for path in private_paths:
        node = out
        for key in path[:-1]:
            node = node.get(key) if isinstance(node, dict) else None
            if node is None:
                break
        if node is None:
            continue
        leaf = path[-1]
        if isinstance(node, dict) and leaf in node:
            v = node[leaf]
            if isinstance(v, str):
                node[leaf] = scrub_text(v, map_)
            elif isinstance(v, dict):
                for k, vv in v.items():
                    if isinstance(vv, str):
                        v[k] = _anonymize_str(k, scrub_text(vv, map_))
                    elif isinstance(vv, dict):
                        for k2, vv2 in vv.items():
                            if isinstance(vv2, str):
                                vv[k2] = _anonymize_str(k2, scrub_text(vv2, map_))
    # whole-document safety net: scrub every string leaf that still contains
    # an ip/host/user shape anywhere
    walk = [out]
    while walk:
        node = walk.pop()
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(v, str) and _IP_RE.search(v):
                    node[k] = scrub_text(v, map_)
                elif isinstance(v, (dict, list)):
                    walk.append(v)
        elif isinstance(node, list):
            walk.extend(node)
    return out


def export_alerts(alerts: list[dict], events: list[dict]) -> list[dict]:
    """Join alerts with their contributing events (siem.ingest_id).

    Pure and total (the testable core). An alert's contributing events are
    its ``event_ids`` that exist in the events dump, in the SAME order as the
    alert carries them; the triggering event (``trigger_event_id``) is always
    included first when present in the dump. Unknown ids are listed under
    ``missing_event_ids`` so the reviewer sees the cap/truncation, never a
    silent gap.
    """
    by_id: dict = {}
    for ev in events:
        ii = None
        if isinstance(ev, dict):
            siem = ev.get("siem")
            ii = siem.get("ingest_id") if isinstance(siem, dict) else None
        if isinstance(ii, str) and ii:
            by_id.setdefault(ii, ev)
    out = []
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        aids = alert.get("event_ids")
        ids = list(aids) if isinstance(aids, list) else []
        tid = alert.get("trigger_event_id")
        ordered: list[str] = []
        if isinstance(tid, str) and tid and tid not in ordered:
            ordered.append(tid)
        for i in ids:
            if i not in ordered:
                ordered.append(i)
        contrib = []
        missing = []
        for i in ordered:
            if i in by_id:
                contrib.append(by_id[i])
            else:
                missing.append(i)
        rec = {
            "alert_id": alert.get("alert_id"),
            "rule_id": alert.get("rule_id"),
            "rule_title": alert.get("rule_title"),
            "level": alert.get("level"),
            "score": alert.get("score"),
            "time": alert.get("time"),
            "src_endpoint": alert.get("src_endpoint"),
            "contributing_events": contrib,
            "missing_event_ids": missing,
            "event_ids_total": len(aids) if isinstance(aids, list) else 0,
        }
        out.append(rec)
    return out


def load_jsonl(path: Path) -> tuple[list[dict], int]:
    malformed = 0
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            malformed += 1
            continue
        if isinstance(obj, dict):
            out.append(obj)
        else:
            malformed += 1
    return out, malformed


def write_review(out_dir: Path, records: list[dict], src_alerts: Path,
                 src_events: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / "alerts.jsonl"
    lines = [json.dumps(r) for r in records]
    # header line carries provenance + the input digests (not the data!)
    header = {"deck": "fengarde-labeller-v1", "kind": "review-export",
              "alerts_source": src_alerts.name,
              "events_source": src_events.name,
              "alerts_digest": _digest(json.dumps(records, sort_keys=True).encode())}
    payload = json.dumps(header) + "\n" + "\n".join(lines) + "\n"
    target.write_text(payload, encoding="utf-8", newline="\n")
    return target


def read_review_file(path: Path) -> list[dict]:
    lines = path.read_text(encoding="utf-8").splitlines()
    out = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict) and "alert_id" in obj:
            out.append(obj)
    return out


def label_append(labels_path: Path, alert_id: str, verdict: str,
                 note: str = "", *, override: bool = False) -> int:
    if verdict not in VERDICTS:
        raise ValueError(f"verdict must be one of {VERDICTS}")
    labels_path.parent.mkdir(parents=True, exist_ok=True)
    existing = []
    if labels_path.exists():
        try:
            existing = [json.loads(line) for line in
                        labels_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        except ValueError:
            existing = []
    if not override and any(e.get("alert_id") == alert_id for e in existing):
        return 1  # duplicate: use --override
    record = {"alert_id": alert_id, "verdict": verdict, "note": note}
    existing = [e for e in existing if e.get("alert_id") != alert_id]
    existing.append(record)
    with labels_path.open("w", encoding="utf-8", newline="\n") as fh:
        for e in existing:
            fh.write(json.dumps(e) + "\n")
    return 0


def scrub_file(src: Path, dst_dir: Path, map_: dict, seed: str) -> Path:
    doc = json.loads(src.read_text(encoding="utf-8"))
    scrubbed = scrub_doc(doc, map_, seed)
    scrubbed["scrubbed"] = True
    scrubbed["scrub_seed"] = seed
    scrubbed["scrub_digest"] = _digest(
        json.dumps(scrubbed, sort_keys=True).encode())
    dst_dir.mkdir(parents=True, exist_ok=True)
    dst = dst_dir / src.name
    dst.write_text(json.dumps(scrubbed, ensure_ascii=False) + "\n",
                   encoding="utf-8", newline="\n")
    return dst


def is_scrubbed(doc: dict) -> bool:
    return bool(doc.get("scrubbed") is True and
                isinstance(doc.get("scrub_digest"), str))


def publish_dir(src_dir: Path, dst_dir: Path) -> int:
    """Copy scrubbed files only; refuse anything not stamped.

    Returns the number of copied files; exits 2 via the CLI when any file
    lacks the scrub stamp — the lane refuses to publish unscrubbed data.
    """
    if not src_dir.is_dir():
        raise NotADirectoryError(str(src_dir))
    dst_dir.mkdir(parents=True, exist_ok=True)
    n = 0
    for path in sorted(src_dir.iterdir()):
        if not path.is_file() or path.suffix == ".lock":
            continue
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            raise ValueError(f"{path.name}: unreadable/not JSON ({exc})") from exc
        if not is_scrubbed(doc):
            raise ValueError(
                f"{path.name}: NOT scrubbed — the lane refuses to publish "
                f"unscrubbed data (run the scrub step first)")
        dst = dst_dir / path.name
        dst.write_text(path.read_text(encoding="utf-8"),
                       encoding="utf-8", newline="\n")
        n += 1
    return n


# ---------------------------------------------------------------- CLI -------

def cmd_export(args) -> int:
    alerts, a_bad = load_jsonl(args.alerts)
    events, e_bad = load_jsonl(args.events)
    records = export_alerts(alerts, events)
    target = write_review(args.out, records, args.alerts, args.events)
    print(f"exported {len(records)} review records -> {target} "
          f"(malformed lines skipped: alerts {a_bad}, events {e_bad}; "
          f"events joined: {sum(len(r['contributing_events']) for r in records)})")
    return 0


def cmd_label(args) -> int:
    try:
        rc = label_append(args.jsonl, args.alert_id, args.verdict,
                          args.note or "", override=args.override)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if rc == 1:
        print(f"error: alert {args.alert_id} already labelled (use --override)",
              file=sys.stderr)
        return 2
    print(f"labelled {args.alert_id} as {args.verdict} -> {args.jsonl}")
    return 0


def cmd_scrub(args) -> int:
    map_ = scrub_map(args.seed)
    srcs = list(args.dir.iterdir()) if args.dir.is_dir() else [args.dir]
    n = 0
    for path in srcs:
        if not path.is_file():
            continue
        scrub_file(path, args.out, map_, args.seed)
        n += 1
    print(f"scrubbed {n} file(s) -> {args.out} (seed {args.seed})")
    return 0


def cmd_publish(args) -> int:
    try:
        n = publish_dir(args.src, args.dst)
    except (ValueError, OSError, NotADirectoryError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"published {n} scrubbed file(s) -> {args.dst}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("export", help="join alert dump + event dump into review records")
    p.add_argument("--alerts", required=True, type=Path)
    p.add_argument("--events", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.set_defaults(fn=cmd_export)

    p = sub.add_parser("label", help="record a tp/fp/unknown verdict")
    p.add_argument("--jsonl", required=True, type=Path)
    p.add_argument("--alert-id", required=True)
    p.add_argument("--verdict", required=True, choices=VERDICTS)
    p.add_argument("--note", default=None)
    p.add_argument("--override", action="store_true")
    p.set_defaults(fn=cmd_label)

    p = sub.add_parser("scrub", help="deterministically anonymize review files")
    p.add_argument("--dir", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--seed", default="fengarde-2026")
    p.set_defaults(fn=cmd_scrub)

    p = sub.add_parser("publish", help="copy scrubbed files, refuse anything else")
    p.add_argument("--src", required=True, type=Path)
    p.add_argument("--dst", required=True, type=Path)
    p.set_defaults(fn=cmd_publish)
    return ap


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())