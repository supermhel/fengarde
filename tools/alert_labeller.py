#!/usr/bin/env python3
"""Alert labelling tool + real-data lane (WP-2.2).

The owner labels alerts from their own network ONCE and gets per-rule
precision. The lane (every default path is git-ignored):

    dump alerts (alerts.ndjson, make_alert shape) + events (events.ndjson,
    normalized.events docs, siem.ingest_id as the join key)
      ->  python tools/alert_labeller.py export --alerts ... --events ...
      ->  (human) python tools/alert_labeller.py label --alert-id <id> \
             --verdict fp --note "..."
      ->  python tools/alert_labeller.py scrub --dir eval/real/review/ \
             --labels eval/real/labels.jsonl --out eval/real/out/scrubbed/
      ->  python tools/alert_labeller.py publish --src eval/real/out/scrubbed/
             (re-scans every line; refuses on any stamp/digest/ip/host/user hit)
      ->  python eval/real/grade.py --review-dir eval/real/out/scrubbed/ \
             --labels eval/real/out/scrubbed/labels.jsonl

Privacy rules: everything under ``eval/real/`` that may contain live traffic
is git-ignored, and every OUTPUT path (label/export/scrub/publish/grade) is
refused unless ``git check-ignore`` covers it. SCRUB pseudonymises ips,
hostnames, users and alert ids with HMAC-SHA256 under a secret that is never
written to the output; the stamp is an integrity check, not authenticity, so
``publish`` independently re-scans the content and refuses on any private-
looking value.

All subcommands are pure file operations; tests are synthetic (tools/test_
alert_labeller.py) and never touch the bus.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]
REAL = ROOT / "eval" / "real"
VERDICTS = ("tp", "fp", "unknown")

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_V6_RE = re.compile(r"(?<![\w:.])[0-9A-Fa-f:]{2,39}(?![\w:.])")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}")
_HOST_RE = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b")
_USER_RE = re.compile(r"\buser(?:name)?[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_.@$-]{3,64})", re.I)
_PSEUDO_RE = re.compile(r"^(?:user|host)-[0-9a-f]{8}$")
_ALERT_PSEUDO_RE = re.compile(r"^alert-[0-9a-f]{12}$")
_PSEUDO_NET = ipaddress.ip_network("198.18.0.0/15")  # RFC 2544 benchmark range

# Values under these keys are private by key semantics (a bare 'jdoe' matches
# no regex). host-kind keys get host-<h>, the rest user-<h>. Over-scrubbing
# (e.g. process.name) is deliberate: the scrubbed copy is for rule-level grading.
_HOST_KEYS = frozenset({"hostname", "computer", "domain", "host", "fqdn", "workstation"})
_NAME_KEYS = _HOST_KEYS | {"name", "uid", "username", "user", "account", "upn", "email"}
# Top-level fields that are public rule facts / stamp metadata (never scrubbed).
_SAFE_TOP = frozenset({"rule_id", "rule_title", "level", "score", "time",
                       "event_ids_total", "event_ids_omitted", "verdict", "kind",
                       "deck", "alerts_digest", "scrubbed", "scrub_digest"})
# Top-level fields dropped outright: free text / provenance names.
_DROP_TOP = frozenset({"note", "alerts_source", "events_source"})


def _digest(text: bytes) -> str:
    return hashlib.sha256(text).hexdigest()[:16]


def _is_v6(tok: str) -> bool:
    if tok.count(":") < 2:
        return False
    try:
        ipaddress.IPv6Address(tok)
    except ValueError:
        return False
    return True


class Scrubber:
    """One real->pseudonym map per run. Names/ids are HMAC-SHA256 under a
    secret that is never stored in any output (unsalted hashes are
    dictionary-reversible); IPs are keyed the same way but probed until the
    pseudonym is unused, so two real IPs never share one."""

    def __init__(self, secret: Optional[bytes] = None):
        self.key = secret if secret is not None else secrets.token_bytes(32)
        self._ips: dict[str, str] = {}
        self._used: set[str] = set()
        self._known: dict[str, str] = {}   # private value -> "user"|"host"
        self._known_re: Optional[re.Pattern] = None

    def _h(self, label: str, value: str, n: int) -> str:
        return hmac.new(self.key, f"{label}:{value}".encode(), hashlib.sha256).hexdigest()[:n]

    def name(self, kind: str, value: str) -> str:
        return f"{kind}-{self._h(kind, value.lower() if kind == 'host' else value, 8)}"

    def alert_id(self, value: str) -> str:
        # make_alert ids are rule:group:bucket, so they embed the src ip/user
        return f"alert-{self._h('alert', value, 12)}"

    def ip(self, real: str) -> str:
        if real not in self._ips:
            n = 0
            while True:
                idx = int(self._h(f"ip{n}", real, 8), 16) % (_PSEUDO_NET.num_addresses - 2) + 1
                cand = str(_PSEUDO_NET[idx])
                if cand not in self._used:
                    break
                n += 1
            self._used.add(cand)
            self._ips[real] = cand
        return self._ips[real]

    def learn(self, node: object, key: str = "") -> None:
        """Collect values under name keys so free text elsewhere is cleaned."""
        if isinstance(node, dict):
            for k, v in node.items():
                self.learn(v, str(k).lower())
        elif isinstance(node, list):
            for v in node:
                self.learn(v, key)
        elif isinstance(node, str) and key in _NAME_KEYS:
            if (len(node) >= 2 and not _PSEUDO_RE.match(node) and node not in self._known
                    and node.lower() not in ("user", "host", "alert", "ip6")):  # pseudonym prefixes
                self._known[node] = "host" if key in _HOST_KEYS else "user"
                self._known_re = None

    def text(self, text: str) -> str:
        def v6(m):
            return f"ip6-{self._h('ip6', m.group(0), 8)}" if _is_v6(m.group(0)) else m.group(0)

        def email(m):
            local, _, dom = m.group(0).partition("@")
            return f"{self.name('user', local)}@{self.name('host', dom)}"

        text = _EMAIL_RE.sub(email, text)
        text = _IP_RE.sub(lambda m: self.ip(m.group(0)), text)
        text = _V6_RE.sub(v6, text)
        text = _HOST_RE.sub(lambda m: self.name("host", m.group(0)), text)
        text = _USER_RE.sub(
            lambda m: m.group(0).replace(m.group(1), self.name("user", m.group(1))), text)
        if self._known:
            if self._known_re is None:
                alt = "|".join(re.escape(v) for v in sorted(self._known, key=len, reverse=True))
                self._known_re = re.compile(rf"(?<!\w)(?:{alt})(?!\w)")
            text = self._known_re.sub(
                lambda m: self.name(self._known[m.group(0)], m.group(0)), text)
        return text

    def _walk(self, node: object, key: str, top: bool) -> object:
        if isinstance(node, dict):
            out: dict = {}
            for k, v in node.items():
                if top and k in _DROP_TOP:
                    continue
                if top and k in _SAFE_TOP:
                    out[k] = v
                else:
                    out[self.text(k)] = self._walk(v, k.lower(), False)
            return out
        if isinstance(node, list):
            return [self._walk(v, key, False) for v in node]
        if isinstance(node, str) and node:
            if key == "alert_id":
                return self.alert_id(node)
            if key in _NAME_KEYS:
                return self.name("host" if key in _HOST_KEYS else "user", node)
            return self.text(node)
        return node

    def scrub_doc(self, doc: dict) -> dict:
        """Recurse into EVERY string leaf and key (no field is assumed public),
        replacing known-private values wherever they appear in free text."""
        self.learn(doc)
        return self._walk(doc, "", True)  # type: ignore[return-value]


def _text_hits(s: str) -> list[str]:
    hits = []
    for m in _IP_RE.finditer(s):
        try:
            if ipaddress.ip_address(m.group(0)) in _PSEUDO_NET:
                continue
        except ValueError:
            pass
        hits.append("ipv4")
    hits += ["ipv6" for m in _V6_RE.finditer(s) if _is_v6(m.group(0))]
    hits += ["email" for _ in _EMAIL_RE.finditer(s)]
    hits += ["host" for _ in _HOST_RE.finditer(s)]
    hits += ["user" for m in _USER_RE.finditer(s) if not _PSEUDO_RE.match(m.group(1))]
    return hits


def find_private(node: object, path: str = "$", key: str = "", top: bool = True) -> list[str]:
    """Independent re-scan of a SCRUBBED record: returns 'path: kind' hits
    (never the private value itself). publish uses it because a stamp is
    self-declared and must not be trusted on its own."""
    hits: list[str] = []
    if isinstance(node, dict):
        for k, v in node.items():
            if top and k in _SAFE_TOP:
                continue
            hits += [f"{path}.<key>: {h}" for h in _text_hits(str(k))]
            hits += find_private(v, f"{path}.{k}", str(k).lower(), False)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            hits += find_private(v, f"{path}[{i}]", key, False)
    elif isinstance(node, str) and node:
        if key == "alert_id":
            if not _ALERT_PSEUDO_RE.match(node):
                hits.append(f"{path}: alert_id not pseudonymised")
        elif key in _NAME_KEYS:
            if not _PSEUDO_RE.match(node):
                hits.append(f"{path}: name field not pseudonymised")
        else:
            hits += [f"{path}: {h}" for h in _text_hits(node)]
    return hits


def export_alerts(alerts: list[dict], events: list[dict]) -> list[dict]:
    """Join alerts with their contributing events (siem.ingest_id).

    Pure and total (the testable core). An alert's contributing events are
    its ``event_ids`` that exist in the events dump, in the SAME order as the
    alert carries them; the triggering event (``trigger_event_id``) is always
    included first when present in the dump. Unknown ids are listed under
    ``missing_event_ids``; ids the alert's own cap cut are carried as
    ``event_ids_omitted`` so the reviewer sees the truncation, never a
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
        om = alert.get("event_ids_omitted")
        omitted = om if isinstance(om, int) and not isinstance(om, bool) and om > 0 else 0
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
            "event_ids_omitted": omitted,
            "event_ids_total": len(ids) + omitted,
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


def _read_labels(path: Path) -> list[dict]:
    """Strict read: a corrupt line is an error, never silently dropped."""
    if not path.exists():
        return []
    out = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except ValueError as exc:
            raise ValueError(f"{path}:{n}: malformed label line ({exc}); refusing to "
                             f"rewrite the file - fix or remove that line by hand") from exc
        if not isinstance(rec, dict) or not isinstance(rec.get("alert_id"), str):
            raise ValueError(f"{path}:{n}: not a label record; refusing to rewrite "
                             f"the file - fix or remove that line by hand")
        out.append(rec)
    return out


def label_append(labels_path: Path, alert_id: str, verdict: str,
                 note: str = "", *, override: bool = False) -> int:
    if verdict not in VERDICTS:
        raise ValueError(f"verdict must be one of {VERDICTS}")
    labels_path.parent.mkdir(parents=True, exist_ok=True)
    existing = _read_labels(labels_path)  # raises BEFORE anything is written
    if not override and any(e.get("alert_id") == alert_id for e in existing):
        return 1  # duplicate: use --override
    existing = [e for e in existing if e.get("alert_id") != alert_id]
    existing.append({"alert_id": alert_id, "verdict": verdict, "note": note})
    tmp = labels_path.with_name(labels_path.name + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as fh:
        for e in existing:
            fh.write(json.dumps(e) + "\n")
    os.replace(tmp, labels_path)  # atomic: a crash never leaves a truncated file
    return 0


def _stamp(rec: dict) -> dict:
    body = {k: v for k, v in rec.items() if k not in ("scrubbed", "scrub_digest")}
    return {**body, "scrubbed": True,
            "scrub_digest": _digest(json.dumps(body, sort_keys=True).encode())}


def _label_view(rec: dict) -> dict:
    """Label records keep only alert_id + verdict (the free-text note is dropped)."""
    if "verdict" in rec:
        return {"alert_id": rec.get("alert_id"), "verdict": rec["verdict"]}
    return rec


def read_jsonl_strict(path: Path) -> list[dict]:
    out = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except ValueError as exc:
            raise ValueError(f"{path.name}:{n}: not JSON ({exc})") from exc
        if not isinstance(rec, dict):
            raise ValueError(f"{path.name}:{n}: not a JSON object")
        out.append(rec)
    return out


def scrub_file(src: Path, dst_dir: Path, scrubber: Scrubber) -> Path:
    """Scrub a JSONL file line by line; every output line is stamped."""
    recs = read_jsonl_strict(src)
    scrubbed = [_stamp(scrubber.scrub_doc(_label_view(r))) for r in recs]
    dst_dir.mkdir(parents=True, exist_ok=True)
    dst = dst_dir / src.name
    dst.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in scrubbed),
                   encoding="utf-8", newline="\n")
    return dst


def is_scrubbed(doc: dict) -> bool:
    """Stamp present AND digest consistent (integrity only, not authenticity)."""
    return bool(doc.get("scrubbed") is True and isinstance(doc.get("scrub_digest"), str)
                and _stamp(doc)["scrub_digest"] == doc["scrub_digest"])


def publish_dir(src_dir: Path, dst_dir: Path) -> int:
    """Copy scrubbed files only. Validates EVERY line of EVERY file first
    (stamp + digest + independent private-value re-scan), then copies."""
    if not src_dir.is_dir():
        raise NotADirectoryError(str(src_dir))
    files = [p for p in sorted(src_dir.iterdir()) if p.is_file() and p.suffix != ".lock"]
    for path in files:
        try:
            recs = read_jsonl_strict(path)
        except (ValueError, OSError) as exc:
            raise ValueError(f"{path.name}: unreadable/not JSONL ({exc})") from exc
        for n, rec in enumerate(recs, 1):
            if not is_scrubbed(rec):
                raise ValueError(
                    f"{path.name}:{n}: NOT scrubbed - the lane refuses to publish "
                    f"unscrubbed data (run the scrub step first)")
            hits = find_private(rec)
            if hits:
                raise ValueError(
                    f"{path.name}:{n}: stamped but still looks private - the lane "
                    f"refuses to publish ({'; '.join(hits[:5])})")
    dst_dir.mkdir(parents=True, exist_ok=True)
    for path in files:
        (dst_dir / path.name).write_text(path.read_text(encoding="utf-8"),
                                         encoding="utf-8", newline="\n")
    return len(files)


def ensure_ignored(path: Path, *, is_dir: bool = False) -> None:
    """Refuse an output path that `git check-ignore` does not cover (fail
    closed: git missing / path outside the repo / tracked file all refuse)."""
    probe = (path / ".probe") if is_dir else path
    try:
        rc = subprocess.run(["git", "-C", str(ROOT), "check-ignore", "-q", "--",
                             str(probe.resolve())], capture_output=True).returncode
    except OSError:
        rc = 1
    if rc != 0:
        raise ValueError(f"refusing to write {path}: not covered by .gitignore "
                         f"(live data must stay under the git-ignored eval/real/ area)")


# ---------------------------------------------------------------- CLI -------

def cmd_export(args) -> int:
    try:
        ensure_ignored(args.out, is_dir=True)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    alerts, a_bad = load_jsonl(args.alerts)
    events, e_bad = load_jsonl(args.events)
    records = export_alerts(alerts, events)
    target = write_review(args.out, records, args.alerts, args.events)
    trunc = [r for r in records if r["event_ids_omitted"]]
    print(f"exported {len(records)} review records -> {target} "
          f"(malformed lines skipped: alerts {a_bad}, events {e_bad}; "
          f"events joined: {sum(len(r['contributing_events']) for r in records)})")
    if trunc:
        print(f"TRUNCATED: {len(trunc)} alert(s) lost {sum(r['event_ids_omitted'] for r in trunc)} "
              f"contributing event id(s) to the alert's own cap (event_ids_omitted); "
              f"their review is NOT complete")
    return 0


def cmd_label(args) -> int:
    try:
        ensure_ignored(args.jsonl)
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
    try:
        ensure_ignored(args.out, is_dir=True)
        secret = args.secret_file.read_bytes().strip() if args.secret_file else None
        if secret is not None and not secret:
            raise ValueError("--secret-file is empty")
        srcs = sorted(p for p in args.dir.iterdir() if p.is_file()) if args.dir.is_dir() \
            else [args.dir]
        skipped = [p.name for p in srcs if p.suffix != ".jsonl"]
        srcs = [p for p in srcs if p.suffix == ".jsonl"]
        if args.labels:
            srcs.append(args.labels)
        scr = Scrubber(secret)
        for path in srcs:  # learn every private name first so free text in ANY file is cleaned
            for rec in read_jsonl_strict(path):
                scr.learn(rec)
        for path in srcs:
            scrub_file(path, args.out, scr)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"scrubbed {len(srcs)} file(s) -> {args.out} (skipped non-.jsonl: {len(skipped)}; "
          f"secret {'from file' if secret else 'random per run, not stored'})")
    return 0


def cmd_publish(args) -> int:
    try:
        ensure_ignored(args.dst, is_dir=True)
        n = publish_dir(args.src, args.dst)
    except (ValueError, OSError) as exc:
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
    p.add_argument("--out", type=Path, default=REAL / "review")
    p.set_defaults(fn=cmd_export)

    p = sub.add_parser("label", help="record a tp/fp/unknown verdict")
    p.add_argument("--jsonl", type=Path, default=REAL / "labels.jsonl")
    p.add_argument("--alert-id", required=True)
    p.add_argument("--verdict", required=True, choices=VERDICTS)
    p.add_argument("--note", default=None)
    p.add_argument("--override", action="store_true")
    p.set_defaults(fn=cmd_label)

    p = sub.add_parser("scrub", help="pseudonymise review files (+ labels) with a secret key")
    p.add_argument("--dir", required=True, type=Path, help="review dir (or one .jsonl file)")
    p.add_argument("--labels", type=Path, help="labels.jsonl to scrub in the SAME run "
                   "(alert ids are pseudonymised, so review and labels must share one run)")
    p.add_argument("--out", type=Path, default=REAL / "out" / "scrubbed")
    p.add_argument("--secret-file", type=Path, help="file holding the HMAC secret (keep it "
                   "private); default: random per run, never stored")
    p.set_defaults(fn=cmd_scrub)

    p = sub.add_parser("publish", help="copy scrubbed files, refuse anything else")
    p.add_argument("--src", type=Path, default=REAL / "out" / "scrubbed")
    p.add_argument("--dst", type=Path, default=REAL / "out" / "published")
    p.set_defaults(fn=cmd_publish)
    return ap


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
