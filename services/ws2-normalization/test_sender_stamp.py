"""ADR-012 WP 2: WS-2 copies ws1 meta.shipper_ip / meta.source onto siem.sender.

The sender is the authenticated-sender part of a causal key hash, so it must
come ONLY from ws1's meta (never from the record body), be absent when meta
lacks it, and the event must still validate against Contract A.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))
os.environ["BUS_BACKEND"] = "memory"

import main as ws2  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


LINE = ("Jun 10 13:55:36 db01 sshd[2154]: Failed password for invalid user "
        "admin from 203.0.113.5 port 51000 ssh2")


def run(meta):
    raw = {"source_type": "linux_ssh", "raw": LINE, "meta": meta}
    event, errors = ws2.normalize_one(raw)
    check(event is not None, f"event produced for meta={meta}")
    check(not errors, f"event validates for meta={meta}: {errors}")
    return event or {}


def main():
    ev = run({"received_at": 1700000000, "ingest_id": "s1", "shipper_ip": "10.1.2.3", "source": "plc-line-3"})
    check(ev.get("siem", {}).get("sender") == {"ip": "10.1.2.3", "source": "plc-line-3"},
          f"sender copied from meta, got {ev.get('siem', {}).get('sender')}")

    ev = run({"received_at": 1700000000, "ingest_id": "s2", "shipper_ip": "10.1.2.3"})
    check(ev["siem"].get("sender") == {"ip": "10.1.2.3"}, "ip only: no invented source key")

    ev = run({"received_at": 1700000000, "ingest_id": "s3", "source": "label-only"})
    check(ev["siem"].get("sender") == {"source": "label-only"}, "source only: no invented ip key")

    ev = run({"received_at": 1700000000, "ingest_id": "s4"})
    check("sender" not in ev["siem"], "meta without shipper_ip/source: siem.sender absent")

    raw = {"source_type": "linux_ssh", "raw": LINE}
    ev, errors = ws2.normalize_one(raw)
    check(ev is not None and "sender" not in ev["siem"], "no meta at all: siem.sender absent")

    for bad in (None, "", 42, ["10.0.0.1"], {"x": 1}):
        ev = run({"received_at": 1700000000, "ingest_id": "s5", "shipper_ip": bad, "source": bad})
        check("sender" not in ev["siem"], f"unusable meta values {bad!r} give no sender")

    ev = run({"received_at": 1700000000, "ingest_id": "s6", "shipper_ip": "10.0.0.9", "source": "ev\x1b[31mil\x07"})
    src = ev["siem"].get("sender", {}).get("source", "")
    check("\x1b" not in src and "\x07" not in src, f"sender.source sanitized, got {src!r}")

    # the record body can never choose the sender
    raw = {"source_type": "linux_ssh", "raw": LINE, "siem": {"sender": {"ip": "6.6.6.6"}},
           "shipper_ip": "6.6.6.6", "meta": {"received_at": 1700000000, "ingest_id": "s7"}}
    ev, _ = ws2.normalize_one(raw)
    check(ev is not None and "sender" not in ev["siem"], "body-supplied sender fields are ignored")

    # Contract A: the ADR-012 additive optional fields validate; wrong types do not;
    # an event without them (every old fixture) still validates.
    base, _ = ws2.normalize_one({"source_type": "linux_ssh", "raw": LINE,
                                 "meta": {"received_at": 1700000000, "ingest_id": "s8"}})
    check(base is not None and not ws2.validate(base), "event without ADR-012 fields validates")
    rich = {**base, "actor": {**base.get("actor", {}),
                              "process": {"name": "cmd.exe", "pid": 4, "uid": "3b1f2c4d-5e6a-7b8c-9d0e-1f2a3b4c5d6e",
                                          "parent_process": {"uid": "x", "pid": 1, "name": "p"}},
                              "session": {"uid": "3e7"}},
            "connection_info": {"uid": "1234"},
            "siem": {**base["siem"], "key_scope": {"host": "h", "sensor": "s"}, "sender": {"ip": "1.2.3.4", "source": "x"}}}
    check(not ws2.validate(rich), f"ADR-012 fields validate: {ws2.validate(rich)}")
    bad = {**rich, "connection_info": {"uid": 1234}}
    check(bool(ws2.validate(bad)), "connection_info.uid must be a string")
    bad = {**rich, "siem": {**rich["siem"], "sender": {"ip": 5}}}
    check(bool(ws2.validate(bad)), "siem.sender.ip must be a string")

    if FAILS:
        print(f"\n[FAIL] ws2 sender stamp: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] ws2 siem.sender stamp tests PASS")


if __name__ == "__main__":
    main()
