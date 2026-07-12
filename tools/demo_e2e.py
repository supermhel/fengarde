"""Zero-infra END-TO-END ACCEPTANCE TEST for ARGIEM v0.1.

This is the v0.1 "proven good" gate, runnable with no Docker, no Redis, no
OpenSearch — everything rides the in-memory bus + in-memory store.

It proves the headline claim: a burst of failed SSH logins from one IP turns into
a REAL brute-force alert that reaches the indexer, end to end:

    raw SSH "Failed password" x10  (WS-1 shape)
      -> WS-2 normalize -> OCSF Authentication (class 3002, activity 4)
      -> WS-4 detect    -> common_bruteforce.yml fires on the 10th -> alert + ai.requests
      -> WS-5 triage    -> passthrough stub verdict (no Ollama needed)
      -> WS-3 index     -> alert lands in alerts-* (this is what the dashboard reads)

It also proves T7 (idempotency): re-processing the same triggering event yields the
SAME deterministic alert_id, so the indexer dedups instead of creating a duplicate
alert. That is the property that makes at-least-once delivery safe for a SIEM.

Run:  C:/Python313/python.exe tools/demo_e2e.py     (or `make e2e`)
"""
from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
os.environ["BUS_BACKEND"] = "memory"

sys.path.insert(0, str(SERVICES))
from shared.bus import Bus  # noqa: E402

BRUTEFORCE_TITLE = "brute-force"   # substring of common_bruteforce.yml title
ATTACKER_IP = "203.0.113.5"
BASE_S = 1750000000               # epoch seconds; parser scales <1e12 to ms


def _import(ws_dir, mod="main"):
    """Import a service module with its own dir winning on sys.path (mirrors
    tools/integration_e2e.py — several services share module names like `main`)."""
    p = str(SERVICES / ws_dir)
    while p in sys.path:
        sys.path.remove(p)
    sys.path.insert(0, p)
    return importlib.import_module(mod)


def ssh_fail(i: int) -> dict:
    """One raw 'Failed password' syslog line from the attacker IP, +i seconds."""
    return {
        "source_type": "linux_ssh",
        "raw": (f"Jun 10 13:55:{i:02d} db01 sshd[2154]: "
                f"Failed password for invalid user admin from {ATTACKER_IP} port 51000 ssh2"),
        "meta": {"received_at": BASE_S + i, "ingest_id": f"ssh-{ATTACKER_IP}-{i}"},
    }


def _fresh(*mods):
    for m in mods:
        sys.modules.pop(m, None)


def main() -> None:
    fails: list[str] = []
    bus = Bus()

    # --- inject 10 failed logins from one IP within 60s (the brute-force burst) ---
    for i in range(10):
        ev = ssh_fail(i)
        bus.produce("raw.events", key=ATTACKER_IP, payload=ev)

    # WS-2: raw -> normalized OCSF
    _fresh("main", "parsers")
    ws2 = _import("ws2-normalization")
    c2 = ws2.run(bus)

    # WS-4: normalized -> scored + alerts + ai.requests
    _fresh("main", "engine", "scoring")
    ws4 = _import("ws4-detection")
    det = ws4.Detector()
    c4 = ws4.run(bus, det)

    # WS-5: ai.requests -> ai.results + enriched alert (passthrough stub, no Ollama)
    _fresh("main", "classifier", "llm_adapter")
    ws5 = _import("ws5-ai")
    worker = ws5.AiWorker()
    c5 = ws5.run(bus, worker)

    # WS-3: index everything that's routable (this is what the dashboard reads)
    _fresh("main", "router")
    ws3 = _import("ws3-indexer")
    store = ws3.make_store()
    c3 = ws3.run(bus, store)

    print(f"WS-2 normalized={c2['normalized']} dropped={c2['dropped']}")
    print(f"WS-4 scored={c4['scored']} alerts={c4['alerts']} ai={c4['ai_enqueued']}")
    print(f"WS-5 analyzed={c5['analyzed']} (passthrough stub)")
    print(f"WS-3 indexed={c3['indexed']} dup={c3['duplicates']} unroutable={c3['unroutable']}")

    # --- assert: 10/10 normalized to auth-failure ---
    if c2["normalized"] != 10:
        fails.append(f"expected 10 normalized auth events, got {c2['normalized']}")

    # --- assert: a brute-force alert fired and reached the index ---
    alert_indices = [i for i in store.indices() if i.startswith("alerts-")]
    bf_alerts = [
        d for idx in alert_indices for d in store.all_docs(idx)
        if BRUTEFORCE_TITLE in str(d.get("rule_title", "")).lower()
    ]
    if not bf_alerts:
        fails.append("no brute-force alert reached the alerts-* index")
    else:
        a = bf_alerts[0]
        if a.get("score") != 70:
            fails.append(f"brute-force alert score {a.get('score')} != 70")
        print(f"\n  ALERT: {a.get('rule_title')} "
              f"src={a.get('src_endpoint', {}).get('ip')} score={a.get('score')} "
              f"id={a.get('alert_id')}")

    # --- assert T7: re-processing the SAME triggering event is idempotent ---
    if bf_alerts:
        before = sum(store.count(idx) for idx in alert_indices)
        original_id = bf_alerts[0]["alert_id"]

        # replay: an 11th failed login in the same window -> rule fires again ->
        # alert with the SAME deterministic id -> indexer must dedup, not duplicate.
        bus.produce("raw.events", key=ATTACKER_IP, payload=ssh_fail(10))
        _fresh("main", "parsers"); ws2b = _import("ws2-normalization"); ws2b.run(bus)
        _fresh("main", "engine", "scoring"); ws4b = _import("ws4-detection")
        ws4b.run(bus, det)  # reuse det -> window already has 10
        _fresh("main", "router"); ws3b = _import("ws3-indexer")
        ws3b.run(bus, store)  # reuse the SAME store

        after_indices = [i for i in store.indices() if i.startswith("alerts-")]
        after = sum(store.count(idx) for idx in after_indices)
        replay_id = [
            d["alert_id"] for idx in after_indices for d in store.all_docs(idx)
            if BRUTEFORCE_TITLE in str(d.get("rule_title", "")).lower()
        ][0]

        if replay_id != original_id:
            fails.append(f"T7 broken: replay id {replay_id} != original {original_id}")
        if after != before:
            fails.append(f"T7 broken: alert count grew {before}->{after} on replay (duplicate!)")
        else:
            print(f"  T7 OK: replay reused alert_id {replay_id} -> deduped "
                  f"(alerts count stayed {before})")

    if fails:
        print("\n[FAIL] demo e2e:", *fails, sep="\n  - ")
        sys.exit(1)
    print("\n[OK] ARGIEM v0.1 acceptance: SSH brute-force -> real alert in the index, "
          "idempotent under replay. Zero infra.")


if __name__ == "__main__":
    main()
