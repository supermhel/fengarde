"""Builds the demo console's SECOND scenario (AI-to-OT, generated, not recorded) from REAL pipeline code, zero infrastructure.

    python tools/build_ai_ot_fixtures.py            # writes services/ws7-dashboard/app/src/demo/fixtures-ai-ot.json

What is real and what is generated (docs/console-demo.md says the same, in prose):

  * INPUT is synthetic: the evaluation twin's deterministic raw source records (eval/twin/scenario.py, seed 7:
    n8n audit, MCP/agent tool calls, Modbus frames, one web-proxy record no parser exists for). No live attack.
  * EVERYTHING AFTER THE INPUT is the production code, run in-process on the in-memory bus:
    WS-2 normalize -> WS-4 detect -> WS-5 triage (StubLLM, no model) -> WS-8 correlate (incidents + entity graph)
    -> WS-9 resolve (entities) -> WS-3 index. The console's API answers (alerts, incidents, graph, evidence package,
    incident report, NIS2 drafts in EN and DE, entities) are then fetched over HTTP from the real WS-3 handler
    (services/ws3-indexer/triage_api.py) bound to that store. Nothing is hand-written.
  * GENERATED, not recorded from a live stack: the whole run (no Docker/OpenSearch/Redis). Storage is MemoryStore, so
    the alerts/events lists are shaped like the console's OpenSearch search answers by this script (hits.hits with
    _index/_id/_source, indexes named by the real WS-3 router). The WS-8 clock is fixed (as in eval/twin) because the
    twin's timestamps are in the past; WS-4's stateful windows run on event time.
  * Not part of this scenario: the inventory, users, audit trail and service-health panels come from the first
    (recorded lab) scenario; the demo reuses them unchanged.
"""
from __future__ import annotations

import importlib
import importlib.util
import json
import os
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
OUT = ROOT / "services" / "ws7-dashboard" / "app" / "src" / "demo" / "fixtures-ai-ot.json"
os.environ["BUS_BACKEND"] = "memory"
os.environ.setdefault("FENGARDE_AUDIT_LOG", str(Path(os.getenv("TEMP", "/tmp")) / "fengarde-ai-ot-fixture-audit.jsonl"))
SEED = 7
TENANT = "default"
sys.path.insert(0, str(SERVICES))
sys.path.insert(0, str(ROOT / "eval" / "twin"))

from shared.bus import Bus  # noqa: E402


def _import(ws_dir: str, *fresh: str):
    """Import a service's main with its own dir first on sys.path (several services share the module name `main`)."""
    for m in ("main", *fresh):
        sys.modules.pop(m, None)
    p = str(SERVICES / ws_dir)
    while p in sys.path:
        sys.path.remove(p)
    sys.path.insert(0, p)
    return importlib.import_module("main")


def _load_file(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader, path
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def raw_payloads() -> list[dict]:
    import scenario  # eval/twin/scenario.py: the SAME deterministic raw records the twin grades
    payloads, _sensors, _notes, _baseline = scenario._build_chain_payloads(SEED)
    out = []
    for _spec, p in payloads:
        p = json.loads(json.dumps(p))
        p["meta"]["tenant_id"] = TENANT  # the console reads the default tenant
        out.append(p)
    return out


def build() -> dict:
    bus = Bus()
    for p in raw_payloads():
        bus.produce("raw.events", key=p["meta"].get("ip"), payload=p)

    ws2 = _import("ws2-normalization", "parsers")
    c2 = ws2.run(bus)

    ws4 = _import("ws4-detection", "engine", "scoring")
    c4 = ws4.run(bus, ws4.Detector(plugin_rule_dirs=[]))

    ws5 = _import("ws5-ai", "classifier", "llm_adapter")
    worker = ws5.AiWorker()
    c5 = ws5.run(bus, worker)

    # WS-8 and WS-9 each read the `alerts` topic in their own consumer group, exactly as deployed.
    alerts = [m.payload for m in bus.consume("alerts", group="cg-correlate")]
    last_s = max(int(a.get("time") or 0) for a in alerts) / 1000.0
    sys.path.insert(0, str(SERVICES / "ws8-correlation"))
    ws8 = importlib.import_module("correlator")
    sys.path.insert(0, str(SERVICES / "ws9-resolver"))
    ws9 = importlib.import_module("resolver")
    from shared.identity_aliases import configure as configure_aliases
    configure_aliases()
    now_s = last_s + 3600  # fixed "now" one hour after the last alert: the twin's timestamps are in the past
    corr = ws8.Correlator(now_fn=lambda: now_s)
    m8 = _load_file("ws8_main", SERVICES / "ws8-correlation" / "main.py")
    h8 = m8.make_handler(bus, corr)
    for a in alerts:
        h8(a)
    m9 = _load_file("ws9_main", SERVICES / "ws9-resolver" / "main.py")
    resolver = ws9.EntityResolver(now_fn=lambda: now_s)
    h9 = m9.make_handler(bus, resolver)
    for a in alerts:
        h9(a)

    ws3 = _import("ws3-indexer", "router")
    store = ws3.make_store()
    # the alerts WS-8/WS-9 read were consumed from the bus by this script; WS-3 reads its own copy of the topic
    c3 = ws3.run(bus, store)
    print(f"WS-2 normalized={c2['normalized']} dropped={c2['dropped']} | WS-4 alerts={c4['alerts']} ai={c4['ai_enqueued']} "
          f"| WS-5 analyzed={c5['analyzed']} | WS-3 indexed={c3['indexed']} dup={c3['duplicates']}")

    # ---- the console's answers, from the real WS-3 HTTP handler bound to this store --------------------------------
    import triage_api
    import audit
    import rules_view
    handler = triage_api.make_handler(store, audit_log=audit.AuditLog(os.environ["FENGARDE_AUDIT_LOG"]))
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"

    def call(path: str, post: bool = False):
        req = urllib.request.Request(base + path, data=b"" if post else None, method="POST" if post else "GET")
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read())
        except Exception as exc:  # noqa: BLE001
            print(f"  [warn] {path}: {exc}")
            return None

    def hits_of(prefix: str, keep=lambda d: True):
        rows = []
        for idx in sorted(store.indices()):
            if idx.startswith(prefix):
                for doc_id in sorted(store._indices[idx]):  # noqa: SLF001 (MemoryStore internals: no list-all API)
                    doc = store._indices[idx][doc_id]  # noqa: SLF001
                    if keep(doc):
                        rows.append({"_index": idx, "_id": doc_id, "_score": None, "_source": doc, "sort": [doc.get("time")]})
        rows.sort(key=lambda h: -(h["_source"].get("time") or 0))
        total = {"value": len(rows), "relation": "eq"}
        return {"took": 1, "timed_out": False, "hits": {"total": total, "max_score": None, "hits": rows}}

    # the same selections the console's nginx proxy sends to OpenSearch (templates/default.conf.template):
    # /api/alerts = docs that have a rule_title; /api/ai-triage = alert_id prefixed "ai-" (WS-5's verdict docs)
    al = hits_of("alerts-", lambda d: "rule_title" in d)
    ai_rows = hits_of("alerts-", lambda d: str(d.get("alert_id", "")).startswith("ai-"))
    ev = hits_of("events-")
    atk_alerts = [h["_source"] for h in al["hits"]["hits"]]
    atk_events = [h["_source"] for h in ev["hits"]["hits"]]
    t0 = min(e["time"] for e in atk_events)

    inc = call(f"/incidents?tenant_id={TENANT}")
    fx = {
        "meta": {
            "scenario": "ai-ot", "generatedAt": int(time.time() * 1000), "attacker": "10.20.0.50", "t0": t0,
            "timeScale": 12,  # replay compresses the twin's 60 s between steps to 5 s; evidence blocks keep the original times
            "note": ("Synthetic AI-to-OT chain: the evaluation twin's deterministic raw records (seed 7) run through the real "
                     "WS-2/4/5/8/9/3 code in-process. Not recorded from a live stack, not a real attack."),
            "attackAlerts": len(atk_alerts), "attackEvents": len(atk_events), "aiBackend": "stub",
        },
        "alerts": al, "events": ev, "ai": ai_rows, "incidents": inc,
        "rules": {"rules": rules_view.list_rule_summaries(TENANT), "count": None},
        "graph": {}, "evidence": {}, "entity": {}, "incidentReport": {}, "reports": {},
    }
    fx["rules"]["count"] = len(fx["rules"]["rules"])
    for i in inc["incidents"]:
        iid = i["incident_id"]
        q = f"/incidents/{urllib.parse.quote(iid, safe=':')}"
        fx["graph"][iid] = call(f"{q}/graph?tenant_id={TENANT}")
        fx["evidence"][iid] = call(f"{q}/evidence?tenant_id={TENANT}")
        for lg in ("en", "de"):
            fx["incidentReport"][f"{iid}|{lg}"] = call(f"{q}/report?lang={lg}&tenant_id={TENANT}", post=True)
        for n in (fx["graph"][iid] or {}).get("nodes") or []:
            if n["entity_id"] not in fx["entity"]:
                fx["entity"][n["entity_id"]] = call(f"/entities/{n['entity_id']}?tenant_id={TENANT}")
    stages = ("early_warning", "notification", "final_report")
    queries = [""] + [f"?template=nis2&stage={s}&lang={lg}" for s in stages for lg in ("de", "en")]
    for a in atk_alerts:
        aid = urllib.parse.quote(a["alert_id"], safe=":")
        for qs in queries:
            fx["reports"][f"{a['alert_id']}|{qs}"] = call(f"/alerts/{aid}/report{qs}", post=True)
    srv.shutdown()

    return fx


def main() -> None:
    out = Path(sys.argv[sys.argv.index("--out") + 1]) if "--out" in sys.argv else OUT
    fx = build()
    out.write_text(json.dumps(fx), encoding="utf-8")
    print(f"wrote {out} ({out.stat().st_size // 1024} KB)")
    atk_alerts = [h["_source"] for h in fx["alerts"]["hits"]["hits"]]
    inc, t0 = fx["incidents"], fx["meta"]["t0"]
    n_events = len(fx["events"]["hits"]["hits"])
    print(f"  {len(atk_alerts)} alerts, {n_events} events, {len(inc['incidents'])} incidents, {len(fx['reports'])} reports")
    for a in sorted(atk_alerts, key=lambda x: x["time"]):
        tactic = (a.get("mitre") or {}).get("tactic")
        engine = (a.get("ai") or {}).get("engine")
        print(f"  alert t+{(a['time'] - t0) // 1000:>4}s  {a['level']:<8} {a['rule_title']}  [{tactic}]  ai={engine}")
    for i in inc["incidents"]:
        print(f"  incident {i['incident_id']}  members={i['member_count']} tactics={i['tactics']}")


if __name__ == "__main__":
    main()
