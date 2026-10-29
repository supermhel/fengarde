"""tools/build_ai_ot_fixtures.py: the demo's AI-to-OT scenario fixture comes from the real pipeline and is not stale.

Zero infra. Builds the fixture in-process and asserts (a) the chain the project's headline story claims (alarms,
incidents with their member counts, entity graph, hash-chained evidence that verifies, DE/EN NIS2 drafts, AI verdicts
labelled with the stub backend) and (b) that the committed fixtures-ai-ot.json equals a fresh build apart from the
wall-clock stamps, so editing a rule, parser or the twin without regenerating fails here.

Run: python tools/test_build_ai_ot_fixtures.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import build_ai_ot_fixtures as b  # noqa: E402

FAILS: list[str] = []
WALL_CLOCK = {"recordedAt", "generatedAt", "built_at_ms", "generated_at"}


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def strip(x):
    if isinstance(x, dict):
        return {k: strip(v) for k, v in x.items() if k not in WALL_CLOCK}
    if isinstance(x, list):
        return [strip(v) for v in x]
    return x


def main() -> int:
    fx = b.build()
    alerts = [h["_source"] for h in fx["alerts"]["hits"]["hits"]]
    titles = [a["rule_title"] for a in sorted(alerts, key=lambda a: a["time"])]
    check(len(alerts) == 7, f"7 rule alerts expected, got {len(alerts)}")
    for needle in ("n8n new webhook exposed", "outside business hours", "prompt-injection indicator",
                   "non-allowlisted domain", "credential material", "Modbus/TCP write outside the expected address range"):
        check(any(needle in t for t in titles), f"no alert title contains {needle!r}: {titles}")

    members = {i["incident_id"]: i["member_count"] for i in fx["incidents"]["incidents"]}
    check(members == {"default:ip:10.20.0.50:20271": 7, "default:actor:ot-engineer:20271": 5}, f"incidents {members}")
    for iid in members:
        g = fx["graph"][iid]
        check(g and g["nodes"] and g["edges"], f"{iid}: empty graph")
        ev = fx["evidence"][iid]
        check(ev and ev["blocks"], f"{iid}: no evidence blocks")
        for lg in ("en", "de"):
            check(fx["incidentReport"].get(f"{iid}|{lg}"), f"{iid}: no {lg} incident report")
        for n in g["nodes"]:
            check(fx["entity"].get(n["entity_id"]), f"{iid}: entity {n['entity_id'][:8]} missing")
    for a in alerts:
        for lg in ("de", "en"):
            key = f"{a['alert_id']}|?template=nis2&stage=notification&lang={lg}"
            check(fx["reports"].get(key), f"{a['alert_id']}: no {lg} NIS2 draft")

    ai = [h["_source"] for h in fx["ai"]["hits"]["hits"]]
    check(ai and all((x["ai"] or {}).get("engine") == "stub" for x in ai), "every AI verdict must say engine=stub")
    check(fx["meta"]["aiBackend"] == "stub", "meta.aiBackend must be stub")
    covered = {e for x in ai for e in x["event_ids"]}
    check(all(a.get("trigger_event_id") in covered for a in alerts), "every alarm must be coverable by an AI verdict doc")

    committed = json.loads(b.OUT.read_text(encoding="utf-8"))
    check(strip(committed) == strip(fx), f"{b.OUT.name} is stale: rerun python tools/build_ai_ot_fixtures.py")

    if FAILS:
        print("[FAIL] build_ai_ot_fixtures:", *FAILS, sep="\n  - ")
        return 1
    print("[OK] build_ai_ot_fixtures: 7 alerts, 2 incidents (7/5 members), evidence + EN/DE reports, stub AI, fixture current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
