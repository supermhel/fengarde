"""M4 gate: automated two-tenant isolation test -- same stack, isolated data,
isolated alerts (docs/superpowers/specs/2026-07-15-fengarde-combined-plan.md).

Proves, on ONE shared bus + ONE shared store (exactly what a real MSP
deployment runs -- multiple tenants on shared infrastructure, not one stack
per customer):

  1. Two tenants' events land in DIFFERENT OpenSearch indices (router.py's
     tenant-scoped naming) -- never mixed into the same index.
  2. Two tenants' alerts land in DIFFERENT indices, each carrying the
     correct tenant_id (services/ws4-detection/main.py::make_alert).
  3. A tenant-scoped query (the index-name prefix an API/dashboard would use
     once it knows the caller's tenant, M4.2/M4.3) returns ONLY that
     tenant's alerts -- never the other tenant's.
  4. Per-tenant rule enablement actually changes behavior: tenant A has the
     brute-force rule disabled (contracts/tenants/<id>.yml), tenant B does
     not -- an otherwise-identical attack fires for B and NOT for A.

Tenant identity here is stamped explicitly on each raw event's
``meta["tenant_id"]`` (envelope v1's ``stamp_meta()`` only fills this in
when ABSENT -- see services/shared/envelope.py -- so an explicit per-event
value always wins). This is the realistic mechanism for a shared-listener
MSP deployment: something upstream of raw.events (a per-customer collector
port, a source-IP-to-tenant lookup) decides which tenant an inbound log
belongs to and sets it explicitly, rather than the single-process
TENANT_ID env var (which only supports one tenant per whole deployment --
the pre-M4 default, still the right choice for a single-tenant install).

Run: python tools/test_multi_tenant_isolation.py
"""
from __future__ import annotations

import importlib
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
os.environ["BUS_BACKEND"] = "memory"
sys.path.insert(0, str(SERVICES))

from shared.bus import Bus  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _import(ws_dir, mod="main"):
    p = str(SERVICES / ws_dir)
    if p in sys.path:
        sys.path.remove(p)
    sys.path.insert(0, p)
    for m in ("main", "parsers", "engine", "scoring", "router", "tenants"):
        sys.modules.pop(m, None)
    return importlib.import_module(mod)


def _brute_force_events(tenant: str, attacker_ip: str, base_s: int, count: int = 10,
                        tag: str = "") -> list[dict]:
    """`count` failed SSH logins (common_bruteforce.yml's threshold is 10),
    all explicitly tagged with one tenant, shaped like WS-1's real output.
    `tag` disambiguates ingest_id/trace_id across calls sharing one tenant+IP
    combination within a single test."""
    events = []
    for i in range(count):
        events.append({
            "source_type": "linux_ssh",
            "raw": (f"Jun 10 13:55:{i:02d} db01 sshd[2154]: Failed password for "
                    f"invalid user admin from {attacker_ip} port 51000 ssh2"),
            "meta": {"received_at": base_s + i, "ingest_id": f"mt-{tenant}-{tag}-{i}",
                     "tenant_id": tenant, "trace_id": f"trace-{tenant}-{tag}-{i}"},
        })
    return events


def run():
    bus = Bus()
    # Real wall-clock-relative time, not a fixed constant: the P0 hardening
    # pass's clock-skew guard (engine.py::_MAX_CLOCK_SKEW_MS, 5 minutes)
    # rejects a stateful rule's window count on any event timestamped
    # implausibly far from actual "now" -- a fixed distant-past/future base_s
    # would silently zero out every match here, not raise.
    base_s = int(time.time())

    # tenant "acme" gets brute-force DISABLED via a real tenant config file;
    # tenant "globex" has no config at all (fail-open: every global rule applies).
    tenants_dir = Path(tempfile.mkdtemp())
    (tenants_dir / "acme.yml").write_text(
        "disabled_rules:\n  - a5c8f9d2-1b3e-4a6f-9c7d-2e4b6a8c0d1f\n",  # placeholder, overwritten below
        encoding="utf-8",
    )

    # look up the REAL common_bruteforce.yml id so the disablement is genuine,
    # not a placeholder that happens to match nothing.
    ws4_engine_path = str(SERVICES / "ws4-detection")
    sys.path.insert(0, ws4_engine_path)
    from engine import load_rules  # noqa: E402
    rules_dir = ROOT / "contracts" / "rules"
    bruteforce_id = next(r.id for r in load_rules(rules_dir) if "brute-force" in r.title.lower())
    (tenants_dir / "acme.yml").write_text(
        f"disabled_rules:\n  - {bruteforce_id}\n", encoding="utf-8")

    # --- WS-1 (skip; construct raw events directly, see module docstring) ---
    for ev in _brute_force_events("acme", "198.51.100.10", base_s):
        bus.produce("raw.events", key="acme", payload=ev)
    for ev in _brute_force_events("globex", "198.51.100.20", base_s):
        bus.produce("raw.events", key="globex", payload=ev)

    # --- WS-2: normalize ---
    ws2 = _import("ws2-normalization")
    c2 = ws2.run(bus)
    check(c2["normalized"] == 20, f"expected 20 events normalized (10/tenant), got {c2['normalized']}")

    # --- WS-4: detect, tenant-aware (acme has brute-force disabled) ---
    ws4 = _import("ws4-detection")
    det = ws4.Detector(tenants_dir=tenants_dir)
    c4 = ws4.run(bus, det)
    check(c4["alerts"] == 1,
          f"expected exactly 1 alert (globex's brute-force; acme's is disabled), got {c4['alerts']}")

    # --- WS-3: index ---
    ws3 = _import("ws3-indexer")
    store = ws3.make_store()
    ws3.run(bus, store)

    all_indices = store.indices()

    # 1+2: events and alerts must land in TENANT-SCOPED indices, never mixed.
    acme_event_indices = [i for i in all_indices if i.startswith("events-common-acme-")]
    globex_event_indices = [i for i in all_indices if i.startswith("events-common-globex-")]
    check(len(acme_event_indices) == 1,
          f"acme events must land in exactly one events-common-acme-* index, got {acme_event_indices}")
    check(len(globex_event_indices) == 1,
          f"globex events must land in exactly one events-common-globex-* index, got {globex_event_indices}")
    check(store.count(acme_event_indices[0]) == 10 if acme_event_indices else False,
          "acme's events-common-acme-* index must contain exactly acme's 10 events")
    check(store.count(globex_event_indices[0]) == 10 if globex_event_indices else False,
          "globex's events-common-globex-* index must contain exactly globex's 10 events")

    # No untenanted/default index leaked either tenant's events.
    default_event_indices = [i for i in all_indices
                              if i.startswith("events-common-") and "-acme-" not in i and "-globex-" not in i]
    check(default_event_indices == [] or all(store.count(i) == 0 for i in default_event_indices),
          f"no event should land in a non-tenant-scoped index, found {default_event_indices}")

    # 3: alert isolation -- globex's alert must be in a globex-scoped index,
    # and a tenant-scoped query pattern for "acme" must find NOTHING (acme's
    # rule was disabled, so there's no alert to isolate -- proving both the
    # index-naming isolation AND the rule-enablement mechanism in one check).
    globex_alert_indices = [i for i in all_indices if i.startswith("alerts-globex-")]
    acme_alert_indices = [i for i in all_indices if i.startswith("alerts-acme-")]
    check(len(globex_alert_indices) == 1,
          f"globex's alert must land in an alerts-globex-* index, got {globex_alert_indices}")
    check(acme_alert_indices == [],
          f"acme must have NO alert index at all (brute-force disabled for acme), got {acme_alert_indices}")

    if globex_alert_indices:
        globex_alerts = store.all_docs(globex_alert_indices[0])
        check(len(globex_alerts) == 1, "exactly one globex alert expected")
        check(globex_alerts[0].get("tenant_id") == "globex",
              f"globex's alert doc must carry tenant_id=globex, got {globex_alerts[0].get('tenant_id')}")
        check(globex_alerts[0].get("src_endpoint", {}).get("ip") == "198.51.100.20",
              "globex's alert must reference globex's attacker IP, not acme's")


def run_shared_group_key_isolation():
    """F1 regression: two tenants sharing a group_by value (the same source
    IP -- the normal case for an MSP, since RFC1918 ranges overlap across
    customers) must NOT pool their event counts into one stateful-rule
    window. Without tenant-namespacing the window counter key
    (services/ws4-detection/engine.py::evaluate), acme's 6 sub-threshold
    events + globex's 6 sub-threshold events on the SAME IP would sum to 12
    >= threshold(10) and fire a brute-force alert neither tenant earned on
    their own -- attributed to whichever tenant's event crossed the line.
    """
    bus = Bus()
    base_s = int(time.time())
    shared_ip = "198.51.100.99"

    # Neither tenant alone reaches the threshold (10); pooled, they would.
    for ev in _brute_force_events("acme", shared_ip, base_s, count=6, tag="a"):
        bus.produce("raw.events", key="acme", payload=ev)
    for ev in _brute_force_events("globex", shared_ip, base_s, count=6, tag="b"):
        bus.produce("raw.events", key="globex", payload=ev)

    ws2 = _import("ws2-normalization")
    c2 = ws2.run(bus)
    check(c2["normalized"] == 12, f"expected 12 events normalized (6/tenant), got {c2['normalized']}")

    ws4 = _import("ws4-detection")
    det = ws4.Detector(tenants_dir=Path(tempfile.mkdtemp()))  # no per-tenant disablement here
    c4 = ws4.run(bus, det)
    check(c4["alerts"] == 0,
          f"neither tenant reached the brute-force threshold alone -- pooling across "
          f"tenants on a shared IP must NOT fire an alert, got {c4['alerts']}")

    # Now prove each tenant CAN still independently reach ITS OWN threshold
    # on that same shared IP -- the fix must not just suppress firing
    # entirely, it must correctly scope the count per tenant.
    for ev in _brute_force_events("acme", shared_ip, base_s + 100, count=10, tag="c"):
        bus.produce("raw.events", key="acme", payload=ev)
    c2b = ws2.run(bus)
    check(c2b["normalized"] == 10, f"expected 10 more events normalized, got {c2b['normalized']}")
    c4b = ws4.run(bus, det)
    check(c4b["alerts"] == 1,
          f"acme alone reaching 10 events on the shared IP must fire exactly 1 alert, got {c4b['alerts']}")


def run_shared_bucket_alert_id_collision():
    """F1 follow-up (found by adversarial review of the F1 fix commit,
    2026-07-17): the window COUNTER key was namespaced by tenant, but
    Rule.alert_key() -- which computes the actual alert_id stored in
    OpenSearch/MemoryStore -- was not. Two tenants sharing a group_by value
    (the same source IP) whose bursts land in the SAME window-aligned time
    bucket produced the IDENTICAL alert_id. WS-3's find_alert()/find_report()
    search every alerts-* index by that id and return the FIRST match, so
    one tenant's alert became unreachable by id behind the other's,
    regardless of F3's tenant-scoped storage (the collision is on the
    lookup key, not on which index the doc physically lands in). This
    proves each tenant now gets a distinct alert_id, and that each tenant's
    OWN alert_id resolves to THEIR OWN doc via find_alert().
    """
    bus = Bus()
    base_s = int(time.time())
    shared_ip = "198.51.100.77"

    # Same base_s, same per-event offsets for both tenants -> both bursts
    # land in the exact same window-aligned bucket, the collision scenario.
    for ev in _brute_force_events("acme", shared_ip, base_s, count=10, tag="x"):
        bus.produce("raw.events", key="acme", payload=ev)
    for ev in _brute_force_events("globex", shared_ip, base_s, count=10, tag="y"):
        bus.produce("raw.events", key="globex", payload=ev)

    ws2 = _import("ws2-normalization")
    c2 = ws2.run(bus)
    check(c2["normalized"] == 20, f"expected 20 events normalized (10/tenant), got {c2['normalized']}")

    ws4 = _import("ws4-detection")
    det = ws4.Detector(tenants_dir=Path(tempfile.mkdtemp()))
    c4 = ws4.run(bus, det)
    check(c4["alerts"] == 2,
          f"both tenants independently cross threshold on the shared IP in the same "
          f"window bucket -- expected 2 alerts, got {c4['alerts']}")

    ws3 = _import("ws3-indexer")
    store = ws3.make_store()
    ws3.run(bus, store)

    acme_alert_indices = [i for i in store.indices() if i.startswith("alerts-acme-")]
    globex_alert_indices = [i for i in store.indices() if i.startswith("alerts-globex-")]
    check(len(acme_alert_indices) == 1, f"acme alert index missing/ambiguous: {acme_alert_indices}")
    check(len(globex_alert_indices) == 1, f"globex alert index missing/ambiguous: {globex_alert_indices}")
    if not (acme_alert_indices and globex_alert_indices):
        return

    acme_alert = store.all_docs(acme_alert_indices[0])[0]
    globex_alert = store.all_docs(globex_alert_indices[0])[0]
    check(acme_alert["alert_id"] != globex_alert["alert_id"],
          f"two tenants firing on the same shared-IP/bucket must get DISTINCT alert_ids, "
          f"both got {acme_alert['alert_id']!r}")

    # The real-world failure mode: find_alert() by id must resolve EACH
    # tenant's id to THEIR OWN doc, not be shadowed by the other tenant's.
    found_acme = store.find_alert(acme_alert["alert_id"])
    found_globex = store.find_alert(globex_alert["alert_id"])
    check(found_acme is not None and found_acme[1].get("tenant_id") == "acme",
          f"find_alert(acme's id) must resolve to acme's own doc, got {found_acme}")
    check(found_globex is not None and found_globex[1].get("tenant_id") == "globex",
          f"find_alert(globex's id) must resolve to globex's own doc, got {found_globex}")


def main():
    run()
    run_shared_group_key_isolation()
    run_shared_bucket_alert_id_collision()
    if FAILS:
        print(f"[FAIL] multi-tenant isolation: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] M4 gate: two-tenant isolation -- separate indices for events AND "
          "alerts, tenant_id correctly stamped, per-tenant rule disablement verified "
          "(acme's brute-force suppressed, globex's fires normally); shared-group-key "
          "(same source IP) does NOT pool event counts across tenants (F1 regression)")


if __name__ == "__main__":
    main()
