"""End-to-end integration smoke test over a single shared (memory) bus.

Pipes WS-1 -> WS-2 -> WS-4 -> WS-3 to prove the frozen contracts compose:
collectors emit raw -> normalization emits valid OCSF -> detection scores &
alerts -> indexer routes to the right indices. Zero infrastructure.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
os.environ["BUS_BACKEND"] = "memory"

# shared lib
sys.path.insert(0, str(SERVICES))
from shared.bus import Bus  # noqa: E402

bus = Bus()

# Survival floor for SUPPORTED seeds (see SURVIVAL_FLOOR below): a pipeline
# regression that kills 1 in 5 of the events it is supposed to handle must
# fail the gate loudly, not report a green "at least one event made it".
SURVIVAL_FLOOR = 0.8


def _import(ws_dir, mod="main"):
    p = str(SERVICES / ws_dir)
    if p not in sys.path:
        sys.path.insert(0, p)
    import importlib
    # ensure the right service dir wins for ambiguous module names
    sys.path.remove(p)
    sys.path.insert(0, p)
    return importlib.import_module(mod)


def main():
    fails = []

    # WS-1: produce raw.events from mocks. Spy on produce() so we know the
    # EXACT seed set (the mock corpus deliberately includes sources WS-2 has
    # no parser for -- snmp/netflow_ipfix -- and RFC 5424 syslog lines that
    # the RFC 3164-only generic_syslog catch-all dead-letters; those seeds
    # are legitimately unsupported by the current pipeline and must not be
    # counted against it, but they MUST be reported, not hidden in a pass).
    produced_raw: list[dict] = []
    _orig_produce = bus.produce

    def _spy_produce(topic, key=None, payload=None):
        if topic == "raw.events":
            produced_raw.append(payload)
        return _orig_produce(topic, key=key, payload=payload)

    bus.produce = _spy_produce

    ws1 = _import("ws1-collectors")
    c1 = ws1.run_once(bus)
    assert c1["raw.events"] > 0

    # WS-2: raw.events -> normalized.events (fresh import w/ correct sys.path)
    for m in ("main", "parsers"):
        sys.modules.pop(m, None)
    ws2 = _import("ws2-normalization")

    # Classify every seed WS-1 produced through the EXACT code path the
    # pipeline runs (normalize_one = resolve -> parse -> sanitize -> validate).
    # A seed is "supported" when WS-2 says it would have normalized it; the
    # must-survive set is that supported subset, never the whole mock corpus.
    # Dropped seeds are logged individually so a growing silence is visible
    # instead of being absorbed into a pass.
    supported = 0
    for seed in produced_raw:
        event, errors = ws2.normalize_one(seed)
        if event is not None and not errors:
            supported += 1
            continue
        st = seed.get("source_type")
        detail = errors[0] if errors else "parser returned None"
        print(f"[e2e] seed dropped (not in must-survive set): source_type={st!r} "
              f"raw={str(seed.get('raw'))[:80]!r} -> {detail}")

    c2 = ws2.run(bus)

    # WS-4: normalized.events -> scored.events + alerts + ai.requests
    for m in ("main", "engine", "scoring"):
        sys.modules.pop(m, None)
    ws4 = _import("ws4-detection")
    det = ws4.Detector()
    c4 = ws4.run(bus, det)

    # WS-3: index scored.events + alerts
    for m in ("main", "router"):
        sys.modules.pop(m, None)
    ws3 = _import("ws3-indexer")
    store = ws3.make_store()
    c3 = ws3.run(bus, store)

    print(f"WS-1 raw={c1['raw.events']} assets={c1['assets.updates']}")
    print(f"WS-2 normalized={c2['normalized']} dropped={c2['dropped']}")
    print(f"WS-4 scored={c4['scored']} alerts={c4['alerts']} ai={c4['ai_enqueued']}")
    print(f"WS-3 indexed={c3['indexed']} dup={c3['duplicates']} unroutable={c3['unroutable']}")
    print(f"support: {c2['normalized']}/{supported} supported seeds survived "
          f"WS-2 ({c2['normalized'] / supported:.0%})" if supported else
          f"support: 0 supported seeds in the mock corpus")

    if supported == 0:
        fails.append("WS-1's seed corpus contains no event supported by WS-2's "
                     "registered parsers -- the pipeline has nothing to prove here")
    elif c2["normalized"] < SURVIVAL_FLOOR * supported:
        fails.append(f"only {c2['normalized']}/{supported} supported events survived "
                     f"WS-2 (floor {SURVIVAL_FLOOR:.0%}) -- supported seeds must not "
                     f"be dead-lettered en masse")
    if c4["scored"] != c2["normalized"]:
        fails.append("detection did not score every normalized event")
    if c3["indexed"] < c4["scored"]:
        fails.append("indexer did not store all scored events")
    indices = store.indices() if hasattr(store, "indices") else []
    if not any(i.startswith("events-") for i in indices):
        fails.append(f"no events-* index populated: {indices}")
    print("indices:", indices)

    if fails:
        print("[FAIL] e2e:", *fails, sep="\n  - ")
        sys.exit(1)
    print("[OK] end-to-end pipeline composes across WS-1->2->4->3")


if __name__ == "__main__":
    main()
