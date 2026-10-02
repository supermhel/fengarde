"""Companion rules: each closes ONE evasion that the multi-storyline evasion
search measured against its sibling, and this test proves BOTH halves on real
parser + enrichment output:

  (1) the SPLIT attack (the same burst spread over two source addresses / two
      accounts / two clients) is invisible to the sibling rule  -- the gap;
  (2) the companion rule fires on that same split attack         -- the fix;
  (3) the companion stays silent one event short of its threshold -- precision.

Without half (1) the companion could be a rule that merely fires; with it, the
test fails the day someone "improves" the sibling and silently removes the
reason the companion exists, and it fails the day the companion stops closing
the gap.

Run: python services/ws4-detection/test_companion_rules.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "services"))
sys.path.insert(0, str(ROOT / "services" / "ws2-normalization"))

from engine import load_rules  # noqa: E402
from parsers import _REGISTRY  # noqa: E402
from enrichment import enrich  # noqa: E402

RULES_DIR = ROOT / "contracts" / "rules"
BASE = 1_751_500_000_000
FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _rule(rid):
    for r in load_rules(RULES_DIR):          # fresh instance = fresh window state
        if r.id == rid:
            return r
    raise AssertionError(f"rule {rid} not loaded")


def _event(source_type, raw, i, t_ms):
    meta = {"received_at": t_ms, "ingest_id": f"comp-{source_type}-{i}", "tenant_id": "acme"}
    ev = _REGISTRY[source_type].parse({"source_type": source_type, "raw": raw, "meta": meta})
    assert ev is not None, (source_type, raw)
    return enrich(ev)


def _fires(rule, events):
    """True iff the rule fires on ANY event of the stream (stateful: windowed)."""
    return any(rule.evaluate(e) for e in events)


def _case(name, sibling_id, companion_id, build, n_fire, n_short):
    """build(i, t_ms) -> event; stream of n events spaced inside the window."""
    full = [build(i) for i in range(n_fire)]
    short = [build(i) for i in range(n_short)]
    check(not _fires(_rule(sibling_id), full),
          f"{name}: the SIBLING must NOT see the split attack (otherwise the companion is redundant)")
    check(_fires(_rule(companion_id), full),
          f"{name}: the COMPANION must fire on the split attack")
    check(not _fires(_rule(companion_id), short),
          f"{name}: the companion must stay silent one event short of its threshold ({n_short})")


def run():
    # ---- brute force: 12 failures for ONE account over TWO source addresses ----
    ips = ["203.0.113.21", "192.0.2.44"]
    _case("bruteforce_by_account",
          "6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c01", "d83b71c3-93eb-439f-86f9-5985ebcc38cb",
          lambda i: _event("linux_ssh",
                           f"Jun 10 13:55:{i:02d} db01 sshd[{2000 + i}]: Failed password for deploy "
                           f"from {ips[i % 2]} port {51000 + i} ssh2", i, BASE + i * 3_000),
          n_fire=12, n_short=9)

    # ---- port scan: 20 distinct denied ports on ONE target from TWO sources ----
    _case("port_scan_by_target",
          "1d2c3b4a-5e6f-4708-8a91-0b1c2d3e4f05", "aaa9dc23-8550-41ae-acbc-0ae50837d8d6",
          lambda i: _event("cisco_asa",
                           f"%ASA-4-106023: Deny tcp src outside:{ips[i % 2]}/{40000 + i} "
                           f"dst inside:10.0.0.10/{20 + i * 7} by access-group acl_out",
                           i, BASE + i * 2_000),
          n_fire=20, n_short=14)

    # ---- lateral movement: 8 hosts from ONE foothold using TWO accounts ----
    _case("lateral_movement_by_source",
          "2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061", "90561d27-ace4-4138-8cc4-c74569a439c6",
          lambda i: _event("windows_eventlog",
                           {"EventID": 4624, "TargetUserName": ["svc-a", "svc-b"][i % 2],
                            "Computer": f"fs{i:02d}", "IpAddress": "10.50.0.46",
                            "WorkstationName": "db01", "TimeCreated": BASE + i * 25_000},
                           i, BASE + i * 25_000),
          n_fire=8, n_short=4)

    # ---- mass VM delete: 7 deletions from ONE address using TWO accounts ----
    _case("mass_vm_delete_by_source",
          "8c4e1f90-7a2b-4d33-9e55-6f1b2c3a4d03", "9c86195a-8cd6-4b73-b526-a708bbb5299e",
          lambda i: _event("vmware_vsphere",
                           {"operation": "VM.Delete", "vm": f"prod-vm-{i:02d}",
                            "userName": ["svc_a", "svc_b"][i % 2], "host": "vcenter-01",
                            "ipAddress": "203.0.113.21", "createdTime": BASE + i * 8_000},
                           i, BASE + i * 8_000),
          n_fire=7, n_short=4)

    # ---- DNS tunnelling: 48 distinct names under ONE parent from TWO clients ----
    clients = ["10.50.0.46", "10.50.0.47"]
    _case("dns_tunnel_by_domain",
          "a1b2c3d4-5e6f-4708-9a1b-2c3d4e5f6071", "5f3c9d18-72a4-4e0b-b6d1-8c2e7a4f1b93",
          lambda i: _event("dns_query",
                           f"query[A] chunk{i:03d}.t1.exfil.example.invalid from {clients[i % 2]}",
                           i, BASE + i * 1_000),
          n_fire=48, n_short=39)

    # ---- the companion must NOT pool unrelated parents or reverse lookups ----
    unrelated = [_event("dns_query", f"query[A] www.site{i}.com from 10.50.0.46",
                        i, BASE + i * 1_000) for i in range(48)]
    check(not _fires(_rule("5f3c9d18-72a4-4e0b-b6d1-8c2e7a4f1b93"), unrelated),
          "dns_tunnel_by_domain: 48 names under 48 DIFFERENT parents is browsing, not a tunnel")
    ptr = [_event("dns_query", f"query[PTR] {i}.0.0.10.in-addr.arpa from 10.50.0.46",
                  i, BASE + i * 1_000) for i in range(60)]
    check(not _fires(_rule("5f3c9d18-72a4-4e0b-b6d1-8c2e7a4f1b93"), ptr),
          "dns_tunnel_by_domain: reverse-lookup zones must never pool into a tunnel alert")


def run_opcua():
    """ot_opcua_write_unauthorized_node: allowlist-first. A business-hours write
    to an undeclared node is invisible to ot_config_change (no config marker) and
    ot_write_outside_maintenance (inside 08:00-18:00); this rule is what sees it."""
    import shutil
    import tempfile

    rid = "e7a14b6d-3c52-4d90-8f1b-5a9c0d2e6b47"
    in_hours = 1_751_536_800_000          # Thu 2025-07-03 10:00:00 UTC
    raw = {"eventType": "AuditWriteUpdateEventType", "clientUserId": "ot-engineer",
           "clientAddress": "10.20.0.50", "serverId": "opcua-line3",
           "nodeId": "ns=2;s=Line3/PumpEnable", "status": "Success", "time": in_hours}
    ev = _event("opcua_audit", raw, 0, in_hours)

    check(_fires(_rule(rid), [ev]),
          "ot_opcua_write_unauthorized_node: an undeclared node fires (allowlist ships empty)")
    for other in ("4d5e6f70-8192-49b0-8b2c-3d4e5f6a7b8e", "6f708192-a314-4cd2-ad4e-5f6a7b8c9d01"):
        check(not _fires(_rule(other), [ev]),
              f"ot_opcua_write_unauthorized_node: the pre-existing OPC UA rule {other[:8]} must NOT "
              "see this write (otherwise the new rule is redundant)")

    tmp = Path(tempfile.mkdtemp())
    try:
        shutil.copytree(ROOT / "contracts" / "allowlists", tmp / "allowlists")
        (tmp / "allowlists" / "opcua_authorized_nodes.yml").write_text(
            'entries:\n  - "ns=2;s=Line3/PumpEnable"\n', encoding="utf-8")
        rules = load_rules(RULES_DIR, allowlists_dir=tmp / "allowlists")
        rule = next(r for r in rules if r.id == rid)
        check(not _fires(rule, [ev]),
              "ot_opcua_write_unauthorized_node: a node listed as authorised is suppressed")
        other_node = dict(raw, nodeId="ns=2;s=Line3/ValveOverride")
        check(_fires(rule, [_event("opcua_audit", other_node, 1, in_hours)]),
              "ot_opcua_write_unauthorized_node: a DIFFERENT node still fires when the list is populated")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


SSH_SIBLING = "6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c01"
SSH_COMPANION = "d83b71c3-93eb-439f-86f9-5985ebcc38cb"


def _ssh_burst(ips, n=12):
    """n failed SSH logins for ONE account, round-robin over ``ips``, 3s apart."""
    return [_event("linux_ssh",
                   f"Jun 10 13:55:{i:02d} db01 sshd[{2000 + i}]: Failed password for deploy "
                   f"from {ips[i % len(ips)]} port {51000 + i} ssh2", i, BASE + i * 3_000)
            for i in range(n)]


def _detector(tenants_dir):
    from main import Detector
    return Detector(tenants_dir=tenants_dir, plugin_rule_dirs=[])


def _emit_one(det, event):
    """process + _emit one event on a fresh bus; return (matched, alerts)."""
    from shared.bus import Bus
    bus = Bus()
    event, matched, action = det.process(event)
    det._emit(bus, event, matched, action)
    return matched, [m.payload for m in bus.drain("alerts")]


def run_suppression_invariant():
    """FINDING 8 (2026-10-02 review): WS-4 drops a companion's alert whenever its
    sibling MATCHED the same event. That is only sound if "sibling matched" implies
    "a sibling alert is actually emitted" -- otherwise the companion's alert is
    removed in favour of an alert that never exists and the attack goes silent.

    Traced end to end (main.py Detector.process -> _emit): there is NO point
    between `matched` and `bus.produce("alerts")` that can drop a matched rule --
    score does not gate emission, alert_id dedup happens downstream in the
    indexer (a repeat of an already-indexed sibling alert is the sibling having
    "already raised the alert"), and a redelivered event re-matches the sibling
    because window membership is keyed by ingest_id (idempotent). So no scenario
    exists TODAY where the sibling matches but no sibling alert is emitted.

    These checks PIN that invariant so a future downstream filter (a per-rule
    score floor, a rate limit, a mute list) fails here, loudly, instead of
    silently deleting the companion's coverage."""
    import copy
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        tenants = Path(tmp)
        det = _detector(tenants)

        # spy on the companion so the test knows on which events it WOULD have fired
        comp = next(r for r in det.rules if r.id == SSH_COMPANION)
        check(comp.companion_of == SSH_SIBLING, "companion must link to the ssh brute-force sibling")
        comp_fired = []
        real_eval = comp.evaluate

        def spy(ev, _real=real_eval):
            hit = _real(ev)
            if hit:
                comp_fired.append(ev["time"])
            return hit
        comp.evaluate = spy

        events = _ssh_burst(["203.0.113.21"])           # ONE ip + ONE account: both rules match
        alert_ids_by_time: dict = {}
        first_sibling_idx = None
        for i, ev in enumerate(events):
            matched, alerts = _emit_one(det, ev)
            emitted = [a["rule_id"] for a in alerts]
            # (1) emission is exactly the matched set: nothing downstream of
            #     `matched` may drop a rule (this is the pinned invariant)
            check(sorted(emitted) == sorted(r.id for r in matched),
                  f"event {i}: alerts emitted {emitted} != matched {[r.id for r in matched]}")
            alert_ids_by_time[ev["time"]] = emitted
            if SSH_SIBLING in emitted and first_sibling_idx is None:
                first_sibling_idx = i
        check(first_sibling_idx is not None, "the sibling must alert on a 12-failure single-source burst")
        check(len(comp_fired) > 0,
              "vacuity guard: the companion must have MATCHED on this burst, else the suppression is untested")
        # (2) every event the companion matched on carries a sibling alert and NO companion alert
        for t in comp_fired:
            got = alert_ids_by_time.get(t, [])
            check(SSH_SIBLING in got,
                  f"companion matched at t={t} but no sibling alert was emitted for that event: {got}")
            check(SSH_COMPANION not in got,
                  f"companion alert must be suppressed when the sibling alerted (t={t}): {got}")

        # (3) at-least-once redelivery: the same event processed again re-matches the
        #     sibling (idempotent window) -> the companion stays suppressed, no
        #     double alert and no gap
        if first_sibling_idx is not None:
            redelivered = copy.deepcopy(events[first_sibling_idx])
            matched, alerts = _emit_one(det, redelivered)
            ids = [a["rule_id"] for a in alerts]
            check(SSH_SIBLING in ids and SSH_COMPANION not in ids,
                  f"redelivered trigger event must still alert via the sibling only, got {ids}")

        # (4) negative control: the SPLIT attack (sibling blind) still alerts via the companion
        det2 = _detector(tenants)
        seen = []
        for ev in _ssh_burst(["203.0.113.21", "192.0.2.44"]):
            _m, alerts = _emit_one(det2, ev)
            seen.extend(a["rule_id"] for a in alerts)
        check(SSH_COMPANION in seen and SSH_SIBLING not in seen,
              f"split attack must alert via the companion alone, got {sorted(set(seen))}")

        # (5) tenant-disable is untouched: disabling the sibling disables the companion.
        #     (fresh dirs: load_disabled_rules caches per (dir, tenant))
        dis_dir = Path(tmp) / "disabling"
        dis_dir.mkdir()
        (dis_dir / "acme.yml").write_text(f"disabled_rules:\n  - {SSH_SIBLING}\n", encoding="utf-8")
        open_dir = Path(tmp) / "open"
        open_dir.mkdir()

        def tenant_run(tenants_dir):
            d = _detector(tenants_dir)
            out = []
            for ev in _ssh_burst(["203.0.113.21"]):
                ev.setdefault("siem", {})["tenant"] = "acme"
                _m, alerts = _emit_one(d, ev)
                out.extend(a["rule_id"] for a in alerts)
            return out

        seen3 = tenant_run(dis_dir)
        seen4 = tenant_run(open_dir)       # control: tenant "acme" with nothing disabled
        check(SSH_SIBLING in seen4, "control: the same burst alerts for a tenant that disabled nothing")
        check(SSH_SIBLING not in seen3 and SSH_COMPANION not in seen3,
              f"tenant that disabled the sibling must get neither alert, got {sorted(set(seen3))}")


def main():
    run()
    run_opcua()
    run_suppression_invariant()
    if FAILS:
        print(f"[FAIL] companion rules: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] companion rules: each fires on the split attack its sibling cannot see, "
          "and stays silent one event short")


if __name__ == "__main__":
    main()
