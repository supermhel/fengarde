"""Sensitivity checks for WS-8's two negative-control guarantees: a
negative assertion that cannot fail is not a test (same bar
eval/attack/test_fire_check.py established and 2026-08-11's live CAS
concurrency test applied again).

Each check here breaks the real property on a MUTATED copy of the engine's
logic and asserts the test that currently passes on the real engine would
go red against the broken version -- proving the positive tests in
test_contract.py are actually exercising the guarantee, not vacuously
passing regardless of it.

Run: python services/ws8-correlation/test_correlator_sensitivity.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))

from shared.allowlist import Allowlist  # noqa: E402
from shared.window import DequeWindowCounter  # noqa: E402
from correlator import Correlator, _validated_tenant  # noqa: E402
from test_contract import _alert  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


class _MutatedSingleTacticPromotes(Correlator):
    """Mutation of divergence #3: promote on >=1 tactic instead of >=2 --
    the exact bug test_single_tactic_never_promotes() must catch."""

    def _update_track(self, tenant, entity_type, entity_value, alert, now_ms):
        key = self._track_key(tenant, entity_type, entity_value)
        member = alert.get("alert_id")
        self.window_counter.hit(key, now_ms, self.horizon_ms, member=member)
        live_ids = set(self.window_counter.members(key))
        side = self._sides.setdefault(key, {})
        side[member] = {"alert_id": member, "tactic": (alert.get("mitre") or {}).get("tactic"),
                         "score": alert.get("score") or 0, "time": alert.get("time") or now_ms}
        for stale in list(side):
            if stale not in live_ids:
                del side[stale]
        live = [side[m] for m in live_ids if m in side]
        tactics = sorted({m["tactic"] for m in live if m["tactic"]})
        if len(tactics) < 1:  # MUTATED: should be < 2
            return None
        incident_id = self._incident_id(tenant, entity_type, entity_value, now_ms)
        return {"incident_id": incident_id, "tenant_id": tenant, "entity_type": entity_type,
                "entity_value": entity_value, "tactics": tactics,
                "member_alert_ids": sorted(m["alert_id"] for m in live),
                "member_count": len(live), "severity": 0, "truncated": False,
                "first_seen": 0, "last_seen": 0}


def test_single_tactic_promotion_trigger_is_sensitive():
    """If the >=2-distinct-tactics gate is broken (mutated to >=1), a
    single-tactic-repeated alert stream MUST promote -- proving
    test_single_tactic_never_promotes() would have caught this mutation."""
    c = _MutatedSingleTacticPromotes(DequeWindowCounter(), allowlist=Allowlist([]))
    saw_promotion = False
    for i in range(5):
        incs = c.ingest_alert(_alert(f"m{i}", tactic="TA0001", actor="mallory"))
        if incs:
            saw_promotion = True
    check(saw_promotion,
          "sensitivity: the mutated >=1-tactic engine must promote on single-tactic "
          "volume -- if it doesn't, this sensitivity check is broken, not the mutation")


class _MutatedActorKeyedByIP(Correlator):
    """Mutation of divergence #2: when an alert carries BOTH an actor and
    an ip, key the actor-type track by the ip instead of the actor name.
    Two different actors sharing one ip then collapse onto the SAME
    'actor' track -- the exact transitive-merge failure mode divergence #2
    forbids (one shared IP pulling unrelated actors into one incident)."""

    def ingest_alert(self, alert):
        tenant = _validated_tenant(alert.get("tenant_id"))
        now_ms = self._now_ms()
        incidents = []
        actor_name = (alert.get("actor") or {}).get("user", {}).get("name")
        src_ip = (alert.get("src_endpoint") or {}).get("ip")
        if actor_name:
            entity_value = str(src_ip) if src_ip else str(actor_name)  # MUTATED
            inc = self._update_track(tenant, "actor", entity_value, alert, now_ms)
            if inc is not None:
                incidents.append(inc)
        if src_ip and not self._allowlist.matches(src_ip):
            inc = self._update_track(tenant, "ip", str(src_ip), alert, now_ms)
            if inc is not None:
                incidents.append(inc)
        return incidents


def test_no_transitive_merge_is_sensitive():
    """Run the SAME scenario test_no_transitive_merge_via_shared_ip() uses
    (two actors, one shared unlisted ip) against both the real engine and
    the mutated one. The real engine must keep grace's and heidi's alerts
    in disjoint actor tracks; the mutated engine -- which keys the actor
    track by ip when present -- must MERGE them into one. If the mutated
    engine also kept them disjoint, this sensitivity check (and therefore
    the guarantee test_contract.py asserts) would be proving nothing."""
    real = Correlator(DequeWindowCounter(), allowlist=Allowlist([]))
    mutated = _MutatedActorKeyedByIP(DequeWindowCounter(), allowlist=Allowlist([]))

    events = [
        _alert("y1", tactic="TA0001", actor="grace", ip="198.51.100.9"),
        _alert("y2", tactic="TA0002", actor="grace", ip="198.51.100.9"),
        _alert("y3", tactic="TA0001", actor="heidi", ip="198.51.100.9"),
        _alert("y4", tactic="TA0002", actor="heidi", ip="198.51.100.9"),
    ]
    for e in events:
        real.ingest_alert(e)
        mutated.ingest_alert(e)

    real_grace_ids = set(real._sides.get(real._track_key("default", "actor", "grace"), {}))
    real_heidi_ids = set(real._sides.get(real._track_key("default", "actor", "heidi"), {}))
    check(real_grace_ids.isdisjoint(real_heidi_ids),
          "sensitivity: the REAL engine must keep grace's and heidi's actor tracks disjoint")

    mutated_shared_key = mutated._track_key("default", "actor", "198.51.100.9")
    mutated_ids = set(mutated._sides.get(mutated_shared_key, {}))
    check(mutated_ids == {"y1", "y2", "y3", "y4"},
          "sensitivity: the MUTATED (ip-keyed-actor) engine must merge grace's and "
          "heidi's alerts into one track -- if it doesn't, this mutation isn't "
          "actually exercising the transitive-merge failure mode, and "
          "test_no_transitive_merge_via_shared_ip() proves nothing")


class _MutatedDeviceKeyedByIP(Correlator):
    """Mutation of the 2026-08-19 pivot-correlation fix: key the device:
    track by ip instead of mac/hostname -- i.e. revert to the pre-fix
    behavior where a DHCP-driven IP change silently starts a brand-new
    track instead of continuing the same one."""

    def ingest_alert(self, alert):
        tenant = _validated_tenant(alert.get("tenant_id"))
        now_ms = self._now_ms()
        incidents = []
        src = alert.get("src_endpoint") or {}
        src_ip = src.get("ip")
        if src_ip and not self._allowlist.matches(src_ip):
            inc = self._update_track(tenant, "ip", str(src_ip), alert, now_ms)
            if inc is not None:
                incidents.append(inc)
        device_id = src_ip  # MUTATED: should be src.get("mac") or src.get("hostname")
        if device_id:
            inc = self._update_track(tenant, "device", str(device_id), alert, now_ms)
            if inc is not None:
                incidents.append(inc)
        return incidents


def test_device_pivot_correlation_is_sensitive():
    """Run the SAME scenario test_device_track_correlates_across_ip_change()
    uses (one host, two ips, two tactics, no actor) against the real engine
    and the mutated (ip-keyed-device) one. The real engine must promote via
    the device: track; the mutated engine -- which silently starts a new
    device track per ip, same as having no device correlation at all --
    must NOT promote, since each of its two ip-keyed "device" tracks only
    ever sees one tactic. If the mutated engine also promoted, this
    sensitivity check would be proving nothing about the pivot fix."""
    real = Correlator(DequeWindowCounter(), allowlist=Allowlist([]))
    mutated = _MutatedDeviceKeyedByIP(DequeWindowCounter(), allowlist=Allowlist([]))

    events = [
        _alert("p1", tactic="TA0043", ip="10.0.0.5", mac="AA:BB:CC:DD:EE:FF"),
        _alert("p2", tactic="TA0006", ip="10.0.0.9", mac="AA:BB:CC:DD:EE:FF"),
    ]
    real_promoted = any(real.ingest_alert(e) for e in events)
    mutated_promoted = any(mutated.ingest_alert(e) for e in events)

    check(real_promoted,
          "sensitivity: the REAL engine must promote the device: track across the ip change")
    check(not mutated_promoted,
          "sensitivity: the MUTATED (ip-keyed-device) engine must NOT promote -- if it "
          "does, this mutation isn't actually exercising the pivot-correlation fix, and "
          "test_device_track_correlates_across_ip_change() proves nothing")


def run_all():
    test_single_tactic_promotion_trigger_is_sensitive()
    test_no_transitive_merge_is_sensitive()
    test_device_pivot_correlation_is_sensitive()


if __name__ == "__main__":
    run_all()
    if FAILS:
        print(f"[FAIL] WS-8 sensitivity: {len(FAILS)} problem(s)")
        for f in FAILS:
            print(f"  - {f}")
        sys.exit(1)
    print("[OK] WS-8 sensitivity checks PASS (promotion trigger + no-merge guarantee + "
          "device pivot-correlation all proven to actually break under mutation)")
