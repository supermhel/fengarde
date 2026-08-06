"""WS-1 asset-observation contract test — zero infrastructure (memory bus).

Guards the invariant that made a 100%-drop path ship unnoticed (2026-08-05):

    a collector may only yield an `assets.updates` observation when it has a MAC.

`contracts/bus-topics.md` names `mac` as that topic's partition key, and the
topic's only consumer (WS-6) keys inventory on it — `InventoryStore
.upsert_with_diff()` returns None for a macless observation ("inventory is
MAC-keyed (Contract C)"). So an observation without a MAC is discarded on
arrival: bus traffic plus a misleading warn-log, never an inventory update.

Live-verified on a real Docker/Redis stack before this test existed: 3 of the 5
observations WS-1 seeds at startup were syslog-sourced with `mac: None`, and
100% of them were dropped every run. `asset_observations()` had ZERO test
coverage anywhere in the suite, which is exactly why it went unnoticed for as
long as it did — `test_contract.py` asserted only that at least ONE observation
carried a MAC, never that all of them did, so a wholly-dead syslog path passed.

Note this test deliberately does NOT import WS-6 to check the store's real
rejection: services in this repo never import each other (see CLAUDE.md
"coupled only through a message bus"). It asserts the contract invariant
directly instead.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(SERVICES))
sys.path.insert(0, str(HERE))
os.environ["BUS_BACKEND"] = "memory"

from shared.bus import Bus  # noqa: E402
from collectors.syslog_collector import SyslogCollector  # noqa: E402
from collectors.snmp_collector import SnmpCollector  # noqa: E402
from collectors.netflow_collector import NetflowCollector  # noqa: E402
import main as ws1  # noqa: E402

FAILS: list[str] = []

# An RFC5424 line whose HOSTNAME field is a real hostname, not an IP literal —
# precisely the shape that used to produce a macless observation.
SYSLOG_NAMED_HOST = (
    "<38>1 2024-06-16T12:00:01.250Z wks-jdoe sshd 1832 - - "
    "Failed password for jdoe from 10.20.30.40 port 51514 ssh2"
)


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def test_syslog_emits_no_macless_observation():
    """The specific fix: syslog parses a hostname but has no MAC, so abstains."""
    c = SyslogCollector()
    payload = c.handle_line(SYSLOG_NAMED_HOST)

    check(payload is not None, "syslog should still produce a raw event")
    obs = list(c.asset_observations())
    check(
        obs == [],
        f"syslog must emit NO asset observation (headers carry no MAC); got {obs!r}",
    )


def test_syslog_still_exposes_hostname_in_meta():
    """Abstaining must not throw the parsed hostname away — it still rides on
    the raw event's meta, it is just not used as an asset identity."""
    c = SyslogCollector()
    payload = c.handle_line(SYSLOG_NAMED_HOST)
    check(payload is not None, "syslog produced no payload at all")
    if payload:
        check(
            payload["meta"].get("hostname") == "wks-jdoe",
            f"syslog dropped the parsed hostname from meta: {payload['meta']!r}",
        )


def test_syslog_ip_literal_host_also_emits_nothing():
    """A HOSTNAME field holding an IP literal was already excluded; keep it so —
    otherwise the abstention above could be reintroduced through this branch."""
    c = SyslogCollector()
    c.handle_line(
        "<13>1 2024-06-16T12:00:02.500Z 10.0.0.50 nginx 9001 - - 10.0.0.50 GET /login 200"
    )
    obs = list(c.asset_observations())
    check(obs == [], f"syslog emitted an observation for an IP-literal host: {obs!r}")


def test_snmp_emits_observation_when_mac_present():
    """The positive case: SNMP is the collector that CAN identify a device."""
    c = SnmpCollector(devices=[{
        "ip": "10.0.0.1",
        "oids": {"1.3.6.1.2.1.1.5.0": "core-switch-01",
                 "1.3.6.1.2.1.2.2.1.6": "AA:BB:CC:00:11:01"},
    }])
    list(c.poll())
    obs = list(c.asset_observations())
    check(len(obs) == 1, f"SNMP with a MAC should emit exactly 1 observation, got {len(obs)}")
    if obs:
        check(obs[0].get("mac") == "AA:BB:CC:00:11:01", f"wrong mac: {obs[0]!r}")
        check(obs[0].get("hostname") == "core-switch-01", f"wrong hostname: {obs[0]!r}")
        check(obs[0].get("ip") == "10.0.0.1", f"wrong ip: {obs[0]!r}")
        check(obs[0].get("seen_at"), f"missing seen_at: {obs[0]!r}")


def test_snmp_abstains_when_device_answers_hostname_but_no_mac():
    """Latent instance of the same defect, closed 2026-08-05: the guard was
    `mac or hostname`, so a device answering sysName but NOT ifPhysAddress
    emitted a macless observation. The shipped mock devices all carry a MAC,
    so this never fired in the seeded path and nothing caught it."""
    c = SnmpCollector(devices=[{
        "ip": "10.0.0.9",
        "oids": {"1.3.6.1.2.1.1.5.0": "hostname-only-device"},
    }])
    list(c.poll())
    obs = list(c.asset_observations())
    check(obs == [], f"SNMP must abstain without a MAC; got {obs!r}")


def test_netflow_emits_nothing():
    """Pre-existing, correct abstention — pinned so it cannot regress into the
    macless-emitter shape the other two collectors just had to be fixed out of."""
    c = NetflowCollector(flows_file=str(ws1.MOCKS / "sample_netflow.json"))
    list(c.poll())
    obs = list(c.asset_observations())
    check(obs == [], f"netflow carries no asset identity, must emit nothing; got {obs!r}")


def test_full_cycle_every_published_observation_has_a_mac():
    """The end-to-end invariant, over the real seeded run WS-1 performs on boot.

    This is the assertion whose absence let the bug ship: `test_contract.py`
    checked that at least one observation had a MAC, which stayed true while
    every syslog-sourced one was silently unusable.
    """
    bus = Bus()
    counts = ws1.run_once(bus)
    assets = bus.drain("assets.updates")

    check(len(assets) >= 1, "expected at least one asset observation from the seeded run")
    for m in assets:
        o = m.payload
        check(
            bool(o.get("mac")),
            f"published a macless assets.updates observation (WS-6 will discard it): {o!r}",
        )
        # The topic's partition key IS the mac (contracts/bus-topics.md). The
        # old `key = mac or ip or "unknown"` fallback in main.py only ever
        # mattered for observations that could not be stored anyway.
        check(
            m.key == o.get("mac"),
            f"assets.updates partition key must be the mac; key={m.key!r} obs={o!r}",
        )

    check(
        counts["assets.updates"] == len(assets),
        f"count {counts['assets.updates']} != published {len(assets)}",
    )


def test_full_cycle_raw_ingestion_unaffected():
    """The abstention must not reduce raw.events — syslog lines still ingest
    normally, only the asset side-channel changed."""
    bus = Bus()
    counts = ws1.run_once(bus)
    raw = bus.drain("raw.events")

    check(counts["raw.events"] >= 3, f"raw ingestion regressed: {counts['raw.events']}")
    source_types = {m.payload["source_type"] for m in raw}
    check(any(st.startswith("syslog") for st in source_types),
          f"syslog raw events disappeared: {source_types!r}")


def main():
    for fn in [
        test_syslog_emits_no_macless_observation,
        test_syslog_still_exposes_hostname_in_meta,
        test_syslog_ip_literal_host_also_emits_nothing,
        test_snmp_emits_observation_when_mac_present,
        test_snmp_abstains_when_device_answers_hostname_but_no_mac,
        test_netflow_emits_nothing,
        test_full_cycle_every_published_observation_has_a_mac,
        test_full_cycle_raw_ingestion_unaffected,
    ]:
        fn()

    if FAILS:
        print(f"[FAIL] WS-1 asset observations: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WS-1 asset observations: only MAC-bearing observations reach "
          "assets.updates (syslog/netflow abstain, snmp abstains without a MAC), "
          "partition key is the mac, raw ingestion unaffected")


if __name__ == "__main__":
    main()
