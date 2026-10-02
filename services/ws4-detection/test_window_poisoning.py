"""Window poisoning: an event whose own timestamp is attacker-influenced must not
be able to erase the evidence of the rest of the burst.

THE ATTACK (measured against the real engine before the fix)
    A stateful window's eviction horizon was computed from the CURRENT EVENT'S
    timestamp: ``horizon = event_time - window``. The engine already rejects an
    event dated more than 5 minutes (``_MAX_CLOCK_SKEW_MS``) beyond wall-clock, but
    inside that allowance an event stamped ``wall + 299 s`` moves the horizon to
    ``wall + 239 s`` and evicts EVERY real hit in the window. Send one such event
    for every N-1 probes and a port scan / brute force never accumulates N:

        14 distinct-port probes  ->  forged event (wall+299 s, a port already seen)
        ->  window wiped, distinct count back to 1  ->  13 more probes  ->  forged
        event  ->  ...                                  (never reaches 15)

    It needs a source whose timestamp the attacker influences -- an agent/MCP or
    workflow record that carries its own ``ts``, a forwarded record, a source
    with a skewed or compromised clock -- so it is not an internet-wide bypass,
    but those are exactly the sources this product exists to watch.

THE FIX
    A stateful window is driven by ``min(event_time, wall_clock)``: a "future"
    event inside the skew allowance is treated as happening NOW. Past timestamps
    (historical replay, the harness's fixed 2025 epoch) are untouched, and the
    5-minute guard that DROPS wildly future events stays.

Run: python services/ws4-detection/test_window_poisoning.py
"""
from __future__ import annotations

import sys
import time
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
PORT_SCAN = "1d2c3b4a-5e6f-4708-8a91-0b1c2d3e4f05"      # 15 distinct denied ports / 60 s, by source
BRUTE = "6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c01"          # 10 failures / 60 s, by source
FAILS: list = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _rule(rid):
    return next(r for r in load_rules(RULES_DIR) if r.id == rid)


def _asa(port, i, t_ms):
    line = (f"%ASA-4-106023: Deny tcp src outside:203.0.113.21/{40000 + i} "
            f"dst inside:10.0.0.10/{port} by access-group acl_out")
    meta = {"received_at": t_ms, "ingest_id": f"poison-asa-{i}", "tenant_id": "acme"}
    return enrich(_REGISTRY["cisco_asa"].parse({"source_type": "cisco_asa", "raw": line, "meta": meta}))


def _ssh(i, t_ms):
    line = f"Jun 10 13:55:00 db01 sshd[{2000 + i}]: Failed password for deploy from 203.0.113.21 port {51000 + i} ssh2"
    meta = {"received_at": t_ms, "ingest_id": f"poison-ssh-{i}", "tenant_id": "acme"}
    return enrich(_REGISTRY["linux_ssh"].parse({"source_type": "linux_ssh", "raw": line, "meta": meta}))


def _run_scan(rule, forge: bool, wall_ms: int) -> bool:
    """30 distinct-port probes. With ``forge``, every 13 probes a forged event
    (time = wall + 299 s, reusing a port already seen) is injected."""
    fired = False
    n = 0
    for i in range(30):
        fired |= bool(rule.evaluate(_asa(1000 + i, n, wall_ms + i * 100)))
        n += 1
        if forge and (i + 1) % 13 == 0:
            fired |= bool(rule.evaluate(_asa(1000, n, wall_ms + 299_000)))
            n += 1
    return fired


def run():
    wall = int(time.time() * 1000)

    # CONTROL 1: the honest scan fires. Without this the "evasion" below proves nothing.
    check(_run_scan(_rule(PORT_SCAN), forge=False, wall_ms=wall),
          "control: 30 distinct-port probes with no forgery must fire the port-scan rule")

    # THE ATTACK: same scan, one forged-time event per 13 probes
    check(_run_scan(_rule(PORT_SCAN), forge=True, wall_ms=wall),
          "window poisoning: a forged future-dated event (+299 s, inside the skew allowance) must NOT "
          "be able to wipe the probes accumulated before it -- the scan must still fire")

    # same attack against a COUNT rule (brute force: 10 failures / 60 s)
    rule = _rule(BRUTE)
    fired = False
    n = 0
    for i in range(40):
        fired |= bool(rule.evaluate(_ssh(n, wall + i * 100)))
        n += 1
        if (i + 1) % 8 == 0:
            fired |= bool(rule.evaluate(_ssh(n, wall + 299_000)))
            n += 1
    check(fired, "window poisoning: brute force must still fire when forged future-dated "
                 "failures are interleaved")

    # Historical replay must still work: past timestamps are NOT clamped
    past = wall - 7 * 24 * 3600 * 1000
    check(_run_scan(_rule(PORT_SCAN), forge=False, wall_ms=past),
          "a replay of a week-old scan must still fire (past timestamps untouched)")

    # And the existing hard guard stays: an event far beyond the skew allowance is dropped
    rule = _rule(PORT_SCAN)
    check(not rule.evaluate(_asa(1, 0, wall + 3_600_000)),
          "an event an hour in the future is still dropped by the 5-minute guard")


def main():
    run()
    if FAILS:
        print(f"[FAIL] window poisoning: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] window poisoning: forged near-future timestamps cannot wipe a stateful window")


if __name__ == "__main__":
    main()
