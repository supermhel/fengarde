"""test_fix_modbus_ticket_boundary.py -- PR #80 review finding 1 (mut sound).

The `changeTicketId` downgrade signal is a TRUST-BOUNDARY field. The rules and
SECURITY.md 12 require that the authorization claim come from a source
INDEPENDENT of the observed Modbus wire -- never from frame bytes. This test
runs against the REAL parser (mutation-sound: deleting the meta-channel read
or the shape check turns it RED) and asserts, by execution, not by comment:

  * a `changeTicketId` inside the FRAME record (the wire channel -- attacker
    data) does NOT populate `unmapped.ot.change_ticket_id`, so it cannot
    forge the HIGH->LOW downgrade;
  * a ticket-shaped `changeTicketId` on the envelope's META channel DOES map
    through, and marks the event `change_ticket_unvalidated: true`;
  * a junk / blank / shadeless meta ticket does NOT map through (shape check).

Run (standalone script, like every ws2 test):
    cd services/ws2-normalization && python test_fix_modbus_ticket_boundary.py
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (HERE, os.path.dirname(HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from parsers import _REGISTRY  # noqa: E402

_FAILS: list[str] = []

_WRITE = {"unitId": 1, "functionCode": 6, "address": 41999,
          "sourceIp": "10.20.0.99", "destIp": "10.20.0.5"}


def check():
    parser = _REGISTRY.get("modbus_anomaly")
    if parser is None:
        _FAILS.append("modbus_anomaly parser not registered")
        return

    # 1) Frame-carried ticket (an attacker on the wire controls the frame
    #    record) must be IGNORED -- no downgrade, no change_ticket_id.
    ev = parser.parse({"source_type": "modbus_anomaly",
                       "raw": {**_WRITE, "changeTicketId": "CHG-EVIL-1"},
                       "meta": {}})
    ot = (ev or {}).get("unmapped", {}).get("ot", {})
    if ot.get("change_ticket_id") is not None:
        _FAILS.append("frame-carried changeTicketId populated "
                      "unmapped.ot.change_ticket_id -- trust boundary broken "
                      "(attacker can forge the HIGH->LOW downgrade)")

    # 2) Meta-carried, ticket-shaped id maps through + marks unvalidated.
    ev2 = parser.parse({"source_type": "modbus_anomaly", "raw": _WRITE,
                        "meta": {"changeTicketId": "CHG-2026-08-1042"}})
    ot2 = (ev2 or {}).get("unmapped", {}).get("ot", {})
    if ot2.get("change_ticket_id") != "CHG-2026-08-1042":
        _FAILS.append("meta-carried ticket-shaped changeTicketId not mapped "
                      "through to unmapped.ot.change_ticket_id")
    if ot2.get("change_ticket_unvalidated") is not True:
        _FAILS.append("accepted ticket did not set change_ticket_unvalidated "
                      "= true (the downgrade rests on an unauthenticated claim)")

    # 3) Shape check: junk (no digits) / blank / short tickets must NOT map.
    for bad in ("AAAA", "   ", "x", "noticket"):
        evb = parser.parse({"source_type": "modbus_anomaly", "raw": _WRITE,
                            "meta": {"changeTicketId": bad}})
        otb = (evb or {}).get("unmapped", {}).get("ot", {})
        if otb.get("change_ticket_id") is not None:
            _FAILS.append(f"shape check rejected ticket {bad!r} but "
                          "change_ticket_id was still set")

    # 4) Non-string ticket (meta) must not map.
    evn = parser.parse({"source_type": "modbus_anomaly", "raw": _WRITE,
                        "meta": {"changeTicketId": 12345}})
    otd = (evn or {}).get("unmapped", {}).get("ot", {})
    if otd.get("change_ticket_id") is not None:
        _FAILS.append("non-string meta changeTicketId mapped through")


def main() -> int:
    check()
    if _FAILS:
        for f in _FAILS:
            print(f"[FAIL] {f}")
        print(f"[FAIL] {len(_FAILS)} modbus changeTicketId trust-boundary "
              "violation(s)")
        return 1
    print("[OK] modbus changeTicketId trust boundary enforced: frame-carried "
          "tickets ignored, meta tickets mapped + unvalidated-marker set, "
          "shape check rejects junk (PR #80 finding 1)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
