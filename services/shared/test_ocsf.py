"""shared/ocsf.py unit tests.

P0-1 (audit fix plan, docs/superpowers/specs/2026-07-21-audit-fix-plan.md):
valid_ip() accepted IPv4-mapped-IPv6 addresses ("::ffff:a.b.c.d", the form
Windows/Splunk-attack-range logs emit for locally-routed IPv4 traffic seen
over a dual-stack socket) via ipaddress.ip_address(), but Contract A's `ip`
schema pattern's IPv6 branch forbids embedded dots -- so validate() rejected
the event and WS-2 dead-lettered it. Live-proven on real Splunk attack_data
(4 Kerberos brute-force/spray datasets, 50+ failed-preauth events each) and
EVTX-ATTACK-SAMPLES (kerberos_pwd_spray_4771.evtx, DC securitylog): every one
of those events carried '::ffff:10.0.1.15'-shaped IPs and was silently
dropped, so the brute-force/password-spray rules never saw them -> real
missed detections.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(SERVICES))

from shared.ocsf import valid_ip  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def test_ipv4_mapped_ipv6_normalizes_to_plain_ipv4():
    # The exact form observed live in Splunk attack_data + EVTX-ATTACK-SAMPLES.
    check(valid_ip("::ffff:10.0.1.15") == "10.0.1.15",
          "valid_ip must normalize an IPv4-mapped IPv6 address to plain IPv4 "
          "(Contract A's ip pattern rejects dots in the IPv6 branch, so the "
          "un-normalized form dead-letters the event)")
    check(valid_ip("::ffff:172.16.66.1") == "172.16.66.1",
          "valid_ip must normalize IPv4-mapped IPv6 regardless of octets")


def test_plain_ipv4_unaffected():
    check(valid_ip("10.0.1.15") == "10.0.1.15",
          "valid_ip must pass through a plain IPv4 address unchanged")


def test_real_ipv6_unaffected():
    check(valid_ip("fe80::1") == "fe80::1",
          "valid_ip must not touch a genuine (non-IPv4-mapped) IPv6 address")
    check(valid_ip("2001:db8::1") == "2001:db8::1",
          "valid_ip must not touch a genuine IPv6 address with no v4-mapped form")


def test_invalid_input_still_rejected():
    check(valid_ip("not-an-ip") is None,
          "valid_ip must still reject a non-IP string")
    check(valid_ip(12345) is None,
          "valid_ip must still reject a non-string type (unguarded-JSON-field defense)")
    check(valid_ip(None) is None, "valid_ip must reject None")


def test_normalized_output_matches_contract_a_pattern():
    """Belt-and-suspenders: the normalized value must actually satisfy the
    schema pattern this bug was about, not just look right by inspection."""
    import re
    pattern = re.compile(
        r"^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
        r"|^([0-9a-fA-F:]+:[0-9a-fA-F:]*)$"
    )
    for raw in ("::ffff:10.0.1.15", "::ffff:172.16.66.1", "10.0.1.15", "fe80::1"):
        normalized = valid_ip(raw)
        check(normalized is not None and pattern.match(normalized) is not None,
              f"normalized value for {raw!r} ({normalized!r}) must match "
              f"Contract A's ip schema pattern")


def main():
    test_ipv4_mapped_ipv6_normalizes_to_plain_ipv4()
    test_plain_ipv4_unaffected()
    test_real_ipv6_unaffected()
    test_invalid_input_still_rejected()
    test_normalized_output_matches_contract_a_pattern()

    if FAILS:
        print(f"\n[FAIL] ocsf: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] ocsf unit tests PASS")


if __name__ == "__main__":
    main()
