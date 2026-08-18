"""Tests for shared/allowlist.py (moved here 2026-08-18 from
ws4-detection/engine.py so WS-8 correlation can reuse it -- see that
module's docstring). Behavior is unchanged from before the move; WS-4's own
`not_in` operator tests (test_v03_rule_grammar.py etc.) exercise it
end-to-end through the rule engine, this file tests the loader/matcher
directly and in isolation.

Run: python services/shared/test_allowlist.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from shared.allowlist import Allowlist, invalidate_dir, load_allowlist  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def test_exact_match():
    al = Allowlist(["svc_backup", "10.0.0.5"])
    check(al.matches("svc_backup"), "exact string entry must match")
    check(not al.matches("svc_other"), "a non-listed string must not match")
    check(not al.matches(None), "None must never match")


def test_cidr_match():
    al = Allowlist(["10.0.0.0/8", "192.168.1.1"])
    check(al.matches("10.1.2.3"), "an address inside the CIDR range must match")
    check(al.matches("192.168.1.1"), "a plain-IP entry (no /prefix) must still match itself")
    check(not al.matches("172.16.0.1"), "an address outside every range must not match")


def test_non_cidr_entry_is_exact_only():
    al = Allowlist(["not-an-ip-or-cidr"])
    check(al.matches("not-an-ip-or-cidr"), "a non-CIDR string is still an exact-match entry")
    check(not al.matches("192.168.1.1"), "a real IP must not accidentally match a bad-CIDR entry")


def test_ipv6_vs_ipv4_mismatch_does_not_raise():
    al = Allowlist(["10.0.0.0/8"])
    check(not al.matches("::1"), "an IPv6 address against an IPv4-only allowlist must not match or raise")


def test_ok_false_never_matches():
    al = Allowlist(["10.0.0.0/8"], ok=False)
    check(not al.matches("10.1.2.3"), "ok=False must fail closed regardless of entries")


def test_load_allowlist_missing_file_fails_closed_and_cached():
    with tempfile.TemporaryDirectory() as d:
        al = load_allowlist(Path(d), "does_not_exist")
        check(not al.ok, "a missing allowlist file must load with ok=False")
        check(not al.matches("anything"), "a failed-to-load allowlist must never match")
        # cached: a second load of the SAME (dir, name) must return the cached object
        al2 = load_allowlist(Path(d), "does_not_exist")
        check(al is al2, "load_allowlist must cache by (resolved dir, name)")


def test_load_allowlist_valid_file():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "corp.yml"
        p.write_text("entries:\n  - \"10.0.0.0/8\"\n", encoding="utf-8")
        al = load_allowlist(Path(d), "corp")
        check(al.ok, "a well-formed allowlist file must load with ok=True")
        check(al.matches("10.1.1.1"), "a loaded CIDR entry must actually match")


def test_load_allowlist_malformed_shape_fails_closed():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "bad.yml"
        p.write_text("not_a_dict_with_entries: true\n", encoding="utf-8")
        al = load_allowlist(Path(d), "bad")
        check(not al.ok, "a file missing the 'entries:' list must fail closed, not raise")


def test_invalidate_dir_clears_cache_for_that_dir_only():
    with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
        p1 = Path(d1) / "x.yml"
        p1.write_text("entries:\n  - \"a\"\n", encoding="utf-8")
        p2 = Path(d2) / "x.yml"
        p2.write_text("entries:\n  - \"b\"\n", encoding="utf-8")
        al1_before = load_allowlist(Path(d1), "x")
        al2_before = load_allowlist(Path(d2), "x")
        invalidate_dir(Path(d1))
        al1_after = load_allowlist(Path(d1), "x")
        al2_after = load_allowlist(Path(d2), "x")
        check(al1_before is not al1_after,
              "invalidate_dir must drop the cache entry for its own directory")
        check(al2_before is al2_after,
              "invalidate_dir must NOT touch a different directory's cached allowlist")


def run_all():
    test_exact_match()
    test_cidr_match()
    test_non_cidr_entry_is_exact_only()
    test_ipv6_vs_ipv4_mismatch_does_not_raise()
    test_ok_false_never_matches()
    test_load_allowlist_missing_file_fails_closed_and_cached()
    test_load_allowlist_valid_file()
    test_load_allowlist_malformed_shape_fails_closed()
    test_invalidate_dir_clears_cache_for_that_dir_only()


if __name__ == "__main__":
    run_all()
    if FAILS:
        print(f"[FAIL] shared allowlist: {len(FAILS)} problem(s)")
        for f in FAILS:
            print(f"  - {f}")
        sys.exit(1)
    print("[OK] shared allowlist: exact/CIDR match, fail-closed on missing/malformed file, "
          "per-directory cache + invalidation")
