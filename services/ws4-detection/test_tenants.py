"""F3 (adversarial repo-wide bug hunt, 2026-07-16) — tenant_id validation
in tenants.py::load_disabled_rules.

Before this fix, `tenant_id` flowed straight into `Path(tenants_dir) /
f"{tenant_id}.yml"` with no validation -- a malformed tenant_id containing
path-traversal sequences (e.g. "../../../etc/passwd") could construct a
path outside contracts/tenants/ entirely. This asserts a malformed
tenant_id is now treated exactly like a missing config file: fail open
(empty frozenset, nothing disabled, full detection coverage), no
exception, and -- provably -- no file is ever read from outside
tenants_dir.

Run: python services/ws4-detection/test_tenants.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))

import tenants  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _fresh_dir_and_secret() -> tuple[Path, Path]:
    """A tenants_dir plus a sibling 'secret' file a path-traversal payload
    would try to reach -- e.g. tenants_dir/../secret.yml."""
    base = Path(tempfile.mkdtemp())
    tenants_dir = base / "tenants"
    tenants_dir.mkdir()
    secret = base / "secret.yml"
    secret.write_text("disabled_rules: [common_bruteforce]\n", encoding="utf-8")
    return tenants_dir, secret


def test_path_traversal_tenant_id_fails_open_no_exception():
    tenants_dir, secret = _fresh_dir_and_secret()
    tenants._CACHE.clear()

    for bad in ("../secret", "../../secret", "..%2Fsecret", "a/../../secret"):
        disabled = tenants.load_disabled_rules(tenants_dir, bad)
        check(disabled == frozenset(), f"path-traversal tenant_id={bad!r} must fail open, got {disabled!r}")


def test_path_traversal_tenant_id_never_reads_outside_tenants_dir():
    tenants_dir, secret = _fresh_dir_and_secret()
    tenants._CACHE.clear()

    # If the guard were missing, "../secret" would resolve to tenants_dir/../secret.yml
    # == secret.yml, and its disabled_rules entry (common_bruteforce) would leak in.
    disabled = tenants.load_disabled_rules(tenants_dir, "../secret")
    check("common_bruteforce" not in disabled,
          "a path-traversal tenant_id must never read the sibling secret.yml's contents")


def test_malformed_tenant_id_shapes_fail_open():
    tenants_dir, _ = _fresh_dir_and_secret()
    tenants._CACHE.clear()

    for bad in ("UPPER", "has space", "-leading", "trailing-", "", "a" * 64):
        disabled = tenants.load_disabled_rules(tenants_dir, bad)
        check(disabled == frozenset(), f"malformed tenant_id={bad!r} must fail open, got {disabled!r}")


def test_valid_tenant_and_default_still_load_normally():
    tenants_dir, _ = _fresh_dir_and_secret()
    tenants._CACHE.clear()

    (tenants_dir / "acme-corp.yml").write_text("disabled_rules: [common_bruteforce]\n", encoding="utf-8")
    disabled = tenants.load_disabled_rules(tenants_dir, "acme-corp")
    check(disabled == frozenset({"common_bruteforce"}),
          f"a valid tenant_id's real config must still load, got {disabled!r}")

    default_disabled = tenants.load_disabled_rules(tenants_dir, "default")
    check(default_disabled == frozenset(), f"default tenant with no config file must be empty, got {default_disabled!r}")


def test_invalid_tenant_id_never_cached():
    """P2-1 (2026-07-21 audit): an invalid tenant_id must NOT be written to
    _CACHE -- caching it would let an attacker grow the dict for free with
    unlimited distinct garbage strings, defeating the LRU cap's purpose."""
    tenants_dir, _ = _fresh_dir_and_secret()
    tenants._CACHE.clear()

    tenants.load_disabled_rules(tenants_dir, "../secret")
    cache_key = f"{Path(tenants_dir).resolve()}::../secret"
    check(cache_key not in tenants._CACHE,
          "invalid tenant_id must not be written to _CACHE at all")


def test_cache_is_bounded_under_many_distinct_tenants():
    """P2-1: valid-shaped but distinct tenant_id values must not grow
    _CACHE past _CACHE_MAXSIZE (LRU eviction caps memory)."""
    tenants_dir, _ = _fresh_dir_and_secret()
    tenants._CACHE.clear()

    n = tenants._CACHE_MAXSIZE + 200
    for i in range(n):
        tenants.load_disabled_rules(tenants_dir, f"tenant{i:06d}")

    check(len(tenants._CACHE) <= tenants._CACHE_MAXSIZE,
          f"_CACHE grew to {len(tenants._CACHE)}, expected <= {tenants._CACHE_MAXSIZE}")


def run():
    test_path_traversal_tenant_id_fails_open_no_exception()
    test_path_traversal_tenant_id_never_reads_outside_tenants_dir()
    test_malformed_tenant_id_shapes_fail_open()
    test_valid_tenant_and_default_still_load_normally()
    test_invalid_tenant_id_never_cached()
    test_cache_is_bounded_under_many_distinct_tenants()


def main():
    run()
    if FAILS:
        print(f"[FAIL] tenants.load_disabled_rules validation: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] F3: tenants.load_disabled_rules fails open (no exception, empty frozenset, "
          "no read outside tenants_dir) for a malformed/path-traversal-shaped tenant_id; "
          "valid tenants and the default sentinel still load normally")


if __name__ == "__main__":
    main()
