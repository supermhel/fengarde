"""Test fix M18: _safe_glob_from_regex rejects unescaped '.' (silent regex->glob narrowing).

A bare '.' in a regex means "match any char"; translated to a glob it becomes a
literal dot, silently narrowing the Sigma rule to a subset of what it intended.
Both the fully-literal branch AND the prefix/`.*`/suffix branch must REJECT
any pattern containing a '.' outside a `.*` wildcard -- the follow-up fix
(2026-08-06) closes the second branch, which the first M18 pass missed:
`^cmd.exe .*payload$` translated to the glob `cmd.exe *payload`, silently
narrowing "any char after cmd" down to a literal dot. The '.*' -> '*'
wildcard handling itself must stay untouched.

Run:  python tools/test_fix_m18_sigma_glob.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from import_sigma_rules import _safe_glob_from_regex  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def run() -> None:
    # Bare '.' (with or without trailing text) must be rejected, not narrowed.
    check(_safe_glob_from_regex("foo.bar") is None,
          "bare '.' inside literal must be rejected (was silently narrowed)")
    check(_safe_glob_from_regex(".") is None,
          "a lone '.' must be rejected")
    check(_safe_glob_from_regex("foo.") is None,
          "trailing bare '.' must be rejected")

    # '.*' wildcard is still translated to glob '*'.
    check(_safe_glob_from_regex("foo.*bar") == "foo*bar",
          "'.*' -> '*' wildcard translation must be preserved")

    # Fully literal patterns with NO dot still round-trip unchanged.
    check(_safe_glob_from_regex("foobar") == "foobar",
          "plain literal must round-trip unchanged")

    # Follow-up (2026-08-06): a bare '.' in the PREFIX or SUFFIX around a
    # `.*` wildcard must also be rejected, not silently narrowed.
    check(_safe_glob_from_regex("^cmd.exe .*payload$") is None,
          "bare '.' in the prefix before '.*' must be rejected "
          "(regression: was silently narrowed to 'cmd.exe *payload')")
    check(_safe_glob_from_regex("^powershell .*a.b$") is None,
          "bare '.' in the suffix after '.*' must be rejected")
    check(_safe_glob_from_regex("^cmd .*payload$") == "cmd *payload",
          "prefix/suffix with NO dot around '.*' must still translate")
    check(_safe_glob_from_regex("^prefix.*suffix$") == "prefix*suffix",
          "anchored prefix/suffix with no dots must still translate")


def main() -> None:
    run()
    if FAILS:
        print(f"[FAIL] test_fix_m18_sigma_glob: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] _safe_glob_from_regex rejects bare '.' and keeps '.*' -> '*'")
    return None


if __name__ == "__main__":
    main()
