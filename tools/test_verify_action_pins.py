"""verify_action_pins.py contract tests -- offline, no network.

The gate's whole value is that it goes RED on a bad pin. A check that only
ever passes is decoration, so every defect class it claims to catch is
constructed here and required to fail, and every legitimate shape is required
to pass. The network-dependent half (resolving tags upstream) runs in CI; the
logic tested here is the part that decides pass/fail once the tags are known.

Run: python tools/test_verify_action_pins.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import verify_action_pins as v  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def test_parses_real_workflow_shapes():
    cases = [
        ("      - uses: actions/checkout@abc  # v4",
         ("actions/checkout", "abc", "v4")),
        ("        uses: gitleaks/gitleaks-action@def  # v3.0.0",
         ("gitleaks/gitleaks-action", "def", "v3.0.0")),
        # sub-action path: the repo is owner/repo, not owner/repo/sub
        ("      - uses: github/codeql-action/init@ghi  # v4.37.3",
         ("github/codeql-action", "ghi", "v4.37.3")),
        # no comment at all
        ("      - uses: actions/cache@jkl", ("actions/cache", "jkl", "")),
        # floating tag, no SHA
        ("      - uses: actions/upload-artifact@v7",
         ("actions/upload-artifact", "v7", "")),
    ]
    for line, expected in cases:
        got = v.parse_uses(line)
        check(got == expected, f"parse_uses({line!r}) -> {got}, expected {expected}")


def test_skips_unpinnable_references():
    for line in ("      - uses: ./.github/actions/local",
                 "      - uses: docker://alpine:3.19"):
        check(v.parse_uses(line) is None,
              f"expected {line!r} to be skipped (not pinnable by SHA)")
    check(v.parse_uses("      - name: not a uses line") is None,
          "non-uses line was parsed as an action reference")


def test_exact_comment_must_name_a_tag_on_that_commit():
    check(v.comment_is_satisfied({"v4.37.3", "v4"}, "v4.37.3") is True,
          "exact comment matching a tag on the commit was rejected")
    check(v.comment_is_satisfied({"v4.37.2"}, "v4.37.3") is False,
          "exact comment was accepted against a DIFFERENT release -- this is "
          "the stale-comment case the gate exists to catch")
    check(v.comment_is_satisfied(set(), "v4.37.3") is False,
          "exact comment accepted on a commit carrying no tags at all")


def test_major_only_comment_accepts_any_release_in_that_major():
    """`# v4` means 'some v4.x'. It must NOT be compared against the floating
    v4 tag: that tag advances with every patch release, so a correctly pinned
    older v4.x commit would be reported as a mismatch forever. This exact
    false positive fired on actions/checkout the first time the gate ran."""
    check(v.comment_is_satisfied({"v4.1.7"}, "v4") is True,
          "major-only comment rejected a legitimate older v4.x pin -- the "
          "false-positive class that would make this gate unusable")
    check(v.comment_is_satisfied({"v4"}, "v4") is True,
          "major-only comment rejected a commit carrying the major tag itself")
    check(v.comment_is_satisfied({"v3.9.9"}, "v4") is False,
          "major-only comment accepted a pin from a DIFFERENT major version")
    check(v.comment_is_satisfied({"v40.1.0"}, "v4") is False,
          "major-only comment 'v4' accepted a v40 tag -- prefix matching must "
          "respect the version separator")


def test_sha_shape_is_enforced():
    check(v._SHA.match("34e114876b0b11c390a56381ad16ebd13914f8d5") is not None,
          "a real 40-hex commit SHA was rejected")
    for bad in ("v4", "34e1148", "34e114876b0b11c390a56381ad16ebd13914f8dZ",
                "34e114876b0b11c390a56381ad16ebd13914f8d5a"):
        check(v._SHA.match(bad) is None, f"{bad!r} was accepted as a SHA pin")


def test_taglike_comments_are_distinguished_from_prose():
    for good in ("v4", "v4.37.3", "3.0.0"):
        check(v._TAGLIKE.match(good) is not None,
              f"{good!r} should be treated as a version comment")
    for prose in ("NOTE:", "see", "pinned"):
        check(v._TAGLIKE.match(prose) is None,
              f"{prose!r} should be treated as prose, not a version claim")


def test_every_workflow_on_disk_is_scanned():
    """The gate is worthless if it silently scans nothing -- the same
    'a check that stopped running looks like a check that passed' failure this
    repo already hit in eval/attack/fire_check.py."""
    refs = v.scan()
    files = {p.name for p, *_ in refs}
    on_disk = {p.name for p in v.WORKFLOWS.glob("*.yml")}
    check(len(refs) > 0, "scan() found no action references at all")
    check(files == on_disk,
          f"scan() covered {sorted(files)} but {sorted(on_disk)} exist on disk "
          f"-- a workflow with no PR trigger is exactly what this gate is for")


def test_offline_mode_passes_on_the_real_repo():
    """Offline mode is what runs in the zero-infra gate, so it must not need
    the network and must be green on the tree as it stands."""
    rc = v.main(["--offline"])
    check(rc == 0, f"offline pin check failed on the real workflows (rc={rc})")


def main():
    test_parses_real_workflow_shapes()
    test_skips_unpinnable_references()
    test_exact_comment_must_name_a_tag_on_that_commit()
    test_major_only_comment_accepts_any_release_in_that_major()
    test_sha_shape_is_enforced()
    test_taglike_comments_are_distinguished_from_prose()
    test_every_workflow_on_disk_is_scanned()
    test_offline_mode_passes_on_the_real_repo()

    if FAILS:
        print(f"[FAIL] tools/verify_action_pins.py: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] action-pin gate: parses every real workflow shape, enforces "
          "SHA pinning, catches a stale exact version comment and a "
          "wrong-major pin, and does not false-positive on the normal "
          "'# v4 means some v4.x' convention")


if __name__ == "__main__":
    main()
