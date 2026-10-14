"""DCO v1.1 check for every commit a PR would merge (.github/workflows/dco.yml).

Per COMMIT, not in aggregate: a commit passes only when one of its git
trailers is ``Signed-off-by: Name <email>`` whose email equals the commit's
AUTHOR email (case-insensitive) -- the DCO certifies the author's own right
to submit. Review of PR #96 (2026-10-14) found the previous inline check
compared the TOTAL number of matching lines anywhere in the messages against
the commit count, so one commit carrying two sign-offs let an unsigned commit
through, and a line in the body (not a trailer) counted too.

Fail-closed: a missing/unknown base commit is an error, never a skip (a
skipped required check renders green). Merge commits are checked like any
other commit -- rebase onto the base branch instead of GitHub's "Update
branch" merge, or sign the merge (``git commit -s --amend``).

Run:  python tools/check_dco.py <base-sha> [<head-ref>]      (default head: HEAD)
"""
from __future__ import annotations

import subprocess
import sys


def _git(*args: str, cwd: str | None = None) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True,
                          capture_output=True, text=True).stdout


def unsigned_commits(base: str, head: str = "HEAD",
                     cwd: str | None = None) -> tuple[int, list[str]]:
    """(commits checked, ["<sha> <subject>" for each commit failing DCO])."""
    shas = _git("rev-list", f"{base}..{head}", cwd=cwd).split()
    bad = []
    for sha in shas:
        author, subject = _git("show", "-s", "--format=%ae%x00%s", sha,
                               cwd=cwd).rstrip("\n").split("\x00", 1)
        sobs = _git("show", "-s",
                    "--format=%(trailers:key=Signed-off-by,valueonly,unfold)",
                    sha, cwd=cwd).lower()
        if f"<{author.lower()}>" not in sobs:
            bad.append(f"{sha[:12]} {subject} (author {author})")
    return len(shas), bad


def main(argv: list[str]) -> int:
    if len(argv) < 2 or not argv[1]:
        print("[FAIL] check_dco: no base sha given -- refusing to pass an unchecked PR")
        return 1
    base, head = argv[1], (argv[2] if len(argv) > 2 else "HEAD")
    try:
        _git("rev-parse", "--quiet", "--verify", f"{base}^{{commit}}")
        total, bad = unsigned_commits(base, head)
    except subprocess.CalledProcessError as exc:
        print(f"[FAIL] check_dco: git failed ({exc.stderr.strip() or exc}) -- "
              f"base {base} not in this checkout? fetch-depth must be 0")
        return 1
    print(f"commits={total} signed_off={total - len(bad)}")
    if bad:
        print(f"[FAIL] {len(bad)}/{total} commit(s) lack a Signed-off-by trailer "
              f"matching the commit author:")
        for b in bad:
            print(f"  {b}")
        print("Every commit must be signed off (Developer Certificate of Origin v1.1).")
        print("  git commit -s                          # for new commits")
        print("  git rebase --signoff <base>            # sign every commit on the branch")
        print("See CONTRIBUTING.md -> Pull request expectations -> DCO.")
        return 1
    print("[OK] every new commit is signed off by its author (DCO v1.1)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
