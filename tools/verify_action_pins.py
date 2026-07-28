"""Verify every GitHub Action reference is SHA-pinned and that its trailing
version comment tells the truth.

Why this exists: a workflow file is only exercised by the triggers IT declares.
`scorecard.yml` runs on `schedule` / `push: [main]` / `branch_protection_rule`
-- never on `pull_request` -- so nothing in PR CI executes it, and a bad edit
ships to `main` and sits until the next cron. That is not hypothetical: this
repo's `actionlint` job exists because `ossf/scorecard-action@v2` was an
unresolvable tag that shipped broken and was only discovered on its first live
run, and the `attack-scorecard` job's `upload-artifact` line carried a NOTE for
months saying its SHA had never been verified.

This gate closes that specific hole by checking the CONTENT of every workflow
from a job that does run on every PR. A workflow with no PR trigger is still
just a file on disk, and a file on disk can be validated without executing it.

Two properties are enforced:

  * **Pinned.** Every `uses:` must reference a 40-character commit SHA, not a
    floating tag. A tag can be moved; a commit cannot.
  * **Honest.** If the line carries a trailing `# v1.2.3` comment, that tag must
    actually resolve upstream to the pinned commit. Under SHA pinning that
    comment is the ONLY human-readable record of what is pinned, so a stale one
    is worse than none -- it is a claim nobody re-checks. Annotated tags are
    resolved through their peeled ref (`refs/tags/X^{}`), which is the commit a
    `uses:` actually needs; comparing against the unpeeled tag object would
    report a false mismatch on every annotated tag (github/codeql-action's are).

What this CANNOT catch, stated so nobody reads more into a green run: it
verifies that a pin RESOLVES, not that the action still BEHAVES. Bumping
`codeql-action/init` to v4 while leaving `analyze` on v3 resolves perfectly and
still fails at runtime with a configuration error (PR #26). Only executing the
workflow catches that, which is why `scorecard.yml` also gained a
`workflow_dispatch` trigger -- so it can be run on demand after a change
instead of waiting for the weekly cron to discover the problem.

Run: python tools/verify_action_pins.py            # full check (needs network)
     python tools/verify_action_pins.py --offline  # pin-shape only, zero infra
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"

# `uses: owner/repo[/sub/path]@ref` with an optional trailing `# comment`.
_USES = re.compile(r"^\s*(?:-\s*)?uses:\s*(?P<spec>\S+)(?:\s+#\s*(?P<comment>\S+))?")
_SHA = re.compile(r"^[0-9a-f]{40}$")
# Tag-shaped comments only: `# v4.37.3`, `# v4`. Anything else is prose.
_TAGLIKE = re.compile(r"^v?\d[\w.\-]*$")


def parse_uses(line: str) -> tuple[str, str, str] | None:
    """(repo, ref, comment) for an action reference, or None.

    Local (`./path`) and container (`docker://`) actions are not pinnable this
    way and are skipped rather than reported."""
    m = _USES.match(line)
    if not m:
        return None
    spec = m.group("spec").strip("\"'")
    if spec.startswith("./") or spec.startswith("docker://"):
        return None
    if "@" not in spec:
        return spec, "", (m.group("comment") or "")
    path, ref = spec.rsplit("@", 1)
    parts = path.split("/")
    repo = "/".join(parts[:2])  # owner/repo, dropping any sub-action path
    return repo, ref, (m.group("comment") or "")


def scan() -> list[tuple[Path, int, str, str, str]]:
    """(file, lineno, repo, ref, comment) for every action reference on disk."""
    found = []
    for path in sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml")):
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            parsed = parse_uses(line)
            if parsed:
                found.append((path, lineno, *parsed))
    return found


_TAG_CACHE: dict[str, dict[str, set[str]] | None] = {}


def tags_by_commit(repo: str) -> dict[str, set[str]] | None:
    """{commit_sha: {tag names pointing at it}} for one repo, or None if the
    repo could not be reached.

    Annotated tags are recorded under their PEELED commit (`refs/tags/X^{}`),
    which is what a `uses:` reference actually needs -- the unpeeled ref is the
    tag object and would never match a pin."""
    if repo in _TAG_CACHE:
        return _TAG_CACHE[repo]
    try:
        out = subprocess.run(
            ["git", "ls-remote", "--tags", f"https://github.com/{repo}"],
            capture_output=True, text=True, timeout=120,
        )
    except (subprocess.TimeoutExpired, OSError):
        _TAG_CACHE[repo] = None
        return None
    if out.returncode != 0:
        _TAG_CACHE[repo] = None
        return None

    direct: dict[str, str] = {}   # tag -> sha of whatever the ref points at
    peeled: dict[str, str] = {}   # tag -> commit sha, for annotated tags
    for line in out.stdout.splitlines():
        parts = line.split()
        if len(parts) != 2 or not parts[1].startswith("refs/tags/"):
            continue
        sha, ref = parts
        name = ref[len("refs/tags/"):]
        if name.endswith("^{}"):
            peeled[name[:-3]] = sha
        else:
            direct[name] = sha

    by_commit: dict[str, set[str]] = {}
    for name, sha in direct.items():
        commit = peeled.get(name, sha)
        by_commit.setdefault(commit, set()).add(name)
    _TAG_CACHE[repo] = by_commit
    return by_commit


def comment_is_satisfied(tags: set[str], comment: str) -> bool:
    """Does the pinned commit carry a tag consistent with its comment?

    An EXACT comment (`v4.37.3`) must name a tag on that very commit. A
    MAJOR-ONLY comment (`v4`) means "some v4.x release", which is the normal
    convention -- and it must NOT be compared against the floating `v4` tag,
    because that tag advances with every patch release, so a correctly pinned
    older v4.x commit would be reported as a mismatch forever. Requiring the
    commit to carry any `v4`/`v4.*` tag checks what the comment actually
    claims: this is a real released v4."""
    if comment in tags:
        return True
    major = comment.split(".")[0]
    if comment == major:  # major-only comment
        return any(t == major or t.startswith(major + ".") for t in tags)
    return False


def main(argv: list[str]) -> int:
    offline = "--offline" in argv
    refs = scan()
    problems: list[str] = []
    checked_tags = 0

    for path, lineno, repo, ref, comment in refs:
        where = f"{path.relative_to(ROOT)}:{lineno}"
        if not _SHA.match(ref):
            problems.append(
                f"{where}: {repo}@{ref} is not SHA-pinned -- a tag can be moved "
                f"under you, a commit cannot")
            continue
        if offline or not _TAGLIKE.match(comment):
            continue
        by_commit = tags_by_commit(repo)
        if by_commit is None:
            problems.append(
                f"{where}: could not reach github.com/{repo} to verify its "
                f"pin -- treated as a failure, not skipped, so a network "
                f"outage cannot quietly turn this gate into a no-op")
            continue
        tags = by_commit.get(ref, set())
        if not tags:
            problems.append(
                f"{where}: {repo} is pinned to {ref}, which carries no release "
                f"tag upstream -- either the commit does not exist or it is "
                f"not a released version (comment claims {comment})")
        elif not comment_is_satisfied(tags, comment):
            problems.append(
                f"{where}: {repo} is pinned to {ref}, which is "
                f"{'/'.join(sorted(tags))}, but its comment says {comment} -- "
                f"that comment is the only human-readable record of this pin")
        else:
            checked_tags += 1

    mode = "offline (pin shape only)" if offline else "full (tags resolved upstream)"
    print(f"action-pin check -- {len(refs)} action reference(s) across "
          f"{len(list(WORKFLOWS.glob('*.y*ml')))} workflow file(s), mode: {mode}")

    if problems:
        print(f"\n[FAIL] {len(problems)} problem(s):")
        for p in problems:
            print(f"    {p}")
        return 1

    if offline:
        print("[OK] every action reference is SHA-pinned "
              "(tags NOT resolved -- run without --offline in CI)")
    else:
        print(f"[OK] every action reference is SHA-pinned and all {checked_tags} "
              f"version comment(s) resolve to the commit they claim")
    print("     note: this proves pins RESOLVE, not that an action still BEHAVES "
          "-- see this file's docstring")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
