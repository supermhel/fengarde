"""Generate a CycloneDX SBOM for the whole repo (M2 supply-chain, PLAN_C Tier 2.2).

FENGARDE has no single dependency manifest (ADR 004: seven independently-
deployed workstreams, each with its own requirements.txt). This merges every
service's *runtime* requirements.txt into one combined file and runs
cyclonedx-py against it, so `sbom.json` covers the whole deployable system in
one document rather than requiring a consumer to find and combine 6 files
themselves.

Test-only dependencies (hypothesis, ruff, mypy, ...) are deliberately
excluded -- an SBOM answers "what ships/runs," not "what the CI pipeline
uses to check it."

Run:  python tools/generate_sbom.py            # writes sbom.json at repo root
      python tools/generate_sbom.py --check     # regenerate + diff against
                                                   the committed sbom.json,
                                                   exit 1 if stale (CI use)
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "sbom.json"

# Runtime requirements.txt files (excludes devkit-feeder, which pip-installs
# its one dependency inline in its Dockerfile rather than via a requirements
# file, and ws7-dashboard, which is static+nginx with no Python deps).
REQUIREMENTS_FILES = [
    "services/ws1-collectors/requirements.txt",
    "services/ws2-normalization/requirements.txt",
    "services/ws3-indexer/requirements.txt",
    "services/ws4-detection/requirements.txt",
    "services/ws5-ai/requirements.txt",
    "services/ws6-inventory/requirements.txt",
]


def merged_requirements() -> str:
    """Combine every service's requirements.txt into one deduplicated,
    sorted list -- comments stripped (they're per-file context that doesn't
    survive merging meaningfully; the SBOM's provenance is this repo, not
    the comment)."""
    packages: set[str] = set()
    for rel in REQUIREMENTS_FILES:
        path = ROOT / rel
        if not path.exists():
            continue
        for line in path.read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                packages.add(line)
    return "\n".join(sorted(packages)) + "\n"


def _components(path: Path) -> list:
    """The part of the SBOM that actually matters for staleness: what's
    declared. Excludes `metadata.timestamp`, which differs on every
    regeneration even when the dependency graph hasn't changed -- a raw file
    diff would always report "stale" and make the check meaningless."""
    return sorted(
        (c.get("name"), c.get("version")) for c in json.loads(path.read_text()).get("components", [])
    )


def main() -> int:
    check_mode = "--check" in sys.argv
    before = _components(OUTPUT) if check_mode and OUTPUT.exists() else None

    merged_text = merged_requirements()
    merged_path = ROOT / ".merged-requirements.txt"
    merged_path.write_text(merged_text)

    try:
        subprocess.run(
            ["cyclonedx-py", "requirements", str(merged_path),
             "-o", str(OUTPUT), "--output-format", "json"],
            check=True, cwd=ROOT,
        )
    finally:
        merged_path.unlink(missing_ok=True)

    if check_mode:
        after = _components(OUTPUT)
        if before is None:
            print("[FAIL] sbom.json does not exist -- generate and commit it")
            return 1
        if before != after:
            print(f"[FAIL] sbom.json's declared components are stale:\n"
                  f"  committed: {before}\n  actual:    {after}\n"
                  f"Regenerate with `python tools/generate_sbom.py` and commit it.")
            return 1
        # Regenerating always touches metadata.timestamp even when components
        # didn't change -- restore the committed file so `--check` is a pure
        # read (no incidental diff) rather than silently rewriting it.
        subprocess.run(["git", "checkout", "--", str(OUTPUT)], cwd=ROOT, check=False)
        print("[OK] sbom.json is up to date")
        return 0

    print(f"[OK] wrote {OUTPUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
