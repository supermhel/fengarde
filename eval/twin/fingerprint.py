"""Deterministic input fingerprint for Phase 6 evaluation artifacts."""
from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Keep this list explicit. It covers behavior that can change a measured atom,
# while excluding generated artifacts, tests, and the ratchet itself.
_FINGERPRINT_GLOBS = (
    "contracts/**/*.yml",
    "contracts/**/*.yaml",
    "contracts/**/*.json",
    # Whole directories, not a hand-picked module list: the first version named
    # eight eval/twin modules and missed the storyline builders
    # (storyline_*.py, scenario_kit.py) and causal_order.py, so editing a
    # storyline moved every scenario atom while an old artifact still carried a
    # matching fingerprint (2026-10-14 review). Over-inclusion only forces a re-run.
    "eval/twin/*.py",
    "eval/twin/oracle*.yaml",
    "eval/adversarial/*.py",
    "eval/adversarial/*.yaml",            # evasion tables/findings classify search output
    "eval/attack/*.py",
    "tools/detection_quality_eval.py",
    "tools/validate_contract.py",         # shared/ocsf.py validates every event through it
    "tools/check_rule_producers.py",      # fire_check replays its FIXTURES
    "tools/validate_rules.py",            # load_rules validates through it
    "services/**/*.py",
)
# The ratchet's own code reads artifacts, it does not produce them; evasion_floor.yaml is a ratchet
# OUTPUT (written by evasion_cost.py --update-floor), so a deliberate floor refresh must not stale
# every artifact it was refreshed from.
_EXCLUDED = frozenset({"eval/twin/ratchet.py", "eval/twin/ratchet_measure.py",
                       "eval/twin/fingerprint.py", "eval/adversarial/evasion_floor.yaml"})


def fingerprint_files(root: Path = ROOT) -> list[Path]:
    """Return the sorted, de-duplicated files contributing to the digest."""
    files: set[Path] = set()
    for pattern in _FINGERPRINT_GLOBS:
        files.update(p for p in root.glob(pattern) if p.is_file())
    out = []
    for path in sorted(files, key=lambda p: p.relative_to(root).as_posix()):
        rel = path.relative_to(root).as_posix()
        if "__pycache__" in path.parts or path.name.startswith("test_") or rel in _EXCLUDED:
            continue
        if path.suffix in {".pyc", ".json"} and not rel.startswith("contracts/"):
            continue
        out.append(path)
    return out


def system_fingerprint(root: Path = ROOT) -> str:
    """Hash relative paths and LF-normalized bytes in a fixed sorted order."""
    root = Path(root)
    digest = hashlib.sha256()
    for path in fingerprint_files(root):
        rel = path.relative_to(root).as_posix()
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes().replace(b"\r\n", b"\n"))
        digest.update(b"\0")
    return digest.hexdigest()
