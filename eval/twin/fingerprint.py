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
    "eval/twin/scenario.py",
    "eval/twin/scenarios_extra.py",
    "eval/twin/scenario_registry.py",
    "eval/twin/report.py",
    "eval/twin/negative_controls.py",
    "eval/twin/plc_sim.py",
    "eval/twin/degradation.py",
    "eval/twin/oracle*.yaml",
    "eval/adversarial/mutate.py",
    "eval/adversarial/mutate_generic.py",
    "eval/adversarial/layer_a.py",
    "eval/adversarial/scenario_matrix.py",
    "eval/adversarial/evasion_search.py",
    "eval/adversarial/corpus_b.py",
    "eval/attack/fire_check.py",
    "tools/detection_quality_eval.py",
    "services/shared/**/*.py",
    "services/ws2-normalization/**/*.py",
    "services/ws4-detection/**/*.py",
    "services/ws8-correlation/**/*.py",
)


def fingerprint_files(root: Path = ROOT) -> list[Path]:
    """Return the sorted, de-duplicated files contributing to the digest."""
    files: set[Path] = set()
    for pattern in _FINGERPRINT_GLOBS:
        files.update(p for p in root.glob(pattern) if p.is_file())
    out = []
    for path in sorted(files, key=lambda p: p.relative_to(root).as_posix()):
        rel = path.relative_to(root).as_posix()
        if "__pycache__" in path.parts or path.name.startswith("test_"):
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
