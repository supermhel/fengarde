"""Shared OCSF helpers (Contract A) reused across workstreams."""
from __future__ import annotations
import sys
from pathlib import Path

# valid_ip/valid_mac/safe_str have no tools/ dependency and are re-exported
# here for backward compatibility with existing callers -- see ip_utils.py's
# module docstring for why they live in their own dependency-free module.
from shared.ip_utils import valid_ip, valid_mac, safe_str  # noqa: F401

# Reuse the single source-of-truth validator in tools/. Resolve its location for
# BOTH the repo layout (repo/services/shared -> repo/tools, parents[2]) and the
# container layout (/app/shared -> /app/tools, parents[1]).
#
# Unlike this module's own MFA-import counterpart in users.py (deliberately
# wrapped in try/except so a missing shared/mfa.py degrades to "TOTP
# off" instead of taking the process down), a missing tools/ directory here
# must NOT degrade silently: validate_event/SCHEMA_PATH are load-bearing for
# every parser's OCSF validation, so a stub/no-op fallback would mean
# malformed events pass through completely unvalidated -- worse than a crash.
# What WAS missing was diagnosability: an unusual container layout that
# doesn't match any of the three candidate paths raised a bare
# ModuleNotFoundError with no indication of what to fix. Still fails loudly
# and still refuses to import -- just says why.
_here = Path(__file__).resolve()
_candidates = (_here.parents[2] / "tools", _here.parents[1] / "tools", Path("/app/tools"))
for _cand in _candidates:
    if (_cand / "validate_contract.py").exists():
        sys.path.insert(0, str(_cand))
        break
else:
    raise RuntimeError(
        "shared/ocsf.py could not find tools/validate_contract.py in any of "
        f"{[str(c) for c in _candidates]}. This is required (OCSF schema "
        "validation, Contract A) -- not an optional dependency. Check the "
        "container/repo layout.")
from validate_contract import load, validate_event, SCHEMA_PATH  # noqa: E402

_SCHEMA = load(SCHEMA_PATH)


def make_type_uid(class_uid: int, activity_id: int) -> int:
    """Always derive type_uid; never hand-set it."""
    return class_uid * 100 + activity_id


def validate(event: dict) -> list[str]:
    """Return list of contract errors ([] means valid)."""
    return validate_event(event, _SCHEMA)


def is_valid(event: dict) -> bool:
    return not validate(event)
