"""FENGARDE_PROFILE=prod startup gate (WP-3.2): refuse to boot with an
incomplete or DEFAULT-secured auth surface, and make first-boot admin
provisioning possible without an env-var password.

Demo/profile-less runs are byte-for-byte unchanged: every check here is
gated on ``FENGARDE_PROFILE`` (case-insensitive) being exactly ``prod``.

What prod REQUIRES (aggregated — one numbered failure list, never the
first-failure-only):

  1. ``FENGARDE_API_KEY`` set                        (API-key auth on ws3 write
     surfaces; an unset key runs the service default-open);
  2. ``FENGARDE_RBAC_DB`` set                        (role-based access ON;
     prod without RBAC is default-open by design choice, so it is a refusal);
  3. admin credential: ``FENGARDE_ADMIN_PASSWORD`` set and NOT a known
     default, OR ``FENGARDE_FIRST_BOOT_FILE`` set (explicit first-boot
     generation into a FILE is allowed);
  4. ``FENGARDE_ADMIN_PASSWORD`` (when provided) must not be a known default
     (admin / password / changeme / fengarde / ... case-insensitive) and
     must meet the user store's length rule;
  5. Redis-backed bus -> ``REDIS_PASSWORD`` set.

First-boot generation (``generate_first_boot_password``) writes a fresh
strong password to ``FENGARDE_FIRST_BOOT_FILE`` with mode 0600 and a header
that says rotate-and-delete. This is the WP-3.2 requirement and is an
EXPLICIT, prod-profile-only exception to the repo's standing rule
(users.py: "the service never stores a plaintext credential"; the earlier
write-to-0600 design was closed as CodeQL py/clear-text-storage in the
DEFAULT path). Rationale, stated plainly: an environment variable is
readable via /proc/<pid>/environ by any same-user process; a 0600 file is
not, and the file's owner is told to rotate + delete it after first login.
Never log the generated value — only its path.
"""
from __future__ import annotations

import os
import secrets
import stat
import sys
from pathlib import Path
from typing import Optional

from shared.log import get_logger

DEFAULT_PASSWORDS = frozenset({
    "", "admin", "password", "changeme", "fengarde", "fengarde2026",
    "admin123", "password123", "changeme123", "secret", "123456", "12345678",
    "administrator", "letmein",
})


def prod_active() -> bool:
    """True when FENGARDE_PROFILE (case-insensitive) is exactly 'prod'."""
    return os.getenv("FENGARDE_PROFILE", "").strip().lower() == "prod"


# The printed refusal text comes ONLY from this table of constants, looked up by a reason code. The password value (and
# anything derived from it) never reaches a message, a log record or stderr; CodeQL py/clear-text-logging-sensitive-data
# would otherwise follow the value into the aggregated failure list.
_PW_REASONS = {
    "type": "must be a string",
    "default": "is a known default password — prod refuses to start with it",
    "short": "is shorter than the 12-character minimum (the user store's own rule)",
    "long": "is longer than the 256-character maximum",
}


def admin_password_issue(password: object, min_chars: int = 12) -> Optional[str]:
    """Reason CODE (a key of ``_PW_REASONS``) why the admin password is unacceptable for prod, or None."""
    if not isinstance(password, str):
        return "type"
    if password.strip().lower() in DEFAULT_PASSWORDS:
        return "default"
    if len(password) < min_chars:
        return "short"
    if len(password) > 256:
        return "long"
    return None


def admin_password_ok(password: str, min_chars: int = 12) -> Optional[str]:
    """Why the provided admin password is unacceptable for prod, or None (constant text, never the value).

    Default-credential refusal is the point (a known admin password with
    RBAC on is still default-open); length mirrors users.password_problem.
    """
    code = admin_password_issue(password, min_chars)
    if code == "short" and min_chars != 12:
        return f"is shorter than the {int(min_chars)}-character minimum (the user store's own rule)"
    return None if code is None else _PW_REASONS[code]


def _bus_requires_redis_password() -> bool:
    return os.getenv("BUS_BACKEND", "").strip() in ("redis", "redis-sentinel")


def prod_problems() -> list[str]:
    """Every unsatisfied prod obligation, numbered, in a stable order."""
    problems: list[str] = []
    if not os.getenv("FENGARDE_API_KEY"):
        problems.append("FENGARDE_API_KEY is not set (API-key auth would be OFF)")
    if not os.getenv("FENGARDE_RBAC_DB"):
        problems.append("FENGARDE_RBAC_DB is not set (role-based access would be OFF)")
    pw = os.getenv("FENGARDE_ADMIN_PASSWORD")
    if not pw:
        # first-boot generation (FENGARDE_FIRST_BOOT_FILE) is ALLOWED at
        # startup: the triage bootstrap generates ONLY when the user store is
        # empty and fails closed otherwise — prodcheck cannot see the store.
        if not os.getenv("FENGARDE_FIRST_BOOT_FILE"):
            problems.append(
                "no admin credential: set FENGARDE_ADMIN_PASSWORD or "
                "FENGARDE_FIRST_BOOT_FILE (prod generates a fresh password into "
                "that file at first boot)")
    else:
        code = admin_password_issue(pw)
        if code:
            problems.append("FENGARDE_ADMIN_PASSWORD " + _PW_REASONS[code])
    if _bus_requires_redis_password() and not os.getenv("REDIS_PASSWORD"):
        problems.append("REDIS_PASSWORD is not set (Redis bus with no auth)")
    return problems


def prod_or_die(service: str) -> None:
    """Refuse to start in prod when any obligation is missing.

    Prints ONE aggregated failure list (numbered, every problem at once —
    an operator fixes the whole list in one pass, not one refusal per boot)
    and exits 1. No-op unless ``FENGARDE_PROFILE=prod``; the zero-config
    demo path is untouched.
    """
    if not prod_active():
        return
    problems = prod_problems()
    if not problems:
        return
    head = "FENGARDE_PROFILE=prod but the secure surface is incomplete:"
    body = "\n".join(f"  {i}) {p}" for i, p in enumerate(problems, 1))
    get_logger(service).error(head, problems=problems)
    print(f"{head}\n{body}", file=sys.stderr)
    sys.exit(1)


def generate_first_boot_password(file_env: str = "FENGARDE_FIRST_BOOT_FILE",
                                 min_chars: int = 20) -> str:
    """Generate a strong password, write it 0600 to the env-given path,
    return the value for the in-process first-boot admin creation.

    The file replaces the env var as the ONLY holder of the plaintext; the
    header tells the operator to rotate and delete after first login. The
    password is never logged (callers must not print it either).
    """
    path = os.getenv(file_env)
    if not path:
        raise ValueError(f"{file_env} must be set to generate a first-boot password")
    # token_urlsafe is URL-safe base64: 15 bytes -> 20 chars, entropy ~120 bit
    password = secrets.token_urlsafe(min_chars + 9)[:min_chars + 3]
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    header = (
        "# FENGARDE first-boot admin password — FENGARDE_PROFILE=prod\n"
        "# Generated: never logged; rotate it via the admin API after first\n"
        "# login, then DELETE this file (the service user store only ever\n"
        "# holds the scrypt hash).\n"
    )
    with target.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(header)
        fh.write(password + "\n")
    target.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0o600 regardless of umask
    return password