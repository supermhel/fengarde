"""FENGARDE_PROFILE=prod startup gate (WP-3.2): refuse to boot with an
incomplete or DEFAULT-secured auth surface, and make first-boot admin
provisioning possible without an env-var password.

Demo/profile-less runs are byte-for-byte unchanged: every check here is
gated on ``FENGARDE_PROFILE`` (case-insensitive) being exactly ``prod``.

What prod REQUIRES (aggregated — one numbered failure list, never the
first-failure-only):

  0. ``FENGARDE_PROFILE`` itself is recognised (prod / dev / demo / unset): any
     other non-empty value (``production``, ``prd``, ``prod-``) is a typo that
     would silently run the open demo, so it is REFUSED, not ignored;
  1. ``FENGARDE_API_KEY`` set and >= 24 chars        (API-key auth on ws3 write
     surfaces; an unset key runs the service default-open);
  2. ``FENGARDE_RBAC_DB`` set                        (role-based access ON;
     prod without RBAC is default-open by design choice, so it is a refusal);
  3. admin credential: ``FENGARDE_ADMIN_PASSWORD`` set and NOT a known
     default, OR ``FENGARDE_FIRST_BOOT_FILE`` set (explicit first-boot
     generation into a FILE is allowed);
  4. ``FENGARDE_ADMIN_PASSWORD`` (when provided) must not be a known default
     (admin / password / changeme / fengarde / ... case-insensitive) and
     must meet the user store's length rule;
  5. Redis-backed bus -> ``REDIS_PASSWORD`` set and >= 16 chars; on the plain
     ``redis`` bus the connection uses ``REDIS_URL`` (not ``REDIS_PASSWORD``),
     so the URL must carry the SAME password, else the bus would run
     unauthenticated or fail while the gate said "fine".

First-boot generation (``generate_first_boot_password``) writes a fresh
strong password to ``FENGARDE_FIRST_BOOT_FILE`` with mode 0600 and a header
that says rotate-and-delete. This is the WP-3.2 requirement and is an
EXPLICIT, prod-profile-only exception to the repo's standing rule
(users.py: "the service never stores a plaintext credential"; the earlier
write-to-0600 design was closed as CodeQL py/clear-text-storage in the
DEFAULT path). Rationale, stated plainly: a file keeps the secret OUT of the process
environment, so it is not exposed through ``docker inspect``, orchestrator
manifests, process listings or shell history. It is NOT protection against
other processes of the SAME uid: those can read a 0600 file exactly as they
can read /proc/<pid>/environ. Residual risk: anyone with the service uid (or
root) reads it, and so can a backup of the volume. Mitigate by mounting the
path on a tmpfs / secret mount and DELETING the file right after rotating the
password via the admin API. The file is created atomically (O_CREAT|O_EXCL,
mode 0600 at creation, symlinks refused) and an existing file is never
overwritten. POSIX only: on Windows (where the 0600 mode is not enforced and
prod does not run) generation is refused.
Never log the generated value — only its path.
"""
from __future__ import annotations

import hmac
import os
import secrets
import stat
import sys
from pathlib import Path
from typing import Optional
from urllib.parse import unquote, urlsplit

from shared.log import get_logger

DEFAULT_PASSWORDS = frozenset({
    "", "admin", "password", "changeme", "fengarde", "fengarde2026",
    "admin123", "password123", "changeme123", "secret", "123456", "12345678",
    "administrator", "letmein",
})


# Documented minimums (docs/secure-defaults.md states the same numbers).
API_KEY_MIN = 24
REDIS_PASSWORD_MIN = 16
# Exact documented profile values (case-insensitive); unset/empty is the demo too.
KNOWN_PROFILES = ("prod", "dev", "demo")


def prod_active() -> bool:
    """True when FENGARDE_PROFILE (case-insensitive) is exactly 'prod'."""
    return os.getenv("FENGARDE_PROFILE", "").strip().lower() == "prod"


def profile_problem() -> Optional[str]:
    """Constant message when FENGARDE_PROFILE is set to something undocumented.

    A misspelling must not silently disable the gate. The value is not echoed.
    """
    v = os.getenv("FENGARDE_PROFILE", "").strip().lower()
    if v == "" or v in KNOWN_PROFILES:
        return None
    return ("FENGARDE_PROFILE is set to an unrecognised value; allowed: "
            + ", ".join(KNOWN_PROFILES) + " (or unset). Refusing to start rather "
            "than silently run the insecure demo profile")


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


def _bus_backend() -> str:
    # shared/bus.py::Bus() lowercases BUS_BACKEND, so must this check.
    return os.getenv("BUS_BACKEND", "").strip().lower()


def _redis_problems() -> list[str]:
    """Redis-bus obligations. Messages are constants: no password-derived data."""
    backend = _bus_backend()
    if backend not in ("redis", "redis-sentinel"):
        return []
    problems: list[str] = []
    pw = os.getenv("REDIS_PASSWORD", "")
    if not pw:
        problems.append("REDIS_PASSWORD is not set (Redis bus with no auth)")
    elif len(pw) < REDIS_PASSWORD_MIN:
        problems.append(f"REDIS_PASSWORD is shorter than the {REDIS_PASSWORD_MIN}-character minimum")
    if backend == "redis":
        # bus.py _RedisBus connects with REDIS_URL only; REDIS_PASSWORD is read by the sentinel bus.
        try:
            url_pw = unquote(urlsplit(os.getenv("REDIS_URL", "")).password or "")
        except ValueError:
            url_pw = ""
        if not url_pw:
            problems.append("REDIS_URL carries no password (the plain redis bus authenticates "
                            "with the URL: redis://:<password>@host:6379/0)")
        elif pw and not hmac.compare_digest(url_pw.encode(), pw.encode()):
            problems.append("REDIS_URL's password does not match REDIS_PASSWORD")
    return problems


def _is_windows() -> bool:
    return os.name == "nt"


def _rbac_problems() -> list[str]:
    problems: list[str] = []
    key = os.getenv("FENGARDE_API_KEY")
    if not key:
        problems.append("FENGARDE_API_KEY is not set (API-key auth would be OFF)")
    elif len(key) < API_KEY_MIN:
        problems.append(f"FENGARDE_API_KEY is shorter than the {API_KEY_MIN}-character minimum")
    if not os.getenv("FENGARDE_RBAC_DB"):
        problems.append("FENGARDE_RBAC_DB is not set (role-based access would be OFF)")
    pw = os.getenv("FENGARDE_ADMIN_PASSWORD")
    if not pw:
        # first-boot generation (FENGARDE_FIRST_BOOT_FILE) is ALLOWED at
        # startup: the triage bootstrap generates ONLY when the user store is
        # empty and fails closed otherwise - prodcheck cannot see the store.
        if not os.getenv("FENGARDE_FIRST_BOOT_FILE"):
            problems.append(
                "no admin credential: set FENGARDE_ADMIN_PASSWORD or "
                "FENGARDE_FIRST_BOOT_FILE (prod generates a fresh password into "
                "that file at first boot)")
        elif _is_windows():
            problems.append(
                "FENGARDE_FIRST_BOOT_FILE is POSIX-only (a 0600 file cannot be "
                "enforced on Windows); set FENGARDE_ADMIN_PASSWORD instead")
    else:
        code = admin_password_issue(pw)
        if code:
            problems.append("FENGARDE_ADMIN_PASSWORD " + _PW_REASONS[code])
    return problems


def prod_problems(rbac: bool = True) -> list[str]:
    """Every unsatisfied prod obligation, numbered, in a stable order.

    ``rbac=False`` drops the ws3-only obligations (API key / RBAC DB / admin
    credential) for services with their own auth store (ws6 keystore).
    """
    problems = _rbac_problems() if rbac else []
    return problems + _redis_problems()


def prod_or_die(service: str, rbac: bool = True, extra: tuple = ()) -> None:
    """Refuse to start in prod when any obligation is missing.

    Prints ONE aggregated failure list (numbered, every problem at once —
    an operator fixes the whole list in one pass, not one refusal per boot)
    and exits 1. No-op unless ``FENGARDE_PROFILE=prod``; the zero-config
    demo path is untouched. An UNRECOGNISED non-empty profile also exits 1
    (a typo must not silently disable the gate).
    """
    bad = profile_problem()
    if bad:
        _die(service, "FENGARDE_PROFILE is invalid:", [bad])
    if not prod_active():
        return
    problems = prod_problems(rbac) + list(extra)
    if not problems:
        return
    _die(service, "FENGARDE_PROFILE=prod but the secure surface is incomplete:", problems)


def _die(service: str, head: str, problems: list[str]) -> None:
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
    if _is_windows():
        raise RuntimeError(
            "first-boot password file generation is POSIX-only: the 0600 mode "
            "is not enforced on Windows; set FENGARDE_ADMIN_PASSWORD instead")
    # token_urlsafe(n) is URL-safe base64 of n random bytes (6 bits/char, ~1.33 chars/byte);
    # n = min_chars + 9 gives >= min_chars + 12 chars, of which min_chars + 3 are kept (~138 bit at 20).
    password = secrets.token_urlsafe(min_chars + 9)[:min_chars + 3]
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    header = (
        "# FENGARDE first-boot admin password - FENGARDE_PROFILE=prod\n"
        "# Generated: never logged; rotate it via the admin API after first\n"
        "# login, then DELETE this file (the service user store only ever\n"
        "# holds the scrypt hash).\n"
    )
    # Created atomically with mode 0600 (no umask window), refusing symlinks
    # and refusing to overwrite: O_EXCL doubles as the cross-process lock.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(target, flags, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(header)
        fh.write(password + "\n")
    return password


def discard_first_boot_file(file_env: str = "FENGARDE_FIRST_BOOT_FILE") -> None:
    """Roll back a just-generated file (the admin creation failed after it)."""
    path = os.getenv(file_env)
    if path:
        try:
            os.unlink(path)
        except OSError:
            pass
