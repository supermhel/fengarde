"""FENGARDE E3 MFA: stdlib-only Time-based One-Time Password (RFC 6238).

This module is the single place a TOTP secret is turned into a 6-digit code
or an `otpauth://` provisioning URI, and it uses ONLY the Python standard
library (hmac, hashlib, base64, time, struct, os) -- same stdlib-first
convention as the rest of FENGARDE (CLAUDE.md), so enabling MFA adds no
dependency and nothing new to the supply-chain surface.

What it provides:

  * generate_secret()      -> a fresh random base32 secret (160-bit) for
                              provisioning to an authenticator app
  * otpauth_uri(secret, label, issuer) -> the `otpauth://totp/...` URI that
                              a QR code is rendered from
  * generate_code(secret, at=None) -> the current 6-digit TOTP code (used by
                              tests and by `verify_code` internally)
  * verify_code(secret, code, window=1) -> check a submitted code against the
                              current time step with +/-`window` step slack
                              for clock skew between authenticator and server

Protocol (RFC 4226 dynamic-truncation atop HMAC-SHA1, RFC 6238 TOTP with a
30-second step and 6 digits -- the Google-authenticator-compatible default):

    counter = floor(unix_time / 30)
    hs      = HMAC-SHA1(secret, counter_as_8byte_big_endian)
    offset  = hs[-1] & 0x0F
    dbc     = ((hs[offset]<<24 | hs[offset+1]<<16 | hs[offset+2]<<8 | hs[offset+3])
               & 0x7FFFFFFF)            # 31-bit dynamic binary code (RFC 4226)
    code    = zero-pad(dbc % 1_000_000, 6)

Secrets are stored as base32 (standard for TOTP apps; `generate_code` and
`verify_code` tolerate missing/extra padding and case so a key pasted from
any app works).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time

_STEP_SECONDS = 30
_DIGITS = 6
_DEFAULT_KEY_BYTES = 20  # 160 bits, the RFC-recommended TOTP secret size
_DEFAULT_ISSUER = "FENGARDE"


def _normalize_key(secret: str) -> bytes:
    """Decode a base32 secret to raw bytes.

    Tolerates lower-case and missing/extra '=' padding (both are common when
    a user pastes a key that an app or scanner trimmed differently). Raises
    ValueError on a genuinely malformed secret -- the caller decides whether
    that should fail open or closed.
    """
    s = secret.upper().strip().rstrip("=")
    pad = (8 - len(s) % 8) % 8
    return base64.b32decode(s + "=" * pad)


def _code_for_counter(secret: str, counter: int) -> str:
    """The RFC 4226 / RFC 6238 6-digit code for an exact time-step counter."""
    key = _normalize_key(secret)
    hs = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = hs[-1] & 0x0F
    dbc = struct.unpack(">I", hs[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{dbc % (10 ** _DIGITS):0{_DIGITS}d}"


def _counter(at: float | None) -> int:
    return int((time.time() if at is None else at) // _STEP_SECONDS)


def generate_secret(num_bytes: int = _DEFAULT_KEY_BYTES) -> str:
    """A fresh random base32 secret (default 160-bit) for provisioning."""
    return base64.b32encode(os.urandom(num_bytes)).decode("ascii").rstrip("=")


def generate_code(secret: str, at: float | None = None) -> str:
    """The current (or, for tests, an exact-`at`) 6-digit TOTP code."""
    return _code_for_counter(secret, _counter(at))


def verify_code(secret: str, code, window: int = 1, at: float | None = None) -> bool:
    """True if `code` is a valid TOTP for `secret` within +/-`window` steps.

    ``window`` defaults to 1, i.e. current step plus the immediately
    preceding and following steps -- enough slack for a moderately drifted
    client clock while keeping the brute-force surface tiny (3 possible
    codes instead of an unbounded set). Comparisons are constant-time
    (hmac.compare_digest). Any non-6-digit non-numeric input fails closed to
    False, never raises.
    """
    if not isinstance(code, str):
        return False
    if len(code) != _DIGITS or not code.isdigit():
        return False
    base_counter = _counter(at)
    for offset in range(-window, window + 1):
        if hmac.compare_digest(_code_for_counter(secret, base_counter + offset), code):
            return True
    return False


def otpauth_uri(secret: str, label: str, issuer: str = _DEFAULT_ISSUER) -> str:
    """The `otpauth://totp/...` provisioning URI for a QR code.

    ``label`` is the account name (typically the username); ``issuer`` the
    service name shown in the authenticator app. Both are percent-encoded so
    a username containing ':' or '?' (allowed in the user store) cannot
    corrupt the URI.
    """
    from urllib.parse import quote

    params = (
        f"secret={quote(secret)}"
        f"&issuer={quote(issuer)}"
        "&algorithm=SHA1&digits=6&period=30"
    )
    qualifier = f"{issuer}:{label}" if issuer else label
    return f"otpauth://totp/{quote(qualifier)}?{params}"
