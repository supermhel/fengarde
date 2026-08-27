"""Shared outbound-HTTP hardening (FIX 4, SSRF): never follow redirects.

``urllib.request.urlopen()`` follows HTTP 30x redirects by default. A
compromised webhook receiver, report backend, or LLM endpoint could use
that to pivot an HMAC-signed or otherwise authenticated POST to an
internal host (metadata service, Elasticsearch, Redis, ...).

This module makes redirect-following opt-out for the whole process:

* At import time the standard urllib opener is replaced with a
  no-redirect opener (``HTTPRedirectHandler.redirect_request -> None``), so
  every ``urllib.request.urlopen`` call in the importing process stops
  following redirects. A 30x now surfaces as ``urllib.error.HTTPError`` --
  exactly like any other non-2xx -- so callers' existing ``except`` blocks
  keep their error/exception semantics unchanged.
* ``no_redirect_urlopen(req, timeout=None)`` is the explicit call-site
  helper (used by webhooks.py, reporting.py and llm_adapter.py). It
  delegates to ``urllib.request.urlopen``, which still honors
  ``mock.patch("urllib.request.urlopen", ...)`` in unit tests while using
  the no-redirect opener for real network calls.
"""
from __future__ import annotations

import ipaddress
import socket
import urllib.error
import urllib.parse
import urllib.request


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse every HTTP 30x. Returning None makes urlopen raise HTTPError."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ARG002
        return None  # never follow (per-FIX-4 SSRF hardening)


# R3-#65 (2026-08-27): install_opener is PROCESS-GLOBAL and reversible -- keep
# the pre-import opener so the no-redirect install can be exactly undone (and
# so a test can pin what the import installed). ``urllib.request._opener`` is
# None before the first urlopen, at which point urlopen lazily builds the
# default (redirect-following) opener -- so "restore the original" means
# re-install that same value, None included.
_ORIGINAL_OPENER = getattr(urllib.request, "_opener", None)


def _install_no_redirect_opener() -> None:
    urllib.request.install_opener(
        urllib.request.build_opener(_NoRedirectHandler))


def restore_default_opener() -> None:
    """Re-install the process's pre-import urllib opener, undoing the
    no-redirect install (R3-#65). Tests use this to restore state; a process
    that genuinely wants default redirect-following back can call it too."""
    urllib.request.install_opener(_ORIGINAL_OPENER)


_install_no_redirect_opener()


def no_redirect_urlopen(req, timeout=None):
    """Open ``req`` WITHOUT following HTTP redirects (SSRF hardening).

    Args/returns mirror ``urllib.request.urlopen``: pass either a URL string
    or an ``urllib.request.Request``. A HTTP 30x response raises
    ``urllib.error.HTTPError`` instead of being followed.
    """
    return urllib.request.urlopen(req, timeout=timeout)  # noqa: S310


def safe_urlopen(url, timeout=None):
    """SSRF-guarded outbound POST/GET for CALL-time targets (R3-#58).

    webhooks.py applies ``is_unsafe_target_url`` at config-load time, where
    the URL comes from a file it can reject and skip. A target that arrives
    via env/config at runtime -- e.g. reporting.py's
    ``FENGARDE_SEC_REPORT_URL`` -- has no file to reject at load, so the same
    guard must be applied at open time. This wraps that guard around
    ``no_redirect_urlopen``: the scheme must be http(s), and the host must not
    resolve to a private/loopback/link-local address, or it raises
    ``urllib.error.URLError`` (the same exception family urlopen raises for
    connection failures), so a caller's existing ``except (URLError, ...)``
    block keeps working unchanged (fail closed, never silently coerced).
    """
    if not isinstance(url, str):
        url = getattr(url, "full_url", None) or str(url)
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme not in ("http", "https"):
        raise urllib.error.URLError(
            f"refusing non-http(s) outbound target scheme {scheme!r}")
    if is_unsafe_target_url(url):
        raise urllib.error.URLError(
            f"refusing unsafe/internal outbound target {url!r}")
    return no_redirect_urlopen(url, timeout=timeout)


def is_unsafe_target_url(url: str) -> bool:
    """True if ``url``'s host resolves to a private/loopback/link-local
    address -- a scheme check alone (``http(s)://``) never rejects
    ``http://169.254.169.254/...`` or ``http://redis:6379/...``, both valid
    http URLs. Used at CONFIG-LOAD time for operator-authored outbound
    targets (webhooks.py's ``contracts/webhooks/*.yml``) where the trust
    model is "an operator with filesystem access chose this URL", same as
    the rule-plugin trust note in ws4-detection/plugins.py -- this is
    defense-in-depth, not a substitute for trusting that config source.

    Best-effort: a static resolve at load time can't catch DNS rebinding
    (a name that resolves safely now and to a private IP later); pair with
    network-level egress controls for a stronger guarantee. Any failure
    (malformed URL, DNS failure) is treated as unsafe -- fail closed, same
    posture as ``shared.envelope``'s tenant-id validation.
    """
    try:
        host = urllib.parse.urlsplit(url).hostname
        if not host:
            return True
        try:
            addr = ipaddress.ip_address(host)
            addrs = [addr]
        except ValueError:
            infos = socket.getaddrinfo(host, None)
            addrs = [ipaddress.ip_address(info[4][0]) for info in infos]
        return any(a.is_private or a.is_loopback or a.is_link_local
                   or a.is_reserved or a.is_multicast or a.is_unspecified
                   for a in addrs)
    except Exception:
        return True
