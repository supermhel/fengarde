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

import urllib.request


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse every HTTP 30x. Returning None makes urlopen raise HTTPError."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ARG002
        return None  # never follow (per-FIX-4 SSRF hardening)


def _install_no_redirect_opener() -> None:
    urllib.request.install_opener(
        urllib.request.build_opener(_NoRedirectHandler))


_install_no_redirect_opener()


def no_redirect_urlopen(req, timeout=None):
    """Open ``req`` WITHOUT following HTTP redirects (SSRF hardening).

    Args/returns mirror ``urllib.request.urlopen``: pass either a URL string
    or an ``urllib.request.Request``. A HTTP 30x response raises
    ``urllib.error.HTTPError`` instead of being followed.
    """
    return urllib.request.urlopen(req, timeout=timeout)  # noqa: S310
