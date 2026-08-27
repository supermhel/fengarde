"""R3-#58 / R3-#65 (2026-08-27): SSRF guard at CALL time + opener state pin.

* `safe_urlopen` applies webhooks.py's config-load SSRF guard (`scheme must
  be http(s)` + `is_unsafe_target_url`) at OPEN time, so a target that
  arrives via env/config at runtime (e.g. reporting.py's
  FENGARDE_SEC_REPORT_URL) is rejected before any request is made.
* `install_opener` at import is process-global and reversible: the test
  pins what the import installed (a no-redirect opener) and proves
  `restore_default_opener()` puts the pre-import opener back.

Run: python services/shared/test_outbound_http.py
"""
from __future__ import annotations

import sys
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(SERVICES))

import shared.outbound_http as oh  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


# -- R3-#58: safe_urlopen --------------------------------------------------

def test_safe_urlopen_rejects_unsafe_targets():
    for bad in (
        "http://127.0.0.1:9200/secret",        # loopback
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata
        "file:///etc/passwd",                    # non-http scheme
        "ftp://example.com/x",                   # non-http scheme
        "http://[::1]/secret",                   # IPv6 loopback
    ):
        try:
            result = (_r for _r in [oh.safe_urlopen(bad, timeout=1)])
            next(result)
            check(False, f"safe_urlopen must reject {bad!r}")
        except urllib.error.URLError:
            check(True, "")


def test_safe_urlopen_opens_a_safe_target():
    """Positive wiring: with the guard stubbed to allow, safe_urlopen must
    forward to urlopen with the timeout, proving the guard+open pipeline."""
    calls = []

    def fake_urlopen(req, timeout=None):
        calls.append((req, timeout))
        return "opened"

    old_urlopen = urllib.request.urlopen
    old_guard = oh.is_unsafe_target_url
    urllib.request.urlopen = fake_urlopen
    oh.is_unsafe_target_url = lambda url: False  # guard itself tested above
    try:
        result = oh.safe_urlopen("http://example.com/x", timeout=3)
        check(result == "opened",
              f"safe_urlopen must open a safe target, got {result!r}")
        check(calls and calls[0][1] == 3,
              "timeout must be forwarded through to urlopen")
    finally:
        urllib.request.urlopen = old_urlopen
        oh.is_unsafe_target_url = old_guard


# -- R3-#65: opener install is pinned + reversible --------------------------

def _redirect_handler_types():
    opener = urllib.request._opener
    if not opener:
        return []
    return [type(h) for h in opener.handlers
            if isinstance(h, urllib.request.HTTPRedirectHandler)]


def test_no_redirect_opener_installed_at_import():
    opener = urllib.request._opener
    check(opener is not None, "importing shared.outbound_http must install an opener")
    check(_redirect_handler_types() == [oh._NoRedirectHandler],
          f"the installed opener must refuse redirects, got {_redirect_handler_types()}")


def test_restore_default_opener_reverts():
    oh.restore_default_opener()
    restored = urllib.request._opener
    check(restored is oh._ORIGINAL_OPENER,
          "restore_default_opener() must re-install the pre-import opener")
    if restored is not None:
        check(_redirect_handler_types() != [oh._NoRedirectHandler],
              "the restored opener must follow redirects again (default "
              "HTTPRedirectHandler), not the no-redirect one")
    # put the no-redirect state back for the rest of the process
    oh._install_no_redirect_opener()
    check(_redirect_handler_types() == [oh._NoRedirectHandler],
          "re-installing the no-redirect opener after restore must work")


def main():
    test_safe_urlopen_rejects_unsafe_targets()
    test_safe_urlopen_opens_a_safe_target()
    test_no_redirect_opener_installed_at_import()
    test_restore_default_opener_reverts()

    if FAILS:
        print(f"[FAIL] outbound_http: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] R3-#58 safe_urlopen SSRF guard rejects unsafe/internal targets and "
          "non-http schemes at call time; R3-#65 opener state pinned + restorable")


if __name__ == "__main__":
    main()
