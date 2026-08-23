"""MFA/TOTP end-to-end over REAL HTTP against the deployed handler -- LIVE.

Closes the gap SSOT.md §2 records against the 2026-08-06 hardening row (item d):
"MFA/TOTP is opt-in per-user and login gates on `totp_code` when active --
flow tested zero-infra, not a live browser/login e2e."

Running it live for the first time (2026-08-11) immediately found a real
production defect that every zero-infra test passed straight through:
`shared/users.py` reached the TOTP primitive by walking
`parent.parent / "ws6-inventory"`, which resolves in a source checkout but NOT
in the ws3-indexer image (that image copies `services/shared`, never
`ws6-inventory`). The import failed, the `except` silently set
`_TOTP_AVAILABLE = False`, and in the shipped container `provision_totp()`
raised while `verify_totp()` rejected EVERY code -- MFA inert in production,
green in CI. Fixed by moving the primitive to `services/shared/mfa.py`.

That is exactly why this test exists and why it drives real HTTP against a
handler built the way the service builds it, rather than importing the pieces
and calling them directly: the defect lived in module resolution under the
deployed layout, which no in-process test could see.

The flow asserted, in order:
  1.  login with password only            -> 200 (TOTP not yet active)
  2.  POST /auth/mfa/enable with reauth   -> 200 + otpauth:// URI
  3.  POST /auth/mfa/verify with a code   -> 200, secret becomes ACTIVE
  4.  login with password only            -> 401 (the gate is now closed)
  5.  login with password + WRONG code    -> 401
  6.  login with password + correct code  -> 200

Steps 4 and 5 are the load-bearing ones. Step 6 alone would pass against a
build where MFA is not enforced at all -- which is precisely the state the bug
above left production in.

Run inside the ws3-indexer container (it needs the deployed module layout):

    docker cp services/ws3-indexer/test_mfa_live_e2e.py infra-ws3-indexer-1:/tmp/
    docker exec infra-ws3-indexer-1 python /tmp/test_mfa_live_e2e.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
for _p in (str(HERE), str(HERE.parent), "/app", "/app/ws3-indexer", "/app/shared"):
    if _p not in sys.path and Path(_p).exists():
        sys.path.insert(0, _p)

FAILS: list[str] = []
_PORT = int(os.getenv("MFA_E2E_PORT", "8099"))
_PASSWORD = "e2e-test-password-not-a-real-credential"


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _post(path: str, body: dict, cookie: str | None = None,
          csrf: str | None = None):
    """(status, json_body, set_cookie). Never raises on a 4xx -- the negative
    assertions below are ABOUT 4xx responses, so an exception would turn the
    interesting cases into errors instead of results.

    `csrf` is required for authenticated writes: in RBAC mode the handler
    rejects a state-changing POST with 403 unless the session's `csrf_token`
    (handed out in the /auth/login response BODY, deliberately not a cookie)
    comes back as an `X-CSRF-Token` header. Omitting it made /auth/mfa/enable
    return 403 with an empty body on the first run of this test.
    """
    req = urllib.request.Request(
        f"http://127.0.0.1:{_PORT}{path}",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST")
    if cookie:
        req.add_header("Cookie", cookie)
    if csrf:
        req.add_header("X-CSRF-Token", csrf)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, json.loads(raw or "{}"), resp.headers.get("Set-Cookie")
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            parsed = json.loads(raw or "{}")
        except ValueError:
            parsed = {"raw": raw}
        return exc.code, parsed, exc.headers.get("Set-Cookie")


def main() -> int:
    try:
        from shared.users import _TOTP_AVAILABLE
        import mfa
    except Exception as exc:  # noqa: BLE001
        print(f"[FAIL] MFA e2e: could not import the TOTP primitive at all "
              f"({type(exc).__name__}: {exc}). In the deployed image this is the "
              f"exact defect this test exists to catch -- not a skip.")
        return 1

    # Deliberately a FAILURE, not a SKIP. "TOTP unavailable" is the production
    # bug this test was written for; skipping on it would restore the silence
    # that hid it in the first place.
    if not _TOTP_AVAILABLE:
        print("[FAIL] MFA e2e: _TOTP_AVAILABLE is False -- the TOTP primitive is "
              "not importable under this deployment layout, so MFA is inert here "
              "even though password auth still works.")
        return 1

    import triage_api
    from storage.memory import MemoryStore

    db_path = str(Path(tempfile.mkdtemp(prefix="mfa-e2e-")) / "users.db")
    os.environ["FENGARDE_RBAC_DB"] = db_path
    os.environ["FENGARDE_ADMIN_PASSWORD"] = _PASSWORD

    server = threading.Thread(
        target=triage_api.serve,
        args=(MemoryStore(),),
        kwargs={"host": "127.0.0.1", "port": _PORT},
        daemon=True)
    server.start()

    for _ in range(50):  # wait for the listener rather than sleeping blindly
        time.sleep(0.1)
        try:
            status, _, _ = _post("/auth/login", {"username": "admin",
                                                 "password": "wrong"})
            if status in (401, 200):
                break
        except Exception:  # noqa: BLE001 - not up yet
            continue
    else:
        print("[FAIL] MFA e2e: triage_api never started listening.")
        return 1

    user = "admin"

    # 1. Password-only login works before MFA is activated (the control: if
    #    this fails, every later 401 is meaningless).
    status, body, set_cookie = _post("/auth/login",
                                     {"username": user, "password": _PASSWORD})
    check(status == 200, f"step 1: password-only login before MFA returned "
                         f"{status} {body} -- expected 200")
    if status != 200 or not set_cookie:
        print(f"[FAIL] MFA e2e: {FAILS[-1] if FAILS else 'no session cookie issued'}")
        return 1
    cookie = set_cookie.split(";")[0]
    csrf = body.get("csrf_token")
    check(isinstance(csrf, str) and csrf,
          "step 1: login response carried no csrf_token -- every write below "
          "would 403 for a reason unrelated to MFA")

    # 2. Provision (step one of two). Requires the acting user's password.
    status, body, _ = _post("/auth/mfa/enable",
                            {"password": _PASSWORD}, cookie=cookie, csrf=csrf)
    check(status == 200, f"step 2: /auth/mfa/enable returned {status} {body} "
                         f"-- expected 200 with an otpauth:// URI")
    uri = body.get("otpauth_uri", "")
    check(uri.startswith("otpauth://totp/"),
          f"step 2: expected an otpauth:// provisioning URI, got {uri!r} "
          f"(status {status}, body {body})")
    if not uri.startswith("otpauth://totp/"):
        print(f"[FAIL] MFA e2e: {FAILS[-1]}")
        return 1
    secret = uri.split("secret=")[1].split("&")[0]

    # 3. Confirm a real code (step two) -> secret becomes ACTIVE.
    status, body, _ = _post("/auth/mfa/verify",
                            {"password": _PASSWORD,
                             "totp_code": mfa.generate_code(secret)},
                            cookie=cookie, csrf=csrf)
    check(status == 200, f"step 3: /auth/mfa/verify returned {status} {body} "
                         f"-- expected 200 activating the secret")

    # 4. THE GATE. Password alone must now be refused.
    status, body, _ = _post("/auth/login",
                            {"username": user, "password": _PASSWORD})
    check(status == 401,
          f"step 4: password-only login returned {status} AFTER MFA was "
          f"activated -- the TOTP gate is NOT enforced, which is the whole "
          f"point of the feature")

    # 5. A wrong code must be refused, and indistinguishably from a wrong
    #    password (no new oracle -- see the login route's own comment).
    status, body, _ = _post("/auth/login",
                            {"username": user, "password": _PASSWORD,
                             "totp_code": "000000"})
    check(status == 401,
          f"step 5: login with a WRONG totp_code returned {status} -- expected 401")
    check(body.get("error") == "invalid credentials",
          f"step 5: wrong-code error was {body.get('error')!r}; it must be "
          f"identical to the wrong-password error so it is not an oracle")

    # 6. Password + correct code succeeds. A DIFFERENT step's code than the
    # one step 3 already consumed (2026-08-23 TOTP replay-protection fix,
    # shared/users.py::verify_totp tracks last-accepted-counter per account
    # -- reusing step 3's exact code here now correctly 401s, same as a
    # real captured code could never be replayed twice). +30s is still
    # within the server's real-time +/-1-step acceptance window since this
    # whole e2e runs in well under 30s.
    status, body, set_cookie = _post("/auth/login",
                                     {"username": user, "password": _PASSWORD,
                                      "totp_code": mfa.generate_code(secret, at=time.time() + 30)})
    check(status == 200,
          f"step 6: login with a VALID totp_code returned {status} {body} "
          f"-- expected 200")

    if FAILS:
        print(f"[FAIL] MFA/TOTP live e2e: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        return 1
    print("[OK] MFA/TOTP live e2e PASS -- real HTTP against the deployed "
          "handler: provision -> verify activates, password-only login is then "
          "REFUSED, a wrong code is refused indistinguishably from a wrong "
          "password, and password + valid code succeeds")
    return 0


if __name__ == "__main__":
    sys.exit(main())
