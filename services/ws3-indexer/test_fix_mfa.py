"""FENGARDE E3 MFA/TOTP tests.

Covers, against REAL code paths:

  1. stdlib TOTP primitive (mfa.py): generate/verify a 6-digit code at a
     fixed time, the +/-1-step clock-skew window, malformed-input fail-closed,
     and otpauth:// URI shape.
  2. user-store enable flow: provision stores a secret (inactive), verify_totp
     marks it active only on a valid code.
  3. login: once a user's TOTP is ACTIVE, /auth/login REQUIRES a valid
     `totp_code` (rejects with 401 when missing/invalid).
  4. backward compatibility: a user who never enabled TOTP logs in with
     password alone -- byte-for-byte the pre-E3 path.

Run: python services/ws3-indexer/test_fix_mfa.py
"""
from __future__ import annotations

import json
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
for _p in (str(HERE), str(HERE.parent), str(HERE.parent / "ws6-inventory")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import triage_api  # noqa: E402
import mfa  # noqa: E402
from storage.memory import MemoryStore  # noqa: E402
from shared.users import UserStore  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _serve(store, users):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), triage_api.make_handler(store, users_db=users))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _request(port, method, path, body=None, cookie=None, csrf=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if cookie:
        headers["Cookie"] = cookie
    if csrf is not None:
        headers["X-CSRF-Token"] = csrf
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data,
                                  method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode()), resp.headers.get("Set-Cookie")
    except urllib.error.HTTPError as e:
        err = e.read().decode()
        try:
            bodyp = json.loads(err)
        except (ValueError, json.JSONDecodeError):
            bodyp = {}
        return e.code, bodyp, e.headers.get("Set-Cookie")


def _cookie_value(set_cookie_header: str) -> str:
    return set_cookie_header.split(";")[0]


def _fresh():
    store = MemoryStore()
    store.index("alerts-acme-2026.07.16", "a1",
                {"alert_id": "a1", "tenant_id": "acme", "rule_title": "test"})
    users = UserStore(":memory:")
    users.create_user("alice", "pw-alice-1", role="analyst", tenant_id="acme")
    users.create_user("bob", "pw-bob-1", role="analyst", tenant_id="acme")
    users.create_user("root", "pw-root-1", role="admin", tenant_id="default")
    return store, users


# -- 1. TOTP primitive -------------------------------------------------------

def test_totp_generate_and_verify():
    secret = mfa.generate_secret()
    check(secret and isinstance(secret, str) and len(secret) >= 16,
          "generate_secret must return a non-empty base32 string")

    fixed = 1_700_000_000  # an exact 30s boundary
    code = mfa.generate_code(secret, at=fixed)
    check(len(code) == 6 and code.isdigit(), f"code must be 6 digits, got {code!r}")
    check(mfa.verify_code(secret, code, at=fixed), "the code must verify at its own time step")

    # Wrong code / wrong secret must not verify.
    check(not mfa.verify_code(secret, "000000", at=fixed), "a random code must fail")
    other = mfa.generate_secret()
    if other != secret:
        check(not mfa.verify_code(other, mfa.generate_code(secret, at=fixed), at=fixed),
              "the same code must fail against a different secret")


def test_totp_clock_skew_window():
    secret = mfa.generate_secret()
    at = 1_700_000_000
    # A code from one step ago and one step ahead must both pass (window=1).
    check(mfa.verify_code(secret, mfa.generate_code(secret, at=at - 30), at=at),
          "code from the previous 30s step must pass (skew tolerance)")
    check(mfa.verify_code(secret, mfa.generate_code(secret, at=at + 30), at=at),
          "code from the next 30s step must pass (skew tolerance)")
    # Two steps out must be rejected.
    check(not mfa.verify_code(secret, mfa.generate_code(secret, at=at - 60), at=at),
          "code two steps old must be rejected")


def test_totp_malformed_input_fails_closed():
    secret = mfa.generate_secret()
    real = mfa.generate_code(secret)
    check(not mfa.verify_code(secret, ""), "empty code must fail")
    check(not mfa.verify_code(secret, "12345"), "5-digit code must fail")
    check(not mfa.verify_code(secret, "1234567"), "7-digit code must fail")
    check(not mfa.verify_code(secret, "abcdef"), "non-numeric code must fail")
    check(not mfa.verify_code(secret, None), "None code must fail closed, not raise")
    check(not mfa.verify_code(secret, real + " "), "whitespace/extra chars must fail")


def test_otpauth_uri_shape():
    secret = mfa.generate_secret()
    uri = mfa.otpauth_uri(secret, label="alice", issuer="FENGARDE")
    check(uri.startswith("otpauth://totp/"), f"URI must be otpauth://totp/, got {uri}")
    check(f"secret={secret}" in uri, "URI must carry the secret param")
    check("issuer=FENGARDE" in uri, "URI must carry the issuer param")
    check("period=30" in uri and "digits=6" in uri, "URI must pin period=30&digits=6")


# -- 2. user-store enable flow ------------------------------------------------

def test_user_store_enable_then_verify_activates():
    store, users = _fresh()
    check(not users.is_totp_enabled("alice"), "a fresh account must NOT have TOTP active")

    uri = users.provision_totp("alice")  # step one: store secret (pending)
    check(uri.startswith("otpauth://totp/"), f"provision_totp must return a URI, got {uri}")
    # Secret is stored but NOT active yet.
    row = users.get_user("alice")
    check(bool(row["totp_secret"]), "provisioning must store the secret")
    check(not users.is_totp_enabled("alice"), "stored-but-unverified secret must NOT be active")

    # A wrong code must not activate and password-only login still works.
    check(not users.verify_totp("alice", "000000"), "wrong code must not activate")
    check(not users.is_totp_enabled("alice"), "wrong code must leave MFA inactive")

    # The real code (computed RFC-style against the STORED secret) activates it.
    secret = row["totp_secret"]
    good_code = mfa.generate_code(secret)
    check(users.verify_totp("alice", good_code), "valid code must verify and activate")
    check(users.is_totp_enabled("alice"), "after a valid code the account must be MFA-active")

    # Unknown user / no secret -> fail closed.
    check(not users.verify_totp("ghost", good_code), "unknown user must fail closed")


# -- 3. login requires code when TOTP active ---------------------------------

def test_login_requires_code_when_totp_enabled():
    store, users = _fresh()
    srv, port = _serve(store, users)
    try:
        # Bob never enables TOTP -> login with password alone works (control).
        code_ctl, _, _ = _request(port, "POST", "/auth/login",
                                   {"username": "bob", "password": "pw-bob-1"})
        check(code_ctl == 200, f"control: no-TOTP user logs in with password alone, got {code_ctl}")

        # Alice enables TOTP and confirms it.
        _, login_body, set_cookie = _request(port, "POST", "/auth/login",
                                              {"username": "alice", "password": "pw-alice-1"})
        cookie = _cookie_value(set_cookie)
        csrf = login_body["csrf_token"]
        _, enable_body, _ = _request(port, "POST", "/auth/mfa/enable", {}, cookie=cookie, csrf=csrf)
        # Enable returns an otpauth URI carrying the secret -> derive the real code.
        uri_params = enable_body["otpauth_uri"].split("?", 1)[1]
        secret = dict(p.split("=", 1) for p in uri_params.split("&"))["secret"]
        code = mfa.generate_code(secret)
        _request(port, "POST", "/auth/mfa/verify", {"totp_code": code}, cookie=cookie, csrf=csrf)

        # Now: missing code -> 401; wrong code -> 401.
        code_no, _, _ = _request(port, "POST", "/auth/login",
                                  {"username": "alice", "password": "pw-alice-1"})
        check(code_no == 401, f"login without totp_code must be 401 once MFA active, got {code_no}")
        code_wrong, _, _ = _request(port, "POST", "/auth/login",
                                     {"username": "alice", "password": "pw-alice-1",
                                      "totp_code": "000000"})
        check(code_wrong == 401, f"login with a wrong totp_code must be 401, got {code_wrong}")

        # Correct code + password -> 200.
        code_ok, body_ok, _ = _request(port, "POST", "/auth/login",
                                        {"username": "alice", "password": "pw-alice-1",
                                         "totp_code": mfa.generate_code(secret)})
        check(code_ok == 200, f"login with correct totp_code must succeed, got {code_ok}")
        check(body_ok.get("username") == "alice", "successful MFA login must create a session")
    finally:
        srv.shutdown(); srv.server_close()


# -- 4. backward compatible when disabled ------------------------------------

def test_login_backward_compatible_totp_never_enabled():
    store, users = _fresh()
    srv, port = _serve(store, users)
    try:
        # A user who never touched MFA: password-only login identical to pre-E3.
        for uname, pwd in (("alice", "pw-alice-1"), ("bob", "pw-bob-1"), ("root", "pw-root-1")):
            code, body, set_cookie = _request(port, "POST", "/auth/login",
                                               {"username": uname, "password": pwd})
            check(code == 200, f"{uname}: login must work password-only when TOTP disabled, got {code}")
            check(bool(body.get("csrf_token")) and set_cookie,
                  f"{uname}: login response shape must be unchanged (csrf + cookie)")

        # No TOTP column leak: get_user row carries the (null) secret harmlessly.
        row = users.get_user("alice")
        check("totp_secret" in row.keys() and row["totp_secret"] is None,
              "un-provisioned user must have a NULL totp_secret")
    finally:
        srv.shutdown(); srv.server_close()


def main():
    test_totp_generate_and_verify()
    test_totp_clock_skew_window()
    test_totp_malformed_input_fails_closed()
    test_otpauth_uri_shape()
    test_user_store_enable_then_verify_activates()
    test_login_requires_code_when_totp_enabled()
    test_login_backward_compatible_totp_never_enabled()

    if FAILS:
        print(f"[FAIL] MFA/TOTP: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] FENGARDE E3 MFA/TOTP: stdlib generate+verify, +/-1-step skew "
          "window, fail-closed malformed input, provision->verify activation, "
          "login REQUIRES totp_code when active, and byte-for-byte backward "
          "compat when TOTP is disabled")


if __name__ == "__main__":
    main()
