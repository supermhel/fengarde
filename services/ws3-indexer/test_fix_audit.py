"""E1 audit-log enhancement tests: audit entries recorded on login/triage/
report, /audit is admin-scoped, the log is append-only, and the capacity cap
trims the oldest entries to bound file growth.

Mirrors the ws3 test discipline: standalone script run with
`python services/ws3-indexer/test_fix_audit.py`, check()/FAILS pattern,
zero infra (MemoryStore + a real ThreadingHTTPServer on an ephemeral port).
The RBAC half reuses the M4.2 harness from test_rbac_api.py.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from storage.memory import MemoryStore  # noqa: E402
from shared.users import UserStore  # noqa: E402
import triage_api  # noqa: E402
import audit as audit_mod  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _serve(store, users_db=None, audit_log=None):
    srv = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        triage_api.make_handler(store, users_db=users_db, audit_log=audit_log))
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
            set_cookie = resp.headers.get("Set-Cookie")
            return resp.status, json.loads(resp.read().decode()), set_cookie
    except urllib.error.HTTPError as e:
        set_cookie = e.headers.get("Set-Cookie")
        return e.code, json.loads(e.read().decode()), set_cookie


def _cookie_value(set_cookie_header: str) -> str:
    return set_cookie_header.split(";")[0]


def _make_store_and_users():
    store = MemoryStore()
    store.index("alerts-acme-2026.07.16", "a1",
                {"alert_id": "a1", "tenant_id": "acme", "rule_title": "test rule"})
    users = UserStore(":memory:")
    users.create_user("acme_analyst", "pw-acme-1", role="analyst", tenant_id="acme")
    users.create_user("acme_readonly", "pw-acme-2", role="read_only", tenant_id="acme")
    users.create_user("admin_user", "pw-admin-1", role="admin", tenant_id="default")
    return store, users


def _login(port, username, password):
    return _request(port, "POST", "/auth/login", {"username": username, "password": password})


# ---- 1. entries recorded on login + triage + report ---------------------

def test_events_recorded():
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "audit.jsonl")
        log = audit_mod.AuditLog(path=path)
        store, users = _make_store_and_users()
        srv, port = _serve(store, users, log)
        try:
            # login success
            _, login_body, set_cookie = _login(port, "acme_analyst", "pw-acme-1")
            cookie = _cookie_value(set_cookie)
            csrf = login_body["csrf_token"]
            # triage status change (a write event)
            code, _, _ = _request(port, "POST", "/alerts/a1/triage",
                                  {"status": "triaged"}, cookie=cookie, csrf=csrf)
            check(code == 200, f"triage write should 200, got {code}")
            # report generation (a write event)
            code_r, _, _ = _request(port, "POST", "/alerts/a1/report", cookie=cookie, csrf=csrf)
            check(code_r == 200, f"report generation should 200, got {code_r}")

            events = [e["event"] for e in log.recent()]
            check("login_success" in events, f"login_success must be audited, got {events}")
            check("triage_update" in events, f"triage_update must be audited, got {events}")
            check("report_generated" in events, f"report_generated must be audited, got {events}")

            login_entry = next(e for e in log.recent() if e["event"] == "login_success")
            check(login_entry.get("actor") == "acme_analyst",
                  f"login_success actor must be the username, got {login_entry.get('actor')!r}")
            check(login_entry.get("tenant_id") == "acme",
                  "login_success must carry the tenant_id")

            triage_entry = next(e for e in log.recent() if e["event"] == "triage_update")
            check(triage_entry.get("actor") == "acme_analyst",
                  f"triage_update actor must be the analyst, got {triage_entry.get('actor')!r}")
            check(triage_entry.get("detail", {}).get("alert_id") == "a1",
                  "triage_update detail must identify the alert")
            check(triage_entry.get("detail", {}).get("status") == "triaged",
                  "triage_update detail must record the new status")

            report_entry = next(e for e in log.recent() if e["event"] == "report_generated")
            check(report_entry.get("actor") == "acme_analyst",
                  f"report_generated actor must be the analyst, got {report_entry.get('actor')!r}")
            check(bool(report_entry.get("detail", {}).get("report_id")),
                  "report_generated detail must carry the report_id")

            # login FAILURE must also be audited
            code_bad, _, _ = _login(port, "acme_analyst", "wrong-password")
            check(code_bad == 401, f"wrong password must be 401, got {code_bad}")
            fail_events = [e["event"] for e in log.recent()]
            check("login_failure" in fail_events,
                  f"login_failure must be audited, got {fail_events}")

            # every entry carries the required schema keys
            for e in log.recent():
                check(isinstance(e.get("ts"), str) and e.get("ts"),
                      "each entry must carry a non-empty ts")
                check(isinstance(e.get("actor"), str) and e.get("actor"),
                      "each entry must carry a non-empty actor")
                check("detail" in e and isinstance(e.get("detail"), dict),
                      "each entry's detail must be a dict")

            # fail-open: an audit outage must NOT break a triage write --
            # point the logger at an unusable path and confirm the request
            # still succeeds with no exception surfaced.
            bad_log = audit_mod.AuditLog(path=os.path.join(td, "no_such_dir", "audit.jsonl"))
            store2, users2 = _make_store_and_users()
            srv2, port2 = _serve(store2, users2, bad_log)
            try:
                _, lb, sc = _login(port2, "acme_analyst", "pw-acme-1")
                c2 = _cookie_value(sc)
                code_ok, _, _ = _request(port2, "POST", "/alerts/a1/triage",
                                         {"status": "closed"}, cookie=c2, csrf=lb["csrf_token"])
                check(code_ok == 200,
                      f"triage write must succeed even when auditing fails, got {code_ok}")
            finally:
                srv2.shutdown(); srv2.server_close()
        finally:
            srv.shutdown(); srv.server_close()


# ---- 2. /audit is admin-scoped ------------------------------------------

def test_audit_route_admin_scoped():
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "audit.jsonl")
        log = audit_mod.AuditLog(path=path)
        log.record("login_success", actor="seed", tenant_id="acme", detail={"seed": True})

        store, users = _make_store_and_users()
        srv, port = _serve(store, users, log)
        try:
            # admin can read /audit
            _, _, sc = _login(port, "admin_user", "pw-admin-1")
            code_admin, body_admin, _ = _request(port, "GET", "/audit", cookie=_cookie_value(sc))
            check(code_admin == 200, f"admin GET /audit should 200, got {code_admin}")
            check(isinstance(body_admin.get("entries"), list) and body_admin["count"] > 0,
                  "admin GET /audit must return audit entries")
            check("login_success" in [e["event"] for e in body_admin["entries"]],
                  "/audit must include the seeded audit entry")

            # analyst (>= read_only, < admin) is denied
            _, lb_an, sc_an = _login(port, "acme_analyst", "pw-acme-1")
            code_an, _, _ = _request(port, "GET", "/audit", cookie=_cookie_value(sc_an),
                                     csrf=lb_an["csrf_token"])
            check(code_an in (403, 404), f"non-admin GET /audit must be denied, got {code_an}")

            # read_only is denied
            _, _, sc_ro = _login(port, "acme_readonly", "pw-acme-2")
            code_ro, _, _ = _request(port, "GET", "/audit", cookie=_cookie_value(sc_ro))
            check(code_ro in (403, 404), f"read_only GET /audit must be denied, got {code_ro}")

            # no session at all is denied
            code_none, _, _ = _request(port, "GET", "/audit")
            check(code_none in (401, 403, 404),
                  f"unauthenticated GET /audit must be denied, got {code_none}")
        finally:
            srv.shutdown(); srv.server_close()


def test_audit_route_available_when_rbac_off():
    """RBAC off -> the shared API key is the deployment owner, so /audit is
    visible to the documented authenticated caller."""
    with tempfile.TemporaryDirectory() as td:
        log = audit_mod.AuditLog(path=os.path.join(td, "audit.jsonl"))
        log.record("report_generated", actor="api_key", detail={"n": 1})
        store = MemoryStore()
        srv, port = _serve(store, users_db=None, audit_log=log)
        try:
            code, body, _ = _request(port, "GET", "/audit")
            check(code == 200, f"RBAC-off /audit should be readable, got {code}")
            check(body["count"] >= 1, "RBAC-off /audit must return the seeded entry")
        finally:
            srv.shutdown(); srv.server_close()


# ---- 3. append-only behavior --------------------------------------------

def test_append_only():
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "audit.jsonl")
        log = audit_mod.AuditLog(path=path, max_entries=100)

        e1 = log.record("login_success", actor="u1", tenant_id="acme", detail={"seq": 1})
        with open(path, encoding="utf-8") as f:
            line1 = f.readline()
        check(line1.strip() == json.dumps(e1, sort_keys=True),
              "first recorded entry must be the first line verbatim")
        check(line1.endswith("\n"), "each entry line must be newline-terminated")

        e2 = log.record("triage_update", actor="u1", tenant_id="acme", detail={"seq": 2})
        with open(path, encoding="utf-8") as f:
            all_lines = f.read().splitlines()
        check(len(all_lines) == 2, f"append must add a line (got {len(all_lines)})")
        # append-only: line 1 is byte-for-byte unchanged after a later append
        check(all_lines[0] == line1.strip(),
              "append-only: earlier entries must never be rewritten")
        check(all_lines[1] == json.dumps(e2, sort_keys=True),
              "append-only: newer entry must follow, not overwrite, the older")

        # reading back round-trips in file order (oldest first via count)
        recent = log.recent()
        check(len(recent) == 2, "recent() must return all entries")
        check(recent[0]["detail"]["seq"] == 2, "recent() must be newest-first")
        check(recent[1]["detail"]["seq"] == 1, "recent()[1] must be the older entry")


# ---- 4. capacity cap / tail-truncation ----------------------------------

def test_capacity_cap():
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "audit.jsonl")
        cap = 5
        log = audit_mod.AuditLog(path=path, max_entries=cap)

        for i in range(1, 21):  # 20 > cap
            log.record("triage_update", actor="u1", tenant_id="acme", detail={"seq": i})

        # on-disk file never exceeds the cap
        with open(path, encoding="utf-8") as f:
            lines = [ln for ln in f.read().splitlines() if ln.strip()]
        check(len(lines) == cap, f"file must hold at most {cap} lines, got {len(lines)}")

        recent = log.recent()
        check(len(recent) == cap, f"recent() must hold at most {cap}, got {len(recent)}")

        # ring-buffer: only the NEWEST `cap` survive; the oldest are trimmed
        survivors = sorted(e["detail"]["seq"] for e in recent)
        check(survivors == list(range(21 - cap, 21)),
              f"capacity cap must keep only the newest {cap} (oldest trimmed), got {survivors}")

        # read path agrees with the capped on-disk state
        check(log.count() == cap, f"count() must match the cap, got {log.count()}")

        # even an empty/never-created file is a valid (empty) log
        empty = audit_mod.AuditLog(path=os.path.join(td, "empty.jsonl"), max_entries=3)
        check(empty.recent() == [], "a fresh log must read back empty")


# ---- fail-open at the module level --------------------------------------

def test_record_fail_open():
    """record() must return None (and never raise) when the write target is
    unusable -- the request path must not break on an audit outage."""
    with tempfile.TemporaryDirectory() as td:
        # a path whose parent is a FILE -> makedirs/open cannot succeed
        blocker = os.path.join(td, "not-a-dir")
        with open(blocker, "w", encoding="utf-8") as f:
            f.write("x")
        bad = audit_mod.AuditLog(path=os.path.join(blocker, "audit.jsonl"))
        result = bad.record("login_success", actor="u1", detail={})
        check(result is None, "record() must return None (not raise) on a write failure")


def main():
    os.environ["FENGARDE_SESSION_BACKEND"] = "memory"
    os.environ.pop("FENGARDE_API_KEY", None)
    try:
        test_events_recorded()
        test_audit_route_admin_scoped()
        test_audit_route_available_when_rbac_off()
        test_append_only()
        test_capacity_cap()
        test_record_fail_open()
    finally:
        os.environ.pop("FENGARDE_SESSION_BACKEND", None)
        os.environ.pop("FENGARDE_API_KEY", None)

    if FAILS:
        print(f"[FAIL] E1 audit: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] E1 audit: entries on login/triage/report, /audit admin-scoped, "
          "append-only, capacity-cap tail-truncation, fail-open")


if __name__ == "__main__":
    main()
