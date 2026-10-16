"""Admin-only console routes (2026-10-15): user management, webhook list, rule on/off.

  GET   /users                      -> every account (never password_hash / totp_secret)
  POST  /users                      {username, password, role, tenant_id?} -> create
  PATCH /users/{name}               {role?, password?, disabled?} -> update
  GET   /webhooks                   -> contracts/webhooks/*.yml, redacted (host only)
  PUT   /rules/{rule_id}/enabled    {enabled, tenant_id?} -> contracts/tenants/<id>.yml

Every route is session-RBAC only (Handler dispatches them only when RBAC is on;
RBAC off -> "no such path") and requires role=admin via `_require_role`, the
same 401/404 posture as every other route. CSRF for POST/PUT/PATCH is enforced
by the dispatcher before these run. Route functions take the same `self` as
triage_api's `route_*` functions.
"""
from __future__ import annotations

import os
import re
import sqlite3
from urllib.parse import unquote, urlparse

from shared.envelope import valid_tenant_id
from shared.log import get_logger
from shared.users import ROLES, LastAdminError, password_problem

import rules_view
import webhooks

_LOG = get_logger("ws3-indexer-admin")

_MAX_BODY_BYTES = 4096
# Same character class as an email local part + domain, so SSO-style names fit;
# no '/' (path segment) and no whitespace.
_USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$")
_CREATE_FIELDS = {"username", "password", "role", "tenant_id"}
_UPDATE_FIELDS = {"role", "password", "disabled"}
_TOGGLE_FIELDS = {"enabled", "tenant_id"}


def _user_view(row) -> dict:
    """Explicit allowlist of columns: a new secret column can never leak by default."""
    keys = row.keys()
    return {
        "username": row["username"],
        "role": row["role"],
        "tenant_id": row["tenant_id"],
        "created_at": row["created_at"],
        "last_login_at": row["last_login_at"],
        "mfa_active": bool(row["totp_active"]),
        "disabled": bool(row["disabled"]) if "disabled" in keys else False,
    }


def _unknown(body: dict, allowed: set) -> str | None:
    extra = set(body) - allowed
    return f"unknown field(s): {sorted(extra)}" if extra else None


def route_list_users(self):
    session = self._require_role("admin")
    if session is None:
        return
    users = [_user_view(r) for r in self.deps.users_db.list_users()]
    return self._send(200, {"users": users, "count": len(users)})


def route_create_user(self):
    session = self._require_role("admin")
    if session is None:
        return
    body = self._read_json_body(_MAX_BODY_BYTES)
    err = _unknown(body, _CREATE_FIELDS)
    username, password, role = body.get("username"), body.get("password"), body.get("role")
    tenant = body.get("tenant_id") or session.tenant_id
    if err is None and (not isinstance(username, str) or not _USERNAME.match(username)):
        err = "username must be 1-64 chars of letters, digits, _ . @ - (starting with a letter or digit)"
    if err is None:
        err = password_problem(password)
    if err is None and role not in ROLES:
        err = f"role must be one of {list(ROLES)}"
    if err is None and not valid_tenant_id(tenant):
        err = "invalid tenant_id"
    if err:
        return self._send(400, {"error": err})
    try:
        self.deps.users_db.create_user(username, password, role=role, tenant_id=tenant)
    except sqlite3.IntegrityError:
        return self._send(409, {"error": "user already exists"})
    self._audit("user_create", actor=self._audit_actor(session), tenant_id=tenant,
                detail={"username": username, "role": role, "tenant_id": tenant})
    return self._send(201, _user_view(self.deps.users_db.get_user(username)))


def route_update_user(self, raw_name: str):
    session = self._require_role("admin")
    if session is None:
        return
    name = unquote(raw_name)
    body = self._read_json_body(_MAX_BODY_BYTES)
    if not _USERNAME.match(name):
        return self._send(404, {"error": "no such user"})
    err = _unknown(body, _UPDATE_FIELDS)
    if err is None and not body:
        err = "nothing to update: send role, password and/or disabled"
    role, password, disabled = body.get("role"), body.get("password"), body.get("disabled")
    if err is None and "role" in body and role not in ROLES:
        err = f"role must be one of {list(ROLES)}"
    if err is None and "password" in body:
        err = password_problem(password)
    if err is None and "disabled" in body and not isinstance(disabled, bool):
        err = "disabled must be true or false"
    if err:
        return self._send(400, {"error": err})
    try:
        found = self.deps.users_db.update_user(
            name, role=role if "role" in body else None,
            password=password if "password" in body else None,
            disabled=disabled if "disabled" in body else None)
    except LastAdminError as e:
        return self._send(409, {"error": str(e)})
    if not found:
        return self._send(404, {"error": "no such user"})
    row = self.deps.users_db.get_user(name)
    detail = {"username": name, "changed": sorted(body)}  # field names only, never the password
    if "role" in body:
        detail["role"] = role
    if "disabled" in body:
        detail["disabled"] = disabled
    self._audit("user_update", actor=self._audit_actor(session), tenant_id=row["tenant_id"], detail=detail)
    return self._send(200, _user_view(row))


def route_list_webhooks(self):
    """Redacted: the URL is reduced to scheme + hostname (path, query, userinfo
    and port can all carry a receiver token). `secret_env` is the NAME of the
    env var, never its value; `enabled` says whether that var is set in this
    process, i.e. whether deliveries can be signed and sent. Files are re-read
    per request; the dispatcher thread loaded them at WS-3 startup."""
    session = self._require_role("admin")
    if session is None:
        return
    hooks = []
    for c in webhooks.load_webhook_configs():
        u = urlparse(c.url)
        hooks.append({
            "id": c.id,
            "scheme": u.scheme,
            "host": u.hostname or "",
            "tenant_id": c.tenant_id,
            "min_score": c.min_score,
            "secret_env": c.secret_env,
            "enabled": bool(os.getenv(c.secret_env)),
        })
    return self._send(200, {"webhooks": hooks, "count": len(hooks)})


def route_set_rule_enabled(self, raw_rule_id: str):
    session = self._require_role("admin")
    if session is None:
        return
    rule_id = unquote(raw_rule_id)
    body = self._read_json_body(_MAX_BODY_BYTES)
    err = _unknown(body, _TOGGLE_FIELDS)
    enabled = body.get("enabled")
    tenant = body.get("tenant_id") or session.tenant_id
    if err is None and not isinstance(enabled, bool):
        err = "enabled must be true or false"
    if err is None and not valid_tenant_id(tenant):
        err = "invalid tenant_id"
    if err:
        return self._send(400, {"error": err})
    if rule_id not in {r["id"] for r in rules_view.list_rule_summaries(None)}:
        return self._send(404, {"error": "rule not found"})
    try:
        rules_view.set_rule_enabled(tenant, rule_id, enabled)
    except ValueError as e:  # tenant file exists but is not a YAML mapping
        return self._send(409, {"error": str(e)})
    except OSError as e:
        _LOG.error("tenant config write failed", tenant_id=tenant, error=repr(e))
        return self._send(503, {"error": "tenant config directory is not writable"})
    self._audit("rule_toggle", actor=self._audit_actor(session), tenant_id=tenant,
                detail={"rule_id": rule_id, "enabled": enabled, "tenant_id": tenant})
    return self._send(200, {"id": rule_id, "tenant_id": tenant, "enabled": enabled})
