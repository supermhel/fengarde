"""POST /inventory/assets -- admin-only manual device add/update (WS-3 -> WS-6).

Why this lives in WS-3 and not behind nginx's /api/inventory/ proxy: that proxy
is GET/HEAD-only on purpose, and the dashboard's FENGARDE_API_KEY is one shared
page-level key, so nginx cannot tell an admin from anyone else holding the page.
Only WS-3's session RBAC knows the role. This route therefore:

  1. is reachable only with RBAC on (Handler.do_POST dispatches it inside the
     rbac block, after `_check_csrf` -- a session POST without the matching
     X-CSRF-Token is already a 403 before it gets here);
  2. requires role=admin (`_require_role`, same 401/404 posture as every route);
  3. validates the body strictly (unknown fields, MAC, IP, hostname, sector,
     type, tenant_id) at this trust boundary;
  4. calls WS-6 `POST /assets/upsert` server-side (INVENTORY_URL, optional
     INVENTORY_API_KEY) and maps its failures to clean 400/502;
  5. audits `inventory_asset_upsert` on success.

Route function takes the same `self` as triage_api's `route_*` functions (the
Handler, or a test double exposing the same helpers).
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request

from shared.envelope import valid_tenant_id
from shared.ip_utils import valid_ip
from shared.log import get_logger
from shared.outbound_http import no_redirect_urlopen

_LOG = get_logger("ws3-indexer-inventory-write")

_MAX_BODY_BYTES = 4096
_TIMEOUT_S = 3  # stays inside nginx's 5s proxy_read_timeout on /api/triage/
_FIELDS = {"mac", "hostname", "ip", "sector", "type", "tenant_id"}
# contracts/inventory-api.yaml Asset.sector enum (same set as the OCSF schema).
SECTORS = ("bank", "datacenter", "common")
# AA:BB:CC:DD:EE:FF, aa-bb-cc-dd-ee-ff or aabbccddeeff (one separator style throughout).
_MAC_SHAPE = re.compile(r"^[0-9a-f]{2}([:-]?)[0-9a-f]{2}(?:\1[0-9a-f]{2}){4}$")
_HOSTNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,251}[A-Za-z0-9])?$")
_TYPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$")


def normalize_mac(raw) -> str | None:
    """Canonical upper-case colon form (what the collectors emit and WS-6 keys
    on, case-sensitively), or None if `raw` is not a MAC."""
    if not isinstance(raw, str):
        return None
    s = raw.strip().lower()
    if not _MAC_SHAPE.match(s):
        return None
    hexes = s.replace(":", "").replace("-", "")
    return ":".join(hexes[i:i + 2] for i in range(0, 12, 2)).upper()


def validate(body: dict) -> tuple[dict | None, str | None]:
    """(observation, None) or (None, reason). Empty strings mean "not given"."""
    unknown = set(body) - _FIELDS
    if unknown:
        return None, f"unknown field(s): {sorted(unknown)}"
    mac = normalize_mac(body.get("mac"))
    if mac is None:
        return None, "mac is required, e.g. AA:BB:CC:DD:EE:FF"
    obs: dict = {"mac": mac}
    for field, pattern in (("hostname", _HOSTNAME), ("type", _TYPE)):
        value = body.get(field)
        if value is None or value == "":
            continue
        if not isinstance(value, str) or not pattern.match(value.strip()):
            return None, f"invalid {field}"
        obs[field] = value.strip()
    ip = body.get("ip")
    if ip is not None and ip != "":
        norm = valid_ip(ip.strip()) if isinstance(ip, str) else None
        if norm is None:
            return None, "ip must be a valid IPv4 or IPv6 address"
        obs["ip"] = norm
    sector = body.get("sector")
    if sector is not None and sector != "":
        if not isinstance(sector, str) or sector not in SECTORS:
            return None, f"sector must be one of {list(SECTORS)}"
        obs["sector"] = sector
    tenant = body.get("tenant_id")
    if tenant is not None and tenant != "" and not valid_tenant_id(tenant):
        return None, "invalid tenant_id"
    return obs, None


def _upsert(obs: dict) -> tuple[int, dict]:
    """POST the observation to WS-6. Returns (status, payload) for the client:
    200 asset, 400 when WS-6 rejected the input, 502 for anything else."""
    url = os.getenv("INVENTORY_URL", "http://ws6-inventory:8000").rstrip("/") + "/assets/upsert"
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    key = os.getenv("INVENTORY_API_KEY", "")
    if key:
        headers["X-Api-Key"] = key
    req = urllib.request.Request(url, data=json.dumps(obs).encode(), headers=headers, method="POST")
    try:
        with no_redirect_urlopen(req, timeout=_TIMEOUT_S) as resp:
            asset = json.loads(resp.read())
        if not isinstance(asset, dict):
            raise ValueError("non-object response")
        return 200, asset
    except urllib.error.HTTPError as e:
        if e.code == 400:
            try:
                reason = json.loads(e.read()).get("error")
            except Exception:  # noqa: BLE001 - unreadable error body
                reason = None
            return 400, {"error": str(reason or "rejected by the inventory service")}
        _LOG.warn("inventory upsert failed", status=e.code, mac=obs.get("mac"))
        if e.code in (401, 403):
            return 502, {"error": "inventory service refused WS-3's credentials (check INVENTORY_API_KEY)"}
        return 502, {"error": f"inventory service error (HTTP {e.code})"}
    except (urllib.error.URLError, OSError, ValueError) as e:
        _LOG.warn("inventory service unreachable", error=repr(e), mac=obs.get("mac"))
        return 502, {"error": "inventory service unreachable"}


def route_post_inventory_asset(self):
    """POST /inventory/assets {mac, hostname?, ip?, sector?, type?, tenant_id?}."""
    session = self._require_role("admin")
    if session is None:
        return
    body = self._read_json_body(_MAX_BODY_BYTES)
    obs, err = validate(body)
    if err:
        return self._send(400, {"error": err})
    # Admins may target a tenant explicitly; any other role is pinned to its own
    # (today unreachable past the admin gate -- kept so a role change can't widen scope).
    obs["tenant_id"] = self._list_tenant_filter(session, body.get("tenant_id") or None) or session.tenant_id
    status, payload = _upsert(obs)
    if status == 200:
        self._audit("inventory_asset_upsert", actor=self._audit_actor(session),
                    tenant_id=obs["tenant_id"],
                    detail={"mac": obs["mac"], "new_device": payload.get("new_device")})
    return self._send(status, payload)
