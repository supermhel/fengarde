"""M4.4: outbound alert webhooks, HMAC-signed.

Opt-in (same convention as every other M4 feature): with no files under
``contracts/webhooks/*.yml``, :func:`load_webhook_configs` returns an empty
list and the dispatcher never starts a bus consumer -- zero behavior change
for every deployment that doesn't use this.

A webhook config never carries a secret in the repo: ``secret_env`` names an
ENVIRONMENT VARIABLE holding the real HMAC key, so `contracts/webhooks/*.yml`
stays safe to commit (SECURITY.md SS4: never commit real credentials). If
that env var is unset at dispatch time, delivery for THAT config alone is
skipped (fail closed -- never send an unsigned or garbage-keyed request);
every other configured webhook still fires.

Delivery is independent of indexing: the dispatcher consumes the `alerts`
bus topic under its OWN consumer group (`cg-webhook`), separate from WS-3's
`cg-index` group used by main.py. A webhook receiver being down, slow, or
misconfigured can never block or duplicate an alert being indexed, and
indexing issues never affect webhook delivery -- two independent readers of
one Redis Streams topic, the same pattern already used for
detection<->ai.requests.

Signature scheme mirrors the well-known GitHub webhook convention so
existing receiver-side tooling/knowledge transfers: `X-Fengarde-Signature-256:
sha256=<hex hmac>` over the raw JSON request body, verified with
hmac.compare_digest (constant-time). See docs/webhooks.md for the receiver
side (verify_signature) and contracts/webhooks/README.md for the config
format.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path

import yaml

_HERE = Path(__file__).resolve().parent
_SERVICES = _HERE.parent
_ROOT = _SERVICES.parent


def _contracts_dir() -> Path:
    """Same host-vs-container path-layout mismatch as rules_view.py's
    ``_contracts_dir()`` (see its docstring): _HERE is repo/services/
    ws3-indexer on a host checkout (two parents up to repo root) but
    /app/ws3-indexer in the container (one parent up to /app, where the
    Dockerfile COPYs contracts/). Probe both rather than hardcoding either."""
    for base in (_SERVICES, _ROOT):
        if (base / "contracts" / "webhooks").is_dir():
            return base / "contracts"
    return _ROOT / "contracts"


WEBHOOKS_DIR = _contracts_dir() / "webhooks"

_TIMEOUT_S = 5.0
_MAX_RETRIES = 3
_BACKOFF_S = 0.5
SIGNATURE_HEADER = "X-Fengarde-Signature-256"
DELIVERY_ID_HEADER = "X-Fengarde-Delivery-Id"


@dataclass(frozen=True)
class WebhookConfig:
    id: str
    url: str
    secret_env: str
    tenant_id: str | None = None  # None -> every tenant
    min_score: int = 0            # fire only when alert["score"] >= this


def sign(secret: bytes, body: bytes) -> str:
    return "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()


def verify_signature(secret: bytes, body: bytes, header_value: str | None) -> bool:
    """What a webhook RECEIVER calls to authenticate a delivery. Constant-time
    compare -- a naive `==` would leak the correct prefix length via timing."""
    if not header_value:
        return False
    return hmac.compare_digest(sign(secret, body), header_value)


def load_webhook_configs(webhooks_dir: Path | None = None) -> list[WebhookConfig]:
    """One WebhookConfig per contracts/webhooks/*.yml. A malformed individual
    file is skipped (logged nowhere yet -- same "silent skip" convention as
    tenants.py for a missing tenant file); it never takes down every OTHER
    configured webhook."""
    directory = Path(webhooks_dir) if webhooks_dir is not None else WEBHOOKS_DIR
    configs: list[WebhookConfig] = []
    if not directory.is_dir():
        return configs
    for path in sorted(directory.glob("*.yml")):
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if not isinstance(raw, dict):
            continue
        wid, url, secret_env = raw.get("id"), raw.get("url"), raw.get("secret_env")
        if not isinstance(wid, str) or not isinstance(url, str) or not isinstance(secret_env, str):
            continue
        if not (url.startswith("https://") or url.startswith("http://")):
            continue
        tenant_id = raw.get("tenant_id")
        min_score = raw.get("min_score", 0)
        configs.append(WebhookConfig(
            id=wid,
            url=url,
            secret_env=secret_env,
            tenant_id=tenant_id if isinstance(tenant_id, str) else None,
            min_score=int(min_score) if isinstance(min_score, (int, float))
            and not isinstance(min_score, bool) else 0,
        ))
    return configs


def _matches(config: WebhookConfig, alert: dict) -> bool:
    if config.tenant_id is not None and (alert.get("tenant_id") or "default") != config.tenant_id:
        return False
    score = alert.get("score")
    if not isinstance(score, (int, float)) or isinstance(score, bool):
        score = 0
    return score >= config.min_score


def deliver(config: WebhookConfig, alert: dict) -> bool:
    """POST `alert` to config.url, HMAC-signed. Never raises: a receiver
    being unreachable, slow, or erroring must not crash the dispatcher
    thread. Returns True only once urlopen returns without raising (a non-2xx
    response raises urllib.error.HTTPError, same convention as reporting.py's
    _call_http_backend). 4xx is treated as permanent (bad payload/config on
    OUR side or the receiver's -- retrying won't fix it); connection errors
    and 5xx get bounded retries, matching OpenSearchStore.index's policy."""
    secret = os.getenv(config.secret_env)
    if not secret:
        return False
    delivery_id = str(uuid.uuid4())
    body = json.dumps({"delivery_id": delivery_id, "alert": alert}).encode()
    headers = {
        "Content-Type": "application/json",
        SIGNATURE_HEADER: sign(secret.encode(), body),
        DELIVERY_ID_HEADER: delivery_id,
    }
    for attempt in range(_MAX_RETRIES):
        req = urllib.request.Request(config.url, data=body, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:  # noqa: S310
                resp.read()
            return True
        except urllib.error.HTTPError as exc:
            if 400 <= exc.code < 500:
                return False  # permanent: retrying won't fix a bad payload/config
            # else: 5xx, transient -- fall through to the backoff/retry below
        except (urllib.error.URLError, TimeoutError, OSError):
            pass  # connection error, also transient -- retry
        if attempt < _MAX_RETRIES - 1:
            time.sleep(_BACKOFF_S * (2 ** attempt))
    return False


def dispatch_alert(configs: list[WebhookConfig], alert: dict) -> int:
    """Deliver `alert` to every matching, enabled config. Returns the number
    of successful deliveries. One config raising/failing never stops the
    others from being tried."""
    delivered = 0
    for config in configs:
        if not _matches(config, alert):
            continue
        try:
            if deliver(config, alert):
                delivered += 1
        except Exception:  # noqa: BLE001 - a bad webhook must never crash the consumer
            continue
    return delivered


def run(bus, configs: list[WebhookConfig] | None = None) -> dict:
    """Drain the `alerts` topic once under consumer group `cg-webhook` and
    dispatch each alert to every matching config. Batch entrypoint used by
    tests and the daemon thread wired in main.py. No configs -> a no-op that
    doesn't touch the bus at all (opt-in)."""
    if configs is None:
        configs = load_webhook_configs()
    stats = {"alerts_seen": 0, "deliveries": 0}
    if not configs:
        return stats
    for msg in bus.consume("alerts", group="cg-webhook"):
        stats["alerts_seen"] += 1
        stats["deliveries"] += dispatch_alert(configs, msg.payload)
    return stats
