"""WS-3 routing: map a bus document to (index_name, doc_id).

Index selection (Contract E):
  * OCSF events  -> events-{sector}-{YYYY.MM.DD}   sector in {bank,dc,common}
                    (siem.sector 'datacenter' maps to the 'dc' index family)
  * alerts       -> alerts-{YYYY.MM.DD}
Doc id (idempotency, Contract B at-least-once):
  * events -> siem.ingest_id
  * alerts -> alert_id

M4 multi-tenancy (combined roadmap): a non-"default" tenant_id
(envelope v1's `siem.tenant`, threaded onto alerts by WS-4's make_alert) gets
its OWN index per family/day, inserted right after the family/prefix so
`template_for()` still recognizes it and a tenant-scoped wildcard query
(`events-common-acme-*`, `alerts-acme-*`) is possible:

  * events -> events-{family}-{tenant}-{YYYY.MM.DD}   (tenant != "default")
  * alerts -> alerts-{tenant}-{YYYY.MM.DD}             (tenant != "default")

The "default" tenant (every deployment that has never set TENANT_ID, i.e. all
of them before v0.5) keeps the EXACT pre-M4 naming -- zero migration, zero
behavior change for a single-tenant deployment. This is the storage-layer
half of the M4 isolation gate; the read/query half (an API scoping its
OpenSearch query to the caller's own tenant) is M4.2/M4.3, RBAC + API.
"""
from __future__ import annotations

from datetime import datetime, timezone

from shared.envelope import valid_tenant_id

_SECTOR_TO_FAMILY = {"bank": "bank", "datacenter": "dc", "common": "common"}
DEFAULT_TENANT = "default"


def _date_suffix(epoch_ms: int | None) -> str:
    if epoch_ms:
        dt = datetime.fromtimestamp(epoch_ms / 1000, tz=timezone.utc)
    else:
        dt = datetime.now(tz=timezone.utc)
    return dt.strftime("%Y.%m.%d")


def _validated_tenant(tenant: str) -> str:
    """Reject (never normalize) a tenant that isn't safe to embed in an
    index name. F3 (adversarial repo-wide bug hunt, 2026-07-16): an
    uppercase or otherwise malformed tenant_id (e.g. "Acme", "ACME Corp")
    used to flow straight into f"alerts-{tenant}-..." unchecked, producing
    an OpenSearch-INVALID index name -- OpenSearchStore.index() treats
    that 4xx as permanent, so the write is never retried and the document
    is eventually dead-lettered. That tenant's events/alerts would
    silently receive ZERO detections, an MSP data-loss footgun. Rejecting
    (not lowercasing) is deliberate: "Acme" and "ACME" both normalizing to
    "acme" would silently MERGE two different customers' data into one
    tenant's index, the exact cross-tenant isolation bug this mechanism
    exists to prevent (see valid_tenant_id's docstring)."""
    if tenant != DEFAULT_TENANT and not valid_tenant_id(tenant):
        raise ValueError(
            f"invalid tenant_id {tenant!r}: must be lowercase alphanumeric/hyphen, "
            f"1-63 chars, no leading/trailing hyphen")
    return tenant


def route(doc: dict) -> tuple[str, str]:
    """Return (index_name, doc_id) for a document. Raises ValueError if unroutable."""
    # alert?
    if "alert_id" in doc:
        tenant = _validated_tenant(doc.get("tenant_id") or DEFAULT_TENANT)
        base = "alerts" if tenant == DEFAULT_TENANT else f"alerts-{tenant}"
        return f"{base}-{_date_suffix(doc.get('time'))}", str(doc["alert_id"])

    # OCSF event
    siem = doc.get("siem") or {}
    sector = siem.get("sector")
    family = _SECTOR_TO_FAMILY.get(sector) if isinstance(sector, str) else None
    if family is None:
        raise ValueError(f"unroutable document: sector={sector!r}")
    doc_id = siem.get("ingest_id")
    if not doc_id:
        raise ValueError("event missing siem.ingest_id (needed for idempotency)")
    tenant = _validated_tenant(siem.get("tenant") or DEFAULT_TENANT)
    base = f"events-{family}" if tenant == DEFAULT_TENANT else f"events-{family}-{tenant}"
    return f"{base}-{_date_suffix(doc.get('time'))}", str(doc_id)


def template_for(index_name: str) -> str:
    """Logical index-template name (Contract E) for an index name."""
    if index_name.startswith("events-bank-"):
        return "events-bank"
    if index_name.startswith("events-dc-"):
        return "events-dc"
    if index_name.startswith("events-common-"):
        return "events-common"
    if index_name.startswith("alerts-"):
        return "alerts"
    return "unknown"
