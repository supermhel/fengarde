"""Envelope v1 (M1 correctness gate) — shared helpers for the bus/OCSF envelope
fields threaded across every workstream: ``schema_version``, ``trace_id``,
``tenant_id``. See ``contracts/bus-topics.md`` "Envelope v1" section for the
frozen contract this implements.

All three fields are additive: an event/message without them is still valid
(Contract A's validator does not enforce ``additionalProperties: false`` on
nested objects, and none of these are in the schema's ``required`` list).
Existing pre-v1 fixtures and payloads keep validating unchanged.
"""
from __future__ import annotations

import os
import re
import uuid

#: Version of the SIEM event/bus-envelope contract (contracts/bus-topics.md +
#: contracts/ocsf-event.schema.json), not the OCSF ``metadata.version``.
SCHEMA_VERSION = "1.0"

#: Env var an operator sets to identify events from their deployment when
#: forwarding into a shared multi-tenant index (M4 groundwork). Unset ->
#: "default", matching every event's implicit tenant before this existed.
_TENANT_ENV = "TENANT_ID"
_DEFAULT_TENANT = "default"

# M4.1's tenant_id gets embedded directly into an OpenSearch index name
# (services/ws3-indexer/router.py: f"alerts-{tenant}-...") and a
# contracts/tenants/<tenant_id>.yml filename
# (services/ws4-detection/tenants.py). Both uses need a narrow, safe
# character set: lowercase alphanumeric + hyphen, no leading/trailing
# hyphen, 1-63 chars (DNS-label-style, the same shape Kubernetes
# namespaces use -- a convention MSP operators already recognize).
# Deliberately does NOT normalize (lowercase/slugify) a bad id instead of
# rejecting it: "Acme" and "ACME" would both normalize to "acme" and
# silently MERGE two different customers' data into one tenant's index --
# exactly the cross-tenant isolation bug this whole mechanism exists to
# prevent. An invalid tenant_id must be rejected at the point it's about
# to be used, loudly, never silently coerced into something that happens
# to work.
_TENANT_ID_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def valid_tenant_id(tenant_id) -> bool:
    """True if `tenant_id` is safe to embed in an OpenSearch index name or
    a contracts/tenants/*.yml filename. See module comment above for why
    an invalid id is rejected, never normalized."""
    return isinstance(tenant_id, str) and bool(_TENANT_ID_PATTERN.match(tenant_id))


def default_tenant() -> str:
    """The tenant_id (``siem.tenant``) to stamp on events this deployment
    produces, absent an explicit per-event override. Single-tenant deployments
    (the only kind that exist today) never need to set ``TENANT_ID``."""
    return os.getenv(_TENANT_ENV, _DEFAULT_TENANT)


def new_trace_id() -> str:
    """A fresh trace_id for one raw event's journey collector -> alert.
    Called once per event at WS-1 ingest; every downstream stage carries the
    same value through rather than generating its own (that's what makes it a
    trace, not just another per-stage id)."""
    return str(uuid.uuid4())


def stamp_meta(meta: dict) -> dict:
    """Ensure a raw.events ``meta`` dict carries trace_id/tenant_id, generating
    them if this is the first stage to see the event (WS-1 collectors). A meta
    dict that already has them (re-delivery, or a downstream stage re-calling
    this defensively) is left untouched -- the trace_id must stay stable across
    the whole journey, not regenerate on redelivery."""
    meta.setdefault("trace_id", new_trace_id())
    meta.setdefault("tenant_id", default_tenant())
    return meta
