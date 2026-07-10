# Contract R — Incident-Report Hook (v0.4)

Frozen cross-repo seam between this repo (`argus`, open) and `argus-sec` (private,
paid). Open half: the hook + a generic template backend, both here, both usable
with zero paid dependency. Paid half: `argus-sec` implements the same backend
protocol with regulatory content (RAG over DORA/NIS2/BSI/BaFin, German
notification templates, citations). Neither side may drift from this schema
without updating it here first — same discipline as `contracts/bus-topics.md`.

## Why this exists

An alert is a correlation; an incident report is what an analyst hands to a
regulator (NIS2 24h/72h notifications, DORA Art. 19 initial notification) or
keeps for audit. Generating one from alert facts is useful with zero paid
dependency (the template backend); a legally-mapped, cited regulatory draft is
`argus-sec`'s asset. This contract is the additive-field boundary between them
— the open pipeline must be complete and useful without `argus-sec` ever
running.

## Trigger

```
POST /alerts/{alert_id}/report
GET  /alerts/{alert_id}/report
```

Same host/port as the WS-3 triage API (`TRIAGE_PORT`, default `8013`) — WS-3
already owns the alert document; no new service. Subject to the same auth as
the triage API (`ARGUS_API_KEY`, see `SECURITY.md` §2).

## Backend seam

Selected by `REPORT_BACKEND` env on WS-3:

| Value | Backend | Owner |
|---|---|---|
| `template` (default) | Builtin generic markdown renderer, in-process | this repo |
| `http` | POST to `ARGUS_SEC_REPORT_URL`, response validated against this schema | `argus-sec` |

`http` backend failure (timeout, non-2xx, or a response that fails validation
below) **falls back to the `template` backend** — a report is still produced,
never a hard error. The response gains `"backend_degraded": true` in that case.
This mirrors `services/ws5-ai/llm_adapter.py::make_llm()`'s env-driven,
fail-open pattern — `argus-sec` is an external HTTP callee, not a new
workstream; bus-only coupling between workstreams is untouched.

## Request payload (WS-3 → backend)

```json
{
  "alert": { "...": "the full alert document as stored" },
  "triage": { "status": "...", "note": "...", "updated_at": 0 },
  "events": [ "up to REPORT_MAX_EVENTS (default 20) contributing OCSF events" ],
  "requested_at": 0
}
```

## Response schema (frozen)

```json
{
  "report_id": "<alert_id>:report",
  "alert_id": "...",
  "format": "markdown",
  "body": "...",
  "status": "draft",
  "disclaimer": "DRAFT — automatically generated. Not legal advice. Review before any regulatory submission.",
  "generated_at": 0,
  "backend": "template | argus-sec",
  "backend_degraded": false,
  "citations": [
    {"celex": "32022R2554", "article": "Article 19", "url": "https://eur-lex.europa.eu/...", "retrieved_at": "2026-07-01T00:00:00Z"}
  ]
}
```

### Hard rules (enforced by WS-3, not by convention)

1. **`status` is `"draft"` and only `"draft"` in v0.4.** The enum widens only
   when `argus-sec`'s legal sign-off gate passes (see its `docs/STATUS.md`).
   A response claiming any other status is rejected; WS-3 falls back to the
   template backend instead.
2. **`disclaimer` is mandatory and non-empty.** A response missing it is
   rejected the same way — this is a structural gate, not a documentation
   promise.
3. **`citations` is optional and may be `[]`.** The open pipeline never reads
   or depends on its contents — this is the additive-field discipline
   (`argus-sec`'s Track C3). A template-backend report has no citations and
   is still a complete, valid report.
4. **`body` is markdown, rendered as text in the dashboard** (never
   `innerHTML`) — the backend is external input; the existing stored-XSS
   discipline (`SECURITY.md`) applies here identically.

## Storage

Reports are indexed as `reports-YYYY.MM.DD` via the existing storage adapter
(`services/ws3-indexer/storage/`). `report_id` is deterministic
(`f"{alert_id}:report"`) so re-generation is idempotent under retry — same
discipline as the alert's own `alert_id` (Contract, T7).

## What this is not

Not a bus topic — no `contracts/bus-topics.md` change. Not a new workstream —
WS-3 owns it, same as the triage API. Not a guarantee of legal validity —
every report is a draft until a human (and, for the regulated-content path,
`argus-sec`'s legal sign-off gate) says otherwise.
