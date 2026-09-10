# Contract R — Incident-Report Hook (v0.4)

Frozen cross-repo seam between this repo (`fengarde`, open) and `fengarde-sec` (private,
paid). Open half: the hook + a generic template backend, both here, both usable
with zero paid dependency. Paid half: `fengarde-sec` implements the same backend
protocol with regulatory content (RAG over DORA/NIS2/BSI/BaFin, German
notification templates, citations). Neither side may drift from this schema
without updating it here first — same discipline as `contracts/bus-topics.md`.

## Why this exists

An alert is a correlation; an incident report is what an analyst hands to a
regulator (NIS2 24h/72h notifications, DORA Art. 19 initial notification) or
keeps for audit. Generating one from alert facts is useful with zero paid
dependency (the template backend); a legally-mapped, cited regulatory draft is
`fengarde-sec`'s asset. This contract is the additive-field boundary between them
— the open pipeline must be complete and useful without `fengarde-sec` ever
running.

## Trigger

```
POST /alerts/{alert_id}/report
GET  /alerts/{alert_id}/report
```

Same host/port as the WS-3 triage API (`TRIAGE_PORT`, default `8013`) — WS-3
already owns the alert document; no new service. Subject to the same auth as
the triage API (`FENGARDE_API_KEY`, see `SECURITY.md` §2).

## Backend seam

Selected by `REPORT_BACKEND` env on WS-3:

| Value | Backend | Owner |
|---|---|---|
| `template` (default) | Builtin generic markdown renderer, in-process | this repo |
| `http` | POST to `FENGARDE_SEC_REPORT_URL`, response validated against this schema | `fengarde-sec` |

`http` backend failure (timeout, non-2xx, or a response that fails validation
below) **falls back to the `template` backend** — a report is still produced,
never a hard error. The response gains `"backend_degraded": true` in that case.
This mirrors `services/ws5-ai/llm_adapter.py::make_llm()`'s env-driven,
fail-open pattern — `fengarde-sec` is an external HTTP callee, not a new
workstream; bus-only coupling between workstreams is untouched.

## Request payload (WS-3 → backend)

```json
{
  "alert": { "...": "the full alert document as stored" },
  "triage": { "status": "...", "note": "...", "updated_at": 0 },
  "events": [],
  "requested_at": 0
}
```

**`events` is currently always `[]`, not a real payload** — this was written as
a forward-looking field before the lookup existed to populate it, and no
`REPORT_MAX_EVENTS`-style config was ever built (there is no such env var
anywhere in this repo; don't rely on it existing). Pulling the alert's actual
contributing normalized events (`Rule.contributing_event_ids()`,
`services/ws4-detection/engine.py`, already recorded per-alert since the
Design-A pass) into this field is a real, still-open follow-up — see
`services/ws3-indexer/reporting.py::generate_report`'s own docstring. A backend
implementation (including `fengarde-sec`'s) must not assume this array is ever
non-empty today.

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
  "backend": "template | fengarde-sec",
  "backend_degraded": false,
  "citations": [
    {"celex": "32022R2554", "article": "Article 19", "url": "https://eur-lex.europa.eu/...", "retrieved_at": "2026-07-01T00:00:00Z"}
  ]
}
```

### Hard rules (enforced by WS-3, not by convention)

1. **`status` is `"draft"` and only `"draft"` in v0.4.** The enum widens only
   when `fengarde-sec`'s legal sign-off gate passes (see its `docs/STATUS.md`).
   A response claiming any other status is rejected; WS-3 falls back to the
   template backend instead.
2. **`disclaimer` is mandatory and non-empty.** A response missing it is
   rejected the same way — this is a structural gate, not a documentation
   promise.
3. **`citations` is optional and may be `[]`.** The open pipeline never reads
   or depends on its contents — this is the additive-field discipline
   (`fengarde-sec`'s Track C3). A template-backend report has no citations and
   is still a complete, valid report.
4. **`body` is markdown, rendered as text in the dashboard** (never
   `innerHTML`) — the backend is external input; the existing stored-XSS
   discipline (`SECURITY.md`) applies here identically.

## NIS2 template mode (M5, additive)

`POST /alerts/{alert_id}/report` accepts three OPTIONAL query parameters
that select a second, purely additive rendering mode — the response
envelope above is unchanged, only `body`/`disclaimer`/`backend`/`citations`
differ:

| Param | Values | Default | Effect |
|---|---|---|---|
| `template` | `generic` \| `nis2` | `generic` | `nis2` renders the deterministic German (or English) NIS2/§32 BSIG draft (`services/ws3-indexer/nis2_template.py`) instead of the generic incident-report template. Omitting it is byte-for-byte the pre-M5 behavior. |
| `stage` | `early_warning` \| `notification` \| `final_report` | `notification` | Which of NIS2 Art. 23(4)'s three reporting stages to draft. Only meaningful with `template=nis2`. |
| `lang` | `de` \| `en` | `de` | Draft language. Only meaningful with `template=nis2`. |

`GET /alerts/{alert_id}/report` is unaffected — it returns whatever was
stored by the most recent POST, regardless of which template produced it.

**This is still a draft, not a legal filing.** The NIS2 mode's `body`
carries its own inline "DRAFT — not legal advice" banner (top and bottom)
plus an explicit NIS2-vs-DORA scope caveat (financial entities are
typically governed by DORA Art. 19, a different regime, not NIS2) — see
`docs/nis2-report-generator.md` and `contracts/nis2-de-schema.json` for the
full field-level schema and citations.

## Storage

Reports are indexed as `reports-YYYY.MM.DD` via the existing storage adapter
(`services/ws3-indexer/storage/`). `report_id` is deterministic
(`f"{alert_id}:report"`) so re-generation is idempotent under retry — same
discipline as the alert's own `alert_id` (Contract, T7).

## Evidence packages feed this seam (WP-3-B, 2026-09-02)

`services/ws3-indexer/evidence_package.py` builds an **immutable,
hash-chained evidence package** per incident (Merkle-style: incident genesis
block → per-alert blocks → per-event blocks → optional graph block, each
committing to the prior chain via `prev_hash`; `package_id` deterministic per
incident content, so redelivery/building twice yields the same id). Its
`to_reporting_payload()` returns exactly the **request payload** schema above
(keys `alert`, `triage`, `events`, `requested_at`), with `events` populated
from the package's event blocks — this is the mechanism that turns the
forward-looking, currently-empty `events` field into a real, provenance-linked
payload. The package is the single provenance-linked source multiple views
render from (analyst timeline, incident report, regulatory draft, customer
communication, management summary, postmortem); only the *rendering* is
plural, the hash-chained core stays one artifact. Tampering any
block fails `verify_evidence_package()`. This note is additive; the frozen
response schema above is unchanged.

**Update (Phase 5, 2026-09-04): the first consumer landed, as a genuinely
separate surface, not a widened version of this one.** `GET
/incidents/{id}/evidence` serves the package itself (built fresh on demand,
never an unverified/tampered one — 409 with the failure reasons instead of
a silent 200); `POST /incidents/{id}/report` renders an incident-level
NIS2-style draft FROM it. Both live entirely outside this contract's
request/response schema above — the reason is structural, not a style
choice: `to_reporting_payload()` (the function that maps a package onto
THIS contract's request shape) deliberately collapses the package to its
`primary_alert_id` (chronological first member alert only) because this
seam's response is `alert`-scoped by construction (`report_id:
"{alert_id}:report"`, frozen, and a real cross-repo seam — `fengarde-sec`'s
paid backend implements this exact schema too). An incident can have many
member alerts; widening this frozen schema to carry all of them would mean
breaking or version-coordinating that external implementation for a need
this doc's own design already anticipated (see the "multiple views render
from" language above) without needing to touch the frozen shape.

So: `POST /incidents/{id}/report`'s response is its **own** shape —
`report_id: "{incident_id}:incident-report"` (never `"{alert_id}:report"`,
so the two can never collide in the same `reports-*` index), a
`evidence_verified`/`evidence_package_id` pair naming the package it was
built from, and a `body` ordered by the causal graph's own edge
timestamps (falling back to alert-arrival order only when no graph
exists) — not `to_reporting_payload()`'s alert-shaped request at all.
`services/ws3-indexer/nis2_template.py::build_incident_report()` is the
renderer; `route_post_incident_report` in `triage_api.py` is the route.
Same disclaimer/draft-status/never-fabricate discipline as every other
report this repo generates.

## What this is not

Not a bus topic — no `contracts/bus-topics.md` change. Not a new workstream —
WS-3 owns it, same as the triage API. Not a guarantee of legal validity —
every report is a draft until a human (and, for the regulated-content path,
`fengarde-sec`'s legal sign-off gate) says otherwise.
