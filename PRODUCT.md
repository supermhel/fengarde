# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Existing codebase: a single static `index.html` (inline `<style>` + vanilla JS, no framework, no build step) served by nginx (`services/ws7-dashboard/`), proxying same-origin to a real backend (WS-3's triage/report/rules/incidents API, WS-6's inventory API). Not greenfield — preserved as-is; no framework migration implied by this pass.

## Users

Security analysts and MSP operators running FENGARDE as their SIEM console — triaging fired alerts, correlating multi-stage incidents, checking detection (MITRE) coverage, and tracking network inventory. Primary situation: watching this dashboard during active monitoring or incident response, where fast severity scanning and low cognitive load under stress matter more than visual flourish. Secondary audience: a prospective adopter evaluating the open-source project (screenshots/demo used in README, launch posts, MSP quickstart) — first impression matters there too, but never at the expense of the analyst's working view.

## Product Purpose

FENGARDE is an open-source SIEM pipeline: raw security logs are collected, normalized to OCSF, run through correlation rules, and indexed as alerts. This dashboard (WS-7) is its console — the human-facing surface over that pipeline's real, live data (alerts, correlated incidents, MITRE coverage, asset inventory). Success is an analyst correctly triaging real threats faster, with less missed signal, not a prettier chrome around the same data.

## Positioning

Local-first, no-lock-in SIEM: OCSF-native normalization, local-LLM triage (Ollama, no cloud dependency required), fully open-source (Apache-2.0) core with a paid layer only for compliance/legal reporting. A neighboring closed-source SIEM vendor could not truthfully claim "runs entirely on your infrastructure, inspectable end to end."

## Operating Context

Real workflows this dashboard already serves, each backed by a real endpoint, not a mock:
- **Overview**: live alert feed (`GET /api/alerts`), per-alert triage status + analyst note (persisted), draft incident/NIS2 report generation, saved search filters, 10s auto-refresh live-polling.
- **Incidents** (new, 2026-08-18): correlated multi-stage incidents from WS-8 — an entity (actor or source IP) that shows ≥2 distinct MITRE tactics within a rolling window. Currently a bare table.
- **Coverage**: MITRE ATT&CK/ATLAS/ICS heatmap (tactic × technique, shaded by real fired-alert count), sourced from the rules API.
- **Inventory**: asset list (MAC/hostname/IP/sector/status) with per-asset IP-history drill-down.
- **Sources**: events-by-protocol bar breakdown.
- Session login (opt-in RBAC) gates the whole app behind a sign-in screen when the backend has RBAC configured; otherwise invisible.
- Dark/light theme toggle already exists (`prefers-color-scheme` default, explicit override persisted).

## Capabilities and Constraints

- **Live-data console, not a mockup.** Every view already has a real `get*()` fetch function wired to a real same-origin API (with graceful mock-data fallback on fetch failure) — any redesign must keep these functions and their DOM target IDs (or deliberately, visibly migrate them) working, not replace real data with placeholder content.
- **No build step.** Single HTML file, inline CSS/JS, served statically by nginx. A redesign should stay within this constraint unless the user explicitly asks to introduce a build/bundle step.
- **Security-critical escaping.** Every dynamic value rendered into `innerHTML` (alert fields, asset fields, incident entity values) originates from attacker-controlled log content and is passed through an `esc()` HTML-escape helper — this discipline must be preserved in any new markup-generating code, not just the existing call sites.
- **CSS custom-property theming already exists** (`:root` light / `html.dark` overrides) — a redesign should extend this mechanism, not fork a second theming system.
- **Severity semantics are fixed**: `crit`/`high`/`med`/`low` pill classes map to real backend severity levels and are referenced by existing filter logic (`applyAlertFilter`) — renaming or restructuring these classes needs the JS that reads them updated in lockstep.
- Backend is real and running (Docker Compose stack, `make up`); a redesign can be visually verified against live data when Docker is available.

## Brand Commitments

Name: **FENGARDE**. Existing header mark: 🛡️ shield emoji + "FENGARDE Console" wordmark (no dedicated logo asset). No formal brand guide exists — treat the current visual language (generic GitHub-style neutral palette, system font stack) as an *incomplete* brand: functional but not distinctive, open to real expansion rather than a from-scratch replacement of the name/mark.

## Evidence on Hand

No custom illustration, photography, or logo asset beyond the shield emoji. Real data shapes exist for every view (alert, asset, incident, rule/coverage documents) via `services/ws7-dashboard/mocks/mock_data.js` (mock fallback) and the real backend APIs — use these actual field shapes, never invented sample data with different fields.

## Product Principles

- Analyst legibility under stress beats decoration — severity must be scannable at a glance, always.
- Real data or nothing — no visual element implies data the backend doesn't actually provide.
- Preserve the zero-build-step, single-file deployment model.
- Security escaping is non-negotiable in every new render path.
- Extend the existing CSS-variable theme system (light/dark) rather than forking a second one.

## Accessibility & Inclusion

No formal standard has been required of this project to date. Existing UI already uses semantic `<table>`/`<label>`/`aria-label` in places — preserve and extend that baseline; no additional standard confirmed.
