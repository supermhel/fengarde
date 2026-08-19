# Design

<!-- impeccable:design-schema 1 -->

## Surface

`services/ws7-dashboard/index.html` — the FENGARDE console (single static file, no build step, nginx-served, real backend). Redesigned 2026-08-19, brief-pinned by two user-supplied reference screenshots (light security-console dashboard: dark sidebar rail, sparkline stat cards, world map + tooltip, compliance checklist) plus explicit answers: anchor on the light-console reference, redesign the whole dashboard, keep the four severity colors' meanings.

## World

**Fixed dark icon-rail sidebar + light neutral canvas.** The sidebar (`--side-*` tokens) stays dark charcoal in both light and dark content themes — a deliberate brand-chrome decision, not tied to the `html.dark` toggle. One indigo accent (`--accent: #4f46e5` light / `#818cf8` dark) chosen specifically to stay clear of the four reserved severity hues (crit red, high orange, med amber, low green) so UI accent and security semantics never collide.

## Tokens

- `--bg`/`--panel`/`--border`/`--txt`/`--muted`/`--rowhover` — canvas, cards, dividers, text.
- `--accent`/`--accent-ink`/`--accent-soft` — UI accent (buttons, active nav, links, delta badges), never used for severity.
- `--crit`/`--high`/`--med`/`--low` + `-soft` variants — severity pill/badge colors, preserved from the incumbent palette (same hue families: red/orange/amber/green) per the "keep current color meanings" constraint.
- `--side-bg`/`--side-txt`/`--side-active-bg`/`--side-border`/`--side-accent` — fixed dark sidebar chrome, independent of the content theme.
- `--shadow` — one soft dual-layer card shadow, consistent across all panels/cards/tables.

## Type

System stack (`-apple-system, "Segoe UI", Roboto, sans-serif`) — Operate-mode surface, workhorse UI face by design, not a training-data default reached for without cause. Stat numbers 30px/800 weight with `tabular-nums`; section headers 14px/700; body/table 13px; labels 10.5–11.5px uppercase tracked.

## Icons

Inline single-stroke SVG (`icon()` helper + `ICONS` map, 1.6–1.8px stroke, `currentColor`), replacing every emoji (🛡️/🌙/☀️) in the incumbent markup. No icon library dependency — self-authored to keep the single-file, no-build constraint.

## Components

- **Stat card** (`.card`): label, big number, and (where the underlying data supports it honestly) a real 24h-bucketed sparkline (`sparklineHtml()`) and a real 24h-vs-prior-24h delta badge (`deltaHtml()`) — both computed client-side from already-fetched alert/incident timestamps, never fabricated. A card with no meaningful trend (Active Devices — a snapshot, not a time series) gets a ratio bar instead of a fake sparkline.
- **System posture panel** (`#postureList`): a checklist of real signals only — live-vs-mock data, RBAC on/off, rules-loaded count, MITRE-tagged coverage % — no invented compliance percentages.
- **Top sources panel** (`#sourcesRank`): ranked real `src_endpoint.ip` values from the currently loaded alerts, with a hover tooltip (alert count, top rule, last seen) built from data already in hand. **Deliberate substitute for a literal geo-pin world map**: `contracts/enrichment/geoip.yml` only covers a handful of demo CIDR ranges, not a real GeoIP database, so a map implying worldwide location coverage would show data the backend doesn't actually have for most deployments. The country badge still renders when `src_endpoint.location.country` happens to be present (proven live: a real alert from a demo CIDR entry correctly showed a `CN` badge).
- **Severity pill** (`.pill.crit/.high/.med/.low`): unchanged semantics, now icon-prefixed (check for low, circle otherwise) and using the `-soft` background tokens.

## What stayed untouched

Every real API call (`getAlerts`, `getAssets`, `getRules`, `getIncidents`, `checkSession`, `updateTriage`, report generation), every element id/class/localStorage key the static contract tests (`test_contract.py`, `test_fix_ux.py`) assert on, the `esc()` HTML-escaping discipline on every dynamic value, the CSS-custom-property theming mechanism, and the single-file/no-build deployment model.

## Verified

Live-verified against the real Docker stack (2026-08-19): real alert (brute-force detection) rendered with correct severity pill and real source IP; System Posture panel showed real values (`Live pipeline data: connected`, `RBAC session gate: disabled`, `28 rules`, `96% MITRE-tagged coverage`); Top Sources panel showed the real attacker IP with a real `CN` country badge; Incidents view rendered its stat-card row and empty state correctly (0 incidents, correct — only one alert existed, no promotion expected); dark/light toggle confirmed via computed styles (sidebar stays dark in both themes, canvas flips). Both static contract tests pass unchanged. Pixel-level screenshot verification was not available this session (Browser pane policy-blocks `localhost`, Chrome extension disconnected; worked around via `127.0.0.1` for functional checks, but no screenshot could be captured) — a real gap, not silently skipped: a full visual (pixel) inspection round is still owed before calling this finished.
