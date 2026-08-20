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

## Amplification pass (2026-08-19, `bolder`)

The 4 global stat cards (Overview view) had quietly opted out of the system's own two strongest existing devices: the `icon()`/`ICONS` helper (used everywhere else — sidebar, severity pills, posture panel) and the `--crit`/`--high`/`--med`/`--low` severity token family (used everywhere else a severity concept appears). Fixed by amplifying, not inventing:

- **3 new `ICONS` entries** (`devices`, `warn`, `link`), same single-stroke vocabulary as the 4 already there. Total Alerts reuses the existing `pulse` icon rather than adding a 4th.
- **`.card-icon` chip** (26px rounded-square, `--accent-soft`/`--accent` by default) on every stat card's `.card-top`, wrapped with the label in a new `.card-head` flex span so the existing delta badge still sits opposite it via the untouched `justify-content:space-between`.
- **`.card.tone-crit` modifier**, applied only to the Critical Alerts card: retints its icon chip, delta badge, and sparkline bars from the neutral accent to `--crit`/`--crit-soft` — the same red family `.pill.crit` already uses. The one card whose entire subject IS a severity level now says so in the system's own strongest existing signal, instead of blending into the neutral cards next to it. No other card was touched — Active Devices/Total Alerts/Correlated Incidents stay on the neutral accent, since none of them is a single severity concept.

Verified in both themes via computed style (`.card.tone-crit .card-icon` resolves to `--crit`'s light AND dark value correctly) and live on the Docker stack. Sidebar active-state (`.sidebar nav button.active{background:var(--side-accent)}`) was reviewed and left untouched — already a solid-fill highlight, not the weak/missing state the original comparison assumed from a cramped screenshot.

## New components (2026-08-19/20, real-data-gap closures)

Three additions, each closing a gap where real backend data existed but the dashboard never queried or surfaced it — same "real data or nothing" discipline as everything else in this file, nothing decorative added.

- **MITRE tag chip on every alert row** (`.tag-chip`, new — quiet inline-code treatment, generalized from `.lifecycle-hint code`'s existing pattern rather than a new visual primitive). Deliberately NOT accent-colored: an informational tag competing with the severity pill for attention would be noise, not signal (Operate mode: accent is reserved for actions/selection/state).
- **"Why" disclosure per alert row** (`details.why`, same `<details>` idiom the existing Playbook disclosure already established): MITRE tactic/technique, AI triage verdict when a real one was computed (never an empty "AI triage:" line for the classifier-only tier, which carries no verdict by design), and the rule's contributing `event_ids`. Nothing renders when none of the three are present.
- **Incidents view: list + detail** (`showIncident()`), same click-a-row-see-a-panel pattern `showAsset()` already established for Inventory — `.detail`/`.kv` reused verbatim, one new `.tactic-chip` (accent-colored, deliberately — a promoted tactic IS the reason the incident exists, closer to a state indicator than a passive tag).
- **Raw event browser** ("Events" nav tab) and a **header time-range picker** (1h/24h/7d/30d) scoping both the alert feed and the event browser. New nav icon (`list`-style, 3 lines + dots, matching the existing hand-authored sidebar SVG vocabulary, not the JS `icon()` helper since sidebar buttons are server-rendered markup).

All four reuse `getAlerts()`/`getEvents()`/`getAiTriage()`'s existing try/fetch/fallback shape and the `esc()` escaping discipline on every dynamic value. A real regression was found and fixed mid-build, not shipped and forgotten: the time-range picker's first version sent a semantic `range=24h` string for nginx to translate into OpenSearch date-math server-side, which silently failed (partial-shard-failure, HTTP 200) against both indices' strict `epoch_millis`-formatted `time` field — moved the "what does 24h mean" computation client-side (`rangeGteMs()`) instead, nginx now only regex-validates an already-numeric value.

## Engine tag (2026-08-20)

The Why panel's "AI triage" line previously showed a verdict with no way to tell whether Ollama or the offline StubLLM produced it — both emit the exact same `{verdict, summary, level}` shape. `services/ws5-ai/llm_adapter.py` now stamps `engine`/`model` on every `analyze()` return (`"ollama"`+model name, or `"stub"`, `FallbackLLM` passes through whichever actually ran, never the configured primary), threaded through `main.py::_alert_payload` into `alert.ai.engine`/`alert.ai.model`. `whyDetailsHtml()` renders it inline: `AI triage (high, ollama:qwen2.5): malicious -- ...` when present, degrades gracefully (no engine segment) on pre-upgrade alert docs that predate the field. Real data, not inference from the dashboard's side — the tag says what actually ran, not what was configured to run.

## Full backend wiring pass (2026-08-20)

An 8-workstream audit found every remaining real backend capability the dashboard never surfaced. Closed as a batch, reusing existing components throughout — no new visual language introduced, matching every prior round's discipline in this file.

- **Ops view** (new nav tab, new icon): one generic card-per-service renderer over the uniform `{service, topics, extra}` shape `services/shared/runner.py`'s `/metrics` already exposes on every workstream — reuses `.card`/`.playbook-body`, no bespoke per-service layout.
- **Audit view** (new nav tab, new icon): the E1 admin trail in a plain table, same `<table>` pattern as every other list view. Empty-state handles both "not an admin" and "nothing logged yet" without distinguishing them (the backend itself doesn't distinguish a 403 reason from an empty log at the UI's information level).
- **MFA enrollment panel** (`#mfaPanel`): same `.detail` floating-panel pattern `#reportPanel` established, opened from a new "Security" button next to Sign out. No QR renderer — this project's single-file/no-build constraint rules out a library, so the otpauth secret is shown as literal text (a QR code encodes nothing else).
- **API keys panel**: a collapsed `<details>` inside the existing Inventory view (reuses the Playbook disclosure's exact treatment) rather than a new nav tab — operational detail an analyst doesn't need open by default.
- **All-rules table**: extends the existing Coverage view with a plain table for `enabled`/`score_weight`/`stateful` — fields the heatmap's own data source (`GET /rules`) already carried but never rendered.
- **NIS2 stage/language selectors**: two `<select>` elements inside `#reportPanel`, styled via the existing `input,select` token rule — no new control primitive.
- **Why panel additions**: classifier and reputation lines follow the exact line-per-fact pattern the panel already used for MITRE/AI-triage/contributing-events — nothing new, same `<details>`/`playbook-body` shell.

The one real, previously-silent bug this pass fixed: `window.INVENTORY_API` had no default value, unlike every other `*_API` constant in the file — the Inventory view rendered mock assets on every single deployment since it shipped. Fixed to match the established default-to-same-origin-proxy pattern.

## QA pass on the full wiring round (2026-08-20)

Owner hand-tested the round above and reported two things "broken." Investigation found the dropdown genuinely worked (verified: alert count went 50→0 on "last hour") — the real defect was scope-without-signal: the picker only ever governed 2 of what are now 8 views, silently doing nothing on the rest with zero indication why. Fixed as a system rule, not a one-off patch: `RANGE_SCOPED_VIEWS` + `syncRangeSelectState()` either extends real filtering to a view (Incidents by `last_seen`, Audit by `ts`, Sources by its now-real event-derived counts) or visibly disables the control with an explanatory tooltip when a view is current-state, not historical (Inventory/Coverage/Ops). Empty-state messaging was missing entirely on the alert table — a range that zeroed it out looked identical to broken; now every range-scoped view names the active range in its own empty message.

Ops was a confirmed bug, not a false alarm: `services/shared/runner.py`'s `extra` payload nests 3 levels deep for WS-1 (`syslog_udp.per_source.{ip}.{stat}`); the first formatter only unwrapped 2, so the 3rd silently stringified to `[object Object]` and, compounded by a `.k` label column with no `overflow-wrap`, visually collided with the adjacent value. Rewritten as a genuinely recursive value renderer (any depth) plus `overflow-wrap:anywhere` — confirmed via `getBoundingClientRect()` after a requested screenshot caught it, not instead of one.

## Screenshot/video product tour (2026-08-20)

`docs/index.html` (GitHub Pages) + a matching self-contained Claude artifact, built from the SAME template: 8 real screenshots captured off the live stack via headless Chrome (`--virtual-time-budget` — the naive first pass screenshotted before the async fetches resolved and caught "mock data"/empty panels instead of live state) assembled with `ffmpeg` (zoompan + xfade) into a 16s video. Visual language deliberately reuses the console's own component system — each screenshot sits in a bezel styled like the product's own `.card`/`.detail` panel (border, radius, shadow), not a generic browser-chrome mockup frame, so the page reads as "built from FENGARDE's own pieces" rather than a separate marketing artifact. Typography (Fragment Mono display + Public Sans body) and a dark-committed palette pulling the product's own indigo accent (`#818cf8`) and severity hues were chosen deliberately against the AI-cliché list (no Inter, no warm-cream-serif, no purple-gradient hero) — full plan and rationale in the artifact-design pass that produced it. One small, real dashboard feature came out of building this: hash-based deep-linkable nav (`#ops`, `#audit`, ...), needed to screenshot each tab reliably, kept because it's genuinely useful on its own.

## Fix (2026-08-20)

`.report-btn`/`.nis2-btn`/`#reportClose` were raw unstyled `<button>` elements — every other actionable control in this file (filterbar, login, logout, theme toggle) already ran through the token system, these three never got the same pass and rendered as the browser's default grey/bevel button. Fixed with a shared ghost style (`transparent` bg, `--border` outline, `--muted` text, `--accent` on hover) matching `#logoutBtn`'s existing secondary-action tier. Rebuilt and live-verified on the Docker stack: `getComputedStyle` on `.report-btn` now resolves `background: rgba(0,0,0,0)`, `border: 1px solid var(--border)`, `border-radius: 7px` instead of the UA-default outset bevel.

## Verified

Live-verified against the real Docker stack (2026-08-19): real alert (brute-force detection) rendered with correct severity pill and real source IP; System Posture panel showed real values (`Live pipeline data: connected`, `RBAC session gate: disabled`, `28 rules`, `96% MITRE-tagged coverage`); Top Sources panel showed the real attacker IP with a real `CN` country badge; Incidents view rendered its stat-card row and empty state correctly (0 incidents, correct — only one alert existed, no promotion expected); dark/light toggle confirmed via computed styles (sidebar stays dark in both themes, canvas flips). Both static contract tests pass unchanged. Pixel-level screenshot verification was not available this session (Browser pane policy-blocks `localhost`, Chrome extension disconnected; worked around via `127.0.0.1` for functional checks, but no screenshot could be captured) — a real gap, not silently skipped: a full visual (pixel) inspection round is still owed before calling this finished.
