# Console end-to-end checks, screenshots, demo fixtures and recordings

Scripted-browser tooling for the rebuilt console (`services/ws7-dashboard/app`), run against a **live Docker
stack**, not mocks. It produced the screenshots, the recordings and the demo data on the project page
(`docs/index.html`), and it found real bugs while doing it (see CHANGELOG, "Fixed").

| Script | What it does |
|---|---|
| `check.mjs` | Signs in as admin, analyst and read_only and walks every view: renders, role gating (no Settings, add-device form or rule switches for non-admins), dark theme, German, 390 px width without horizontal overflow, no unexpected API errors, no uncaught page errors. As admin it creates and disables a user, adds a device, flips a rule off and on, and runs the Sources first-event flow with a real UDP syslog line. `node check.mjs [shotDir]` |
| `mfa.mjs` | Enrols a throwaway user in MFA, computes a TOTP code, and signs in **through the real form** with it (a missing code is refused). |
| `demo.mjs` | Checks the static demo build (`docs/demo`): quiet start, replay, incident, evidence "Verified", recorded NIS2 report, local-only writes, reset, German, phone width. Needs `python -m http.server 8099 --directory docs`. |
| `pages.mjs` | Checks the project page: board, ticker, seven reasons, all 29 rules, nine linked architecture boxes that light on replay, four chapters play, DE/EN, no third-party requests, phone width. Same static server. |
| `shots.mjs` | Deliberate screenshot states of each view. `node shots.mjs <outDir>` |
| `record_fixtures.mjs` | Records the demo's fixtures from the live stack (`src/demo/fixtures.json`). See `docs/console-demo.md`. |
| `tour.mjs` | Records the "attack to evidence" video: a real two-stage attack over UDP 5514 while recording. |
| `chapter_access.mjs`, `chapter_triage.mjs`, `chapter_onboard.mjs` | The other recorded chapters: sign-in to settings, analyst triage with the NIS2 draft in German, connecting a device. Built on `tourlib.mjs` (frames from the browser's screencast, encoded by the system `ffmpeg`; no extra binary is downloaded). |
| `close_alarms.mjs` | Closes open high alarms so a recording starts from a quiet banner. |

## Run

```sh
cd tools/console_e2e
npm install                      # playwright-core only; it drives your installed Chrome/Chromium/Edge
node check.mjs
```

Needs the stack up with RBAC on and three local test accounts in a **gitignored** env file (default
`infra/.env.local-test`):

```
FENGARDE_TEST_ADMIN_USER=...      FENGARDE_TEST_ADMIN_PASSWORD=...
FENGARDE_TEST_ANALYST_USER=...    FENGARDE_TEST_ANALYST_PASSWORD=...
FENGARDE_TEST_READONLY_USER=...   FENGARDE_TEST_READONLY_PASSWORD=...
```

Passwords are read in-process and never printed. Environment overrides: `FENGARDE_URL` (default
`http://127.0.0.1:8080`), `FENGARDE_ENV_FILE`, `CHROME_PATH`, `FENGARDE_E2E_OUT`, `FENGARDE_DEMO_URL`,
`FENGARDE_PAGES_URL`.

## Notes

- **Local dev stacks only.** `check.mjs`, `mfa.mjs` and the chapters create users and add devices; the traffic
  scripts send unauthenticated UDP syslog to port 5514. Never point them at a stack you do not own.
- They leave small debris: disabled `ui-e2e-*` users (the Settings view hides disabled accounts by default),
  `e2e-sensor-*` devices, a `night-shift` user from the access chapter. Remove by hand if a screenshot needs
  a clean Inventory.
- `mfa.mjs` waits up to 30 s: WS-3 refuses to reuse the TOTP code spent at enrolment within the same time step.
- The attack traffic comes from `tools/console_tour_traffic.py`.
