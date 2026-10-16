# FENGARDE console — feature matrix (2026-10-16)

Every capability the backend, the classic console and the open PRs provide, plus what Zabbix / Elestio / Splunk-class tools offer, checked against the new React console (`services/ws7-dashboard/app`, served at `/`; classic console at `/legacy/`).

States: **Built** (in the new console, not yet checked on the live stack), **Live-tested** (proven against the Docker stack), **Missing** (backend exists, no UI yet), **Needs backend** (no API exists; UI alone can't do it), **Decision** (needs the owner's call: security or scope).

## A. Existing backend capabilities

| # | Feature | Backend | Classic console | New console | State |
|---|---|---|---|---|---|
| 1 | Sign-in / sign-out, RBAC roles (read_only, analyst, admin), login rate limit | `/auth/login`, `/auth/logout`, `/auth/me` | yes | Login screen, user chip, sign-out, read_only disables triage | Live-tested |
| 2 | TOTP two-factor enrolment | `/auth/mfa/enable`, `/auth/mfa/verify` | yes | Account view | Live-tested (mfa.mjs: enrol, sign in with a TOTP code) |
| 3 | Tenant scoping | `tenant_id` on rules, incidents, inventory | session tenant | session tenant + admin tenant picker | Live-tested (check.mjs) |
| 4 | Alarm banner, unacknowledged count | alerts feed | no | always-on banner | Live-tested |
| 5 | Alert list: search, priority/status filters, saved filters | `/api/alerts` | yes | Alarms view | Live-tested (check.mjs) |
| 6 | Triage: acknowledge, true/false positive, close, note | `/alerts/{id}/triage` | yes | Alarm detail panel | Live-tested |
| 7 | Alert report + NIS2 draft (3 stages × DE/EN) | `/alerts/{id}/report` | yes | Alarm detail panel | Live-tested |
| 8 | AI triage verdict with engine named | `/api/ai-triage` | yes | Alarm detail panel | Live-tested |
| 9 | "Why it fired": matched source events, raw / OCSF | events feed | partial | Alarm detail panel | Live-tested |
| 10 | Correlated incidents list | `/incidents` | yes | Incidents view | Live-tested (3 incidents from the recorded lab run) |
| 11 | Causal graph | `/incidents/{id}/graph` | yes | Incident detail | Live-tested (graph drawn on the recorded live run; demo.mjs asserts it) |
| 12 | Evidence package, hash-chain verify | `/incidents/{id}/evidence` | yes | Incident detail | Live-tested (demo.mjs asserts Verified; recorded on the live stack) |
| 13 | Incident report (DE/EN, built from the verified evidence package), download .md | `POST /incidents/{id}/report` | no | Incident detail | Live-tested (demo.mjs asserts Verified; recorded on the live stack) |
| 14 | Entity lookup | `/entities/{id}` | no | click a node in the causal graph | Built (not asserted by a script) |
| 15 | Event / log explorer | `/api/events` | table only | query bar, field tokens, facets, histogram, raw/OCSF detail | Live-tested |
| 16 | Events by source | events feed | Sources tab | Overview bars + Sources view | Live-tested |
| 17 | MITRE coverage heatmap + all rules (weight, stateful, enabled, opt-in) | `/rules` | yes | Coverage view | Live-tested |
| 18 | Inventory: assets, filter, live device record, IP history | WS-6 `/assets`, `/assets/{mac}` | yes | Inventory view | Live-tested |
| 19 | API key metadata (never key material) | WS-6 `/keys` | yes | Inventory view | Live-tested |
| 20 | Pipeline monitor (collect → normalize → detect → correlate → index) | `/api/ops/ws*` | Monitoring tab | Overview + Operations mimic | Live-tested |
| 21 | Per-service health: topic counters, dead letters, rule last fired | `/api/ops/ws*` | Ops tab | Operations view | Live-tested |
| 22 | Admin audit trail | `/audit` | yes | Audit view | Live-tested |
| 23 | Time range, DE/EN, light/dark, mobile layout | — | partial | top bar | Live-tested |

## B. Needed for Zabbix / Elestio parity

| # | Feature | What exists | Plan | State |
|---|---|---|---|---|
| 24 | Device onboarding: "connect a device", copy-paste config, wait for first event | WS-1 UDP syslog `:5514` (stamped `generic_syslog`), `tools/agent_log_shipper.py` for structured sources | Sources view stepper; honest that syslog senders do not create Inventory devices (Inventory is MAC-keyed, fed only by `assets.updates`) | Live-tested 2026-10-16 (a real UDP syslog line is detected as the first event, including lines routed to linux_ssh, cisco_asa, cef, dns_query) |
| 25 | Add a device to Inventory by hand | WS-6 `POST /assets/upsert` exists; nginx proxies `/api/inventory/` as GET-only on purpose | Opening an admin-only, CSRF-protected write route through nginx | API live-tested 2026-10-15 (admin adds device -> WS-6 -> readable; analyst refused; bad MAC 400). test_inventory_write.py. Browser form: Live-tested 2026-10-16 (check.mjs adds a device through the form) |
| 26 | Silent-source alarm ("no data from X for N min", Zabbix `nodata`) | WS-1 silence watchdog (log line), per-source last-seen derivable from events | Sources view flags a source silent after 15 min; WS-1 per-sender counters shown | Built (silence threshold not exercised live) |
| 27 | System health: host / container metrics | Prometheus (`:9090`) and Grafana (`:3000`) in the compose stack, localhost only | read-only nginx route to Prometheus targets + queries, System health panel, link to Grafana | Panel Live-tested in its unreachable state (Prometheus not running); the populated state is not proven |
| 28 | Notification channels (webhooks) | `contracts/webhooks/*.yml`, `webhooks.py`; config is file-based, no API | read-only list needs a backend route | API live-tested 2026-10-15 (redacted list). test_admin_api.py. Browser panel: Live-tested 2026-10-16 (check.mjs) |
| 29 | Enable / disable a rule per tenant | `rules_view.py` computes `enabled`; no write API | read-only today | Live-tested 2026-10-15: PUT off -> rules view enabled=false and WS-4 (other container, ro volume) disables it; back on reverts. test_admin_api.py, ws4 test_tenants.py. Browser switch: Live-tested 2026-10-16 (check.mjs flips a rule off and on) |
| 30 | User management | `UserStore` via CLI only | no API | API live-tested 2026-10-15 (create, role, disable blocks sign-in, short password 400, last-admin 409). test_admin_api.py. Browser panel: Live-tested 2026-10-16 (check.mjs) |
| 31 | Report download (.md) | report text in UI | Download .md on alarm and incident reports | Live-tested (demo.mjs, recorded reports) |
| 32 | Custom dashboards / widgets | — | out of scope for v1 | Decision |

| 33 | Live syslog reaches the specific parsers (sshd, Cisco ASA, CEF) | WS-1 stamps every UDP datagram `generic_syslog` and WS-2 trusts it, so sshd/ASA/CEF never reach their parsers and the SSH brute-force rule cannot fire on forwarded logs | WS-2 content detection when the label is the generic UDP one; explicit source types stay authoritative | Live-tested 2026-10-15: 12 UDP sshd lines on 5514 -> 12 linux_ssh events -> brute-force alert (high); syslog-wrapped CEF -> cef 3002 Failure. Tests: services/ws2-normalization/test_syslog_udp_routing.py (10) |
| 34 | RFC 5424, TCP/TLS syslog, live SNMP/NetFlow | not implemented (SNMP/NetFlow read mock files) | named as not connectable on the Sources page | Needs backend |

## C. Features arriving with open PRs

| PR | Feature | UI impact | State |
|---|---|---|---|
| #96 | Public detection benchmark (`benchmark/`, results + trend viewer), OpenSSF badge, DCO, funnel CTA | Detection-quality summary in the console; Pages site already links it | Missing (after merge) |
| #97 | Classic console keeps the open incident across the 10 s refresh | New console already keeps it; shows "incident left the loaded list" when it ages out | Built |
| #93 | R3 injection-evasion hardening, eval phases 5–7 | none (backend + eval) | n/a |
| #94, #95 | GitHub Actions bumps | none | n/a |

## D. Found and fixed by driving the console on the live stack (2026-10-15/16)

| Bug | Symptom | Fix and regression test |
|---|---|---|
| Sessions invalidated under load | About 70% of parallel requests got 401: `UserStore` reads shared one SQLite connection without the lock, visible once every request re-checked the account | Reads take the lock. `services/shared/test_users_threading.py` |
| WS-6 intermittent 500s | `/assets` and `/keys` failed under parallel GETs (same shared-connection class) | Locked reads. `ws6-inventory/test_store_threading.py` |
| WS-6 dropped `sector` and `type` | Devices added by hand came back with both null | Stored, validated, kept across observations that omit them. `test_upsert_attrs.py` |
| MFA accounts could not sign in | The new sign-in had no code field | Code field, same 401 for missing or wrong code. `tools/console_e2e/mfa.mjs` |
| Sources missed routed lines | First-event check expected `generic_syslog` after WS-2 started routing to specific parsers | Matches `linux_ssh`, `cisco_asa`, `cef`, `dns_query` and shows the real type. `check.mjs` |
| Fonts blocked | CSP has no `font-src data:` and the bundler inlined the fonts | Real font files (`assetsInlineLimit: 0`) |
| Settings dates wrong | `last_login_at` is epoch seconds, read as milliseconds | Converted. `check.mjs` |
| Causal-graph edges looped outside boxes; mobile overflow; chart colour inherited the rail | Visual | Edge routing, wrapping, scoped colour |

Checks: `check.mjs` 90, `mfa.mjs` 7, `demo.mjs` 18, `pages.mjs` 57 (all against the live stack or the static builds; see `tools/console_e2e/README.md`).
