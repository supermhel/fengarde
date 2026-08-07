# FENGARDE — Reality Map (independent full-file audit, 2026-08-07)

**Author:** independent audit pass (all reads by the auditor directly, start-to-finish).
**Scope this reflects:** every file in the public `fengarde` repo (399 tracked files) and
the private `fengarde-sec` repo (69 tracked files) — docs, code, contracts, infra/CI,
tests. **Method:** read byte-for-byte; every claim below was cross-checked against the
code it describes, not taken from a doc's own word. This document is itself a claim on
disk — treat it as such; verify before relying on it.

**HEAD at time of writing:** `f659802` (branch `main`), **2 commits ahead of `origin/main`**
(`aee25bb` + `f659802`), plus **1 uncommitted working-tree change**
(`services/ws2-normalization/enrichment/__init__.py`) and **5 untracked clutter paths**.

> ⚠️ **What changed since earlier audit snapshots:** a large doc-sync pass (SSOT/README/
> CHANGELOG/4 contracts/6 INTERFACEs/deployment/CONTRIBUTING) that was previously
> reported as "13 uncommitted files" has since been **committed** in `aee25bb` + `f659802`.
> So the "repo is behind disk" finding is now narrower: only the **enrichment fix** is
> uncommitted, and the 5 untracked paths remain unignored. Several stale-INTERFACE
> findings in older reports are also **already corrected on disk** (the INTERFACEs are
> now current). This reality map reflects **current disk**, not any earlier snapshot.

---

## 🔴 1. The repo is ahead of GitHub, and one real fix is uncommitted

- Branch `main` is **2 commits ahead of `origin/main`** (`aee25bb`, `f659802`) — not pushed.
- **`services/ws2-normalization/enrichment/__init__.py` has a real, uncommitted fix** for a
  genuine deployed-image bug: it previously used a fixed `_ROOT = parents[3]` to locate
  `contracts/`, which is correct for a local checkout but **wrong inside the built
  container** (the Dockerfile copies `services/ws2-normalization` → `/app/ws2-normalization`,
  so `parents[3]` lands on `/`, and IOC/GEO enrichment silently read `/contracts/...`
  which doesn't exist → **enrichment was always-empty in every deployed image**). The
  fix probes both candidate bases. Hidden because the module's honest fail-open contract
  means it was "never an error, just silently always-empty." **This needs committing.**
- **5 untracked clutter paths are not gitignored:** `.hermes/`, `.obsidian/`, `.worktrees/`,
  `graphify-out/` (7.5M), `IDEA.md`.

## 🔴 2. SSOT.md §3:119 is still stale — in the inverted direction

The row says the INTERFACEs are "partially stale … ws6 is the most stale." On **current
disk every one of them is current**:

| SSOT §3:119 claims | Current disk actually has |
|---|---|
| ws2 "lists 15 parsers, ships 17" | ws2 INTERFACE lists **17** (incl. sysmon, inventory_diff) |
| ws4 "operator list missing in/contains/glob" | ws4 INTERFACE documents all three |
| ws3 "doesn't mention /audit or /auth/mfa/*" | ws3 INTERFACE documents both |
| ws6 "most stale, only basic CRUD" | ws6 INTERFACE lists all 7 modules incl. keystore/authz/MFA/bus_consumer/tenant |

The doc that exists to arbitrate conflicts is itself introducing false staleness.

## 🟠 3. `contracts/triage-api.yaml` is missing `/audit` + `/auth/mfa/*`

The routes exist in code (`triage_api.py` handles `GET /audit`, `POST /auth/mfa/enable`,
`POST /auth/mfa/verify`) and are documented in ws3's INTERFACE, but are **absent from the
OpenAPI spec**. The spec-vs-code CI gate (`test_api_v1.py::test_openapi_spec_get_paths_are_actually_wired`)
only iterates **GET** paths, so these POST routes are invisible to it.

## 🟠 4. Every published rule count is stale (actual = 13 stateful / 15 stateless)

Runtime count from `load_rules()`: **28 rules total, 13 stateful, 15 stateless, 27 MITRE-tagged.**

| Source | Claims |
|---|---|
| README.md:127 | "12/12 stateful rules hold; the **15** stateless" |
| SSOT.md:89 | "12 stateful … the **14** stateless" |
| `fire_check.py` docstring | "14-stateless-untested result" |

Three stale numbers; the engine's own load is the truth (13/15). (Note: `fire_check`'s
27-tagged and README's 15-stateless are closer; the stateful 12 and SSOT's 14 are wrong.)

## 🟠 5. Coverage-gate floors: docs say "88/75", code enforces 88/65/45/40/60

SSOT.md:41 and the audit docs repeat "floors 88/75." The actual `TARGETS` in
`tools/coverage_gate.py` enforce **88.0 / 65.0 / 45.0 / 40.0 / 60.0** (ws2/ws3/ws3-reports/
ws4/ws6). The real gates are fine; the quoted "75" hasn't been enforced since WS-3's floor
was lowered.

## 🟠 6. Version-label inconsistency (no v0.6 tag exists)

- README/SSOT/CHANGELOG consistently say current = **v0.5.0**.
- `SECURITY.md`, `contracts/sigma-convention.md` (`glob` "v0.6, A-Sigma"), and
  `docs/deployment.md` label the M4.2 auth / glob operator as **"v0.6"**.
- `SECURITY.md` "Supported versions" table still lists **"v0.3.0 (latest tag)"** — the real
  latest tag is **v0.5.0** (v0.2.0–v0.5.0 all exist).

That is three docs implying the project is on a "v0.6" with M4.2/glob features, and one doc
implying it is still on v0.3.0 — while the release is v0.5.0.

## 🟡 7. One genuinely stale code comment (now contradicted by shipped code)

- **`services/ws6-inventory/app.py:201-208`** still says "nothing publishes it to
  `raw.events` yet … WS-6 is deliberately stdlib-only … the `ot_new_device_on_segment` rule
  has no live producer." This was superseded by the **M7 Track Y follow-up**: `bus_consumer.py`
  now consumes `assets.updates` and republishes to `raw.events` (redis now opt-in), and the
  rule is `status: stable`. The comment is 1 release stale and contradicts shipped code.
- (`opensearch.py` CAS: module docstring vs inline comment disagree about live-verification;
  the honest state is "wire-format tested, not live-tested" — the `test_storage_cas.py`
  docstring states this correctly.)

## 🟡 8. Stale `ism-events-30d.json` references (file was renamed)

`ism-events-30d.json` was renamed to **`ism-events-common-90d.json`** (Design-A retention
fix), but `ism-events-400d-pci.json` and `ism-events-90d.json` still contain
"see ism-events-30d.json" descriptions pointing at a file that no longer exists.

## 🟡 9. Env vars read by code but undocumented in service INTERFACEs (~15)

The byte-pass over every module found these `os.getenv` reads absent from their
service's INTERFACE.md (non-secret, ops-relevant):
- **ws3**: `PORT`, `STREAM_REAP_INTERVAL_S`, `REPORT_BACKEND`, `REPORT_BACKEND_TIMEOUT`,
  `FENGARDE_SEC_REPORT_URL`, `RATE_LIMIT_REQUESTS_PER_MIN`, `FENGARDE_AUDIT_LOG`/`_MAX_ENTRIES`,
  `FENGARDE_SESSION_SECRET`/`_BACKEND`
- **ws4**: `PORT`, `DETECTION_OUTPUT_DEPTH_WARN` · **ws5**: `PORT`, `OLLAMA_MODEL`
- **ws6**: `PORT`, `INVENTORY_DB`, `INVENTORY_KEYSTORE_DB` · **shared**: `BUS_XREADGROUP_COUNT`

## 🟡 10. Minor items

- `shared/log.py::get_trace_id()` is dead code (no callers).
- `fuzz.yml` corpus-cache `key` uses `run_id` → the primary cache key never hits.
- `events-bank.json`/`events-dc.json` lack the `metadata` mapping `events-common.json` has
  (would be un-indexed under `dynamic:false`).
- Private `fengarde-sec`: `STATUS.md` header date stale (07-23 vs 08-06 corrections);
  `LICENSE` still says ARGUS (renamed 07-16); `eval/README.md` says "Llama Community License"
  (actual: Proprietary); `model-card-v0.md` over-tagged "most detailed"; test-count drift
  (docs 25/11/14 → actual 28); `2026-08-06-ingestion-edge-redundancy.md` untracked.

---

## 🟢 What the full-file review cleared (equally part of the record)

- **Every test is real and self-critical.** No `pass`-stub tests, no tautological asserts;
  `test_fire_check.py` mutates rules to prove the gate turns red, `test_storage_cas.py`
  reproduces the concurrent-writer race deterministically, parser tests feed wrong-typed
  attacker JSON and assert fail-closed.
- **17 parsers / 28 rules / 9 operators / fairness / classifier-tier / MFA / audit / RBAC /
  webhooks / CAS / keystore / HA-failover** are all backed by passing per-feature tests.
- **Private fengarde-sec "no model trained" holds** — zero weight files, every doc consistent.
- The suite is green (111 `[OK]` verified), and the zero-infra gate is honest about the
  live-Docker paths it does not cover.

---

## Recommended priority fix order (one reviewable commit each)

1. **Commit the enrichment fix** + add the 5 `.gitignore` entries + push the 2 in-flight commits.
2. **Rewrite SSOT §3:119** — the INTERFACEs are current, not stale.
3. **Fix the counts** (13/15) in README, SSOT, and fire_check's docstring.
4. **Add `/audit` + `/auth/mfa/*` to `contracts/triage-api.yaml`**.
5. **Reconcile versions** — supported-versions → v0.5.0; align/de-emphasize the "v0.6" labels.
6. **Fix the coverage-floor docs** (88/65/45/40/60).
7. **Fix the stale ws6 comment + opensearch CAS wording + ism refs.**

*This reality map documents current disk state and the honest distinction between what is
proven (suite green, tests real, features wired), what is stale (SSOT §3, counts, versions,
env-var docs, two comments, ism refs), and what needs committing (the enrichment fix).*
