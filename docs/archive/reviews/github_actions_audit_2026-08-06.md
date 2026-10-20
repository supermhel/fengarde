# FENGARDE SIEM — GitHub Actions & CI/CD Security Audit

**Date:** 2026-08-06  
**Repo:** `github.com/supermhel/fengarde` · HEAD `d701c2f`  
**Scope:** All `.github/workflows/*.yml`, Dependabot, gitleaks, pre-commit, action-pin verification, SBOM generation, supply-chain tooling

---

## Overall Grade: **A−** (exceptional for open-source, 2 gaps)

FENGARDE's CI/CD pipeline is **among the strongest I've audited in open-source**. Every action is SHA-pinned with verified tag comments. Permissions are least-privilege throughout. Secret scanning + CVE audit + CodeQL + Scorecard + actionlint + action-pin-verify all run blocking. The `verify_action_pins.py` script's "treat network failure as FAIL" design is genuinely non-gamable — the sort of detail most projects don't think about.

Two gaps prevent an A+: (1) the `devkit-feeder` service escapes both pip-audit AND SBOM coverage, and (2) Redis-critical test suites (`sessions.py`, `window.py`) are never run against real Redis in CI while their backends are the exact surface that fixes multi-replica bugs.

---

## Finding Tally

| Severity | Count | Summary |
|---|---|---|
| **HIGH** | **2** | devkit-feeder escape (pip-audit + SBOM), Redis backends CI-untested |
| **MEDIUM** | **4** | `\|\| true` fail-open builds, mutmut non-blocking, no OpenSearch service in CI, gitleaks in CI-only (not pre-commit) |
| **LOW** | **4** | mypy loose strictness in CI, coverage excludes security modules, fuzz covers 3/17 parsers, dependabot gaps |
| **INFO** | **5** | Well-documented gate limitations, honest baselines not targets, UUID allowlist justified, matrix Python version skew, verify_action_pins limitation documented |

---

## Per-Workflow Audit

### 1. `ci.yml` — Main CI Pipeline

| Check | Status | Detail |
|---|---|---|
| Action pinning | ✅ **A+** | Every `uses:` is SHA-pinned to 40-char commit with verified comment |
| Permissions | ✅ **A** | `contents: read` top-level; no job escalates |
| Gitleaks | ✅ **A** | Full history scan (`fetch-depth: 0`), blocking |
| Contract tests | ✅ **A** | Zero-infra, `run_all_tests.sh`, blocking |
| Redis integration | ⚠️ **B−** | Real Redis service container — excellent. But runs ONLY `test_runner.py`, `test_bus_trim_acked.py`, `test_bus_lag.py`, `test_bus_read_count.py`. Missing: `test_sessions.py` (Redis session backend), `test_window.py` (RedisWindowCounter). `SESSION_TEST_REDIS=1` env var appears **nowhere** in CI. |
| ruff | ✅ **A** | Blocking, zero findings |
| mypy | ⚠️ **B−** | Blocking at 0 errors — but runs with `--ignore-missing-imports` only, no `--strict`/`--disallow-untyped-defs`. `pyproject.toml:42-58` has only `python_version` + `ignore_missing_imports`. Untyped security functions pass cleanly. |
| Coverage gate | ⚠️ **B** | Blocking at measured baselines — honest. But covers only WS-2 + WS-3. Security-critical modules (`sessions.py`, `bus.py`, `runner.py`, `window.py`, `keystore.py`) are OUTSIDE the coverage source. Gate measures execution, not assertion. |
| mutmut | ⚠️ **C** | Informational only (`\|\| true`), scoped to 1 file (`sessions.py` memory backend), not blocking. Honest disclosure but no mutation-testing enforcement. |
| SBOM freshness | ✅ **A−** | Blocking check. `generate_sbom.py --check` fails if `sbom.json` is stale. **But:** excludes `devkit-feeder` explicitly (H1 below). |
| pip-audit | ⚠️ **B** | Blocking with `--strict`. Loops `services/*/requirements.txt`. **But:** `devkit-feeder` has no `requirements.txt` (inline `pip install` in Dockerfile) → invisible. |
| docker-build | ⚠️ **B−** | Builds all images — excellent that it exists. **But:** Dockerfiles use `pip install ... \|\| true` (fail-open). A broken dep install passes CI green. |
| attack-scorecard | ✅ **A−** | MITRE empirical firing check + boundary-probe sensitivity tests — both blocking. Strong design. |
| actionlint + pin verify | ✅ **A+** | Best-in-repo. actionlint catches malformed workflows. `verify_action_pins.py` treats **network failure as FAIL** (non-gamable), checks SHA pins AND tag comment correctness, handles annotated tag peeling. This is genuinely impressive. |

**CI grade: B+** (A-grade process, dragged down by the specific missing test coverage and fail-open patterns)

---

### 2. `codeql.yml` — Static Analysis

| Check | Status | Detail |
|---|---|---|
| Query level | ✅ **A** | `security-extended` (the higher tier above `default`) |
| Triggers | ✅ **A** | PR + push:main + weekly cron |
| Permissions | ✅ **A** | File-level least-privilege: `contents: read` top, `security-events: write` job-scoped |
| SHA-pinned | ✅ **A** | `f205ea1c...` (v4.37.4) — verified by verify_action_pins.py |

**CodeQL grade: A**

---

### 3. `scorecard.yml` — OpenSSF Scorecard

| Check | Status | Detail |
|---|---|---|
| SHA-pinned | ✅ **A** | All actions pinned |
| PR trigger absent | ✅ **Design** | Deliberate — Scorecard needs `id-token: write` which must not be available on PR. `workflow_dispatch` allows post-merge testing before cron. |
| persist-credentials | ✅ **A** | `false` on checkout |
| Permissions | ✅ **A** | `read-all` top, `security-events: write` + `id-token: write` job-scoped |
| SARIF upload | ✅ **A** | Results uploaded to CodeQL dashboard |

**Scorecard grade: A**

---

### 4. `fuzz.yml` — Nightly Atheris Fuzzing

| Check | Status | Detail |
|---|---|---|
| Schedule | ✅ **A** | Nightly, off-peak (03:17 UTC), `workflow_dispatch` manual trigger |
| Matrix | ✅ **A** | `fail-fast: false` — one parser crash doesn't kill the others |
| Corpus cache | ✅ **A** | Per-target cache with run-ID key + restore-keys fallback |
| Crash artifact | ✅ **A** | Uploads crashing inputs on failure |
| Coverage | ⚠️ **C** | Only 3 of 17 parsers fuzzed (linux_ssh, cisco_asa, windows_eventlog). Honestly disclosed as "top 3" but the other 14 parsers — including the security-critical `db_audit` that has the `GRANT SELECT` bug — are never fuzzed at all |
| Blocking | ✅ **Design** | Nightly, not blocking PR (correct for fuzzing) |

**Fuzz grade: B+** (excellent setup, narrow scope honestly documented)

---

## Supply-Chain Tooling

### Dependabot (`.github/dependabot.yml`)

| Check | Status | Detail |
|---|---|---|
| pip ecosystems | ⚠️ **B** | 6 services covered: ws1 through ws6. **Missing:** `devkit-feeder` (no `requirements.txt` directory to point at) |
| github-actions | ✅ **A** | `/` directory covered |
| Schedule | ✅ **A** | Weekly for all |

### Gitleaks (`.gitleaks.toml`)

| Check | Status | Detail |
|---|---|---|
| Default rules | ✅ **A** | `useDefault = true` — all real secret detectors stay on |
| UUID allowlist | ⚠️ **B** | `[0-9a-fA-F]{8}-...{12}` — allows ALL UUIDs repo-wide. Justified: rule `id:` fields are public UUIDs committed intentionally. But broad: a real API key accidentally formatted as UUID (unlikely but possible) would be silently suppressed |
| pre-commit hook | ❌ **Absent** | Gitleaks runs in CI only. A secret committed and pushed is caught — but the developer doesn't know until CI runs. No local pre-commit hook for instant feedback |

### Pre-commit (`.pre-commit-config.yaml`)

| Check | Status | Detail |
|---|---|---|
| Ruff | ✅ **A** | `v0.15.21` SHA-pinned hook, `--fix` enabled |
| Standard hooks | ✅ **A** | end-of-file-fixer, trailing-whitespace, check-merge-conflict, check-yaml |
| Missing hooks | ⚠️ | No gitleaks, no mypy, no black. mypy/black omission documented and justified (untyped codebase would train `--no-verify`); gitleaks omission is not documented |

### Action-Pin Verification (`tools/verify_action_pins.py`)

| Check | Status | Detail |
|---|---|---|
| SHA-pin check | ✅ **A+** | Fails on floating tags |
| Comment honesty | ✅ **A+** | Tag comment must resolve upstream to pinned commit |
| Network failure | ✅ **A+** | Treated as FAILURE, not skip — non-gamable |
| Annotated tags | ✅ **A+** | Correctly peels `refs/tags/X^{}` for annotated tags |
| Scope limitation | ✅ **Honest** | Docstring states: "proves pins RESOLVE, not that an action still BEHAVES" |

This script is **the single strongest CI artifact in the repo**. It's the kind of self-referential quality gate most projects don't think to write.

### SBOM Generator (`tools/generate_sbom.py`)

| Check | Status | Detail |
|---|---|---|
| CycloneDX output | ✅ **A** | Standard format |
| Runtime-only deps | ✅ **A** | Test deps excluded (correct — SBOM = "what ships") |
| `--check` mode | ✅ **A** | Blocking in CI |
| devkit-feeder | ❌ **Gap** | Explicitly excluded at line 29-31. Documented but still a gap |

---

## HIGH Findings

### H1 — devkit-feeder escapes pip-audit AND SBOM

`services/devkit-feeder/Dockerfile:4`:
```dockerfile
RUN pip install --no-cache-dir redis==5.0.8
```

- **No `requirements.txt`** → `ci.yml:146` `for req in services/*/requirements.txt` loop never finds it → pip-audit never audits it
- **Explicitly excluded** from `generate_sbom.py:29-31` → SBOM has no record of `redis==5.0.8`
- **Version skew**: devkit-feeder pins `redis==5.0.8` while 5 other services pin `8.1.0`
- **Impact**: A CVE in `redis==5.0.8` ships undetected for months. The SBOM is incomplete by design.
- **Severity**: HIGH
- **Fix**: Add `services/devkit-feeder/requirements.txt` with `redis==5.0.8` (or bump to 8.1.0 to match). Add to SBOM generator's `REQUIREMENTS_FILES` list.

### H2 — Redis-critical test suites never run against real Redis in CI

`.github/workflows/ci.yml:50-87` (`redis-integration` job):
```yaml
- name: Runner ack + XAUTOCLAIM redelivery + DLQ on real Redis
  run: python services/shared/test_runner.py
- name: P0-5 acked-stream reaper (trim_acked) on real Redis
  run: python services/shared/test_bus_trim_acked.py
- name: P1-7 real consumer backlog signal (lag) on real Redis
  run: python services/shared/test_bus_lag.py
- name: P1-8 XREADGROUP batch size on real Redis
  run: python services/shared/test_bus_read_count.py
```

Missing from this job:
- `services/shared/test_sessions.py` — `RedisSessionStore` (session-auth boundary)
- `services/ws4-detection/test_window.py` — `RedisWindowCounter` (stateful detection)

`test_sessions.py:33` gates on `SESSION_TEST_REDIS=1`:
```python
if os.getenv("SESSION_TEST_REDIS", "0") != "1":
    ...
    _BACKENDS.append(("redis", None))  # prints [SKIP]
```

`SESSION_TEST_REDIS=1` appears **nowhere** in `.github/workflows/`. And `test_window.py` tests `RedisWindowCounter` against a hand-rolled `_FakeRedis`/`_FakePipe` — the production backend that fixes multi-replica counting bugs is never tested against real Redis.

- **Impact**: A real behavioral bug in Redis session storage or Redis window counting passes CI green. These two backends exist specifically to fix multi-replica defects.
- **Severity**: HIGH
- **Fix**: Add `test_sessions.py` and `test_window.py` to the `redis-integration` job with `SESSION_TEST_REDIS=1`.

---

## MEDIUM Findings

### M1 — Dockerfiles use `|| true` on pip install → fail-open builds

Five Dockerfiles use:
```dockerfile
RUN pip install --no-cache-dir -r /app/wsN-*/requirements.txt || true
```

A broken `requirements.txt` (missing package, typo'd version, removed PyPI package) silently passes the `docker-build` CI job. The image builds but is missing dependencies. Only discovered at runtime.

- **Severity**: MEDIUM
- **Fix**: Remove `|| true` (was on ws6-inventory which already dropped it). The docker-build job should fail if deps can't install.

### M2 — mutmut non-blocking, narrow scope

`ci.yml:117-121`:
```yaml
- name: mutmut (informational, non-blocking)
  run: |
    pip install mutmut
    python -m mutmut run || true
```

- `|| true` means CI stays green regardless of kill rate
- Scope: `services/shared/sessions.py` (memory backend only) — 1 file out of dozens
- Honest disclosure in pyproject.toml, but zero mutation-testing enforcement

- **Severity**: MEDIUM
- **Fix**: Flip to blocking after establishing a non-regression baseline, or broaden scope.

### M3 — No OpenSearch service container in CI

The `redis-integration` job has a Redis service container. But there is **no equivalent for OpenSearch**. The `test_opensearch_live.py` tests (which exist in `services/ws3-indexer/storage/`) are never run in CI. The `make test-live` target requires a manual Docker stack.

- **Severity**: MEDIUM
- **Fix**: Add an `opensearch-integration` CI job with an OpenSearch service container, running `test_opensearch_live.py`.

### M4 — Gitleaks in CI only, not in pre-commit

A secret committed locally is only caught when pushed to CI. Adding gitleaks to `.pre-commit-config.yaml` provides instant local feedback.

- **Severity**: MEDIUM (defense-in-depth; already caught in CI)
- **Fix**: Add gitleaks pre-commit hook.

---

## LOW Findings

### L1 — mypy runs at default-loose strictness

`pyproject.toml:42-58` has only `python_version` + `ignore_missing_imports` + `exclude`. No `disallow_untyped_defs`, no `check_untyped_defs`, no `strict`. "0 mypy errors" is low-information — untyped functions pass cleanly. `ci.yml:112` runs matching flags. Documented honestly — this is a floor, not a ceiling.

### L2 — Coverage gate excludes security-critical modules

`tools/coverage_gate.py:30-82` TARGETS covers only WS-2 + WS-3. No coverage floor protects `sessions.py`, `bus.py`, `runner.py`, `window.py`, `keystore.py`. Gate measures execution not assertion — a test that runs code without checking output still counts. Honest about its limitations.

### L3 — Fuzz covers only 3 of 17 parsers

`fuzz.yml` matrix targets: `linux_ssh`, `cisco_asa`, `windows_eventlog`. The other 14 parsers never see fuzzing. `db_audit` (which has the `GRANT SELECT` downgrade) is not fuzzed. Honestly disclosed as "top 3".

### L4 — Python version skew in CI matrix

- `contract-tests`: Python 3.12
- `redis-integration`: Python 3.12  
- `quality`: Python **3.11**
- `pip-audit`: Python 3.12
- `attack-scorecard`: Python 3.12
- `actionlint`: Python 3.12
- `fuzz`: Python **3.11**

Not a vulnerability, but `quality` and `fuzz` run on a different minor version than everything else, including the project's declared `python_version = "3.11"` in pyproject.toml. All other jobs already use 3.12 successfully.

---

## Strengths Worth Explicit Credit

1. **`verify_action_pins.py`** — Treats network failure as FAILURE (lines 166-170). This is genuinely non-gamable. Most projects skip on network error. The annotated-tag peeling logic (lines 112-120) correctly handles `github/codeql-action`'s annotated tags. Comment-exact-vs-major-only matching (lines 132-147) correctly handles the `# v4` convention.

2. **`fire_check.py` boundary-probe sensitivity** — The CI runs `test_fire_check.py` which **mutates real rules until they ARE too loose** and asserts the gate exits 1. This proves the negative assertions are falsifiable — a test that always green on a broken harness is caught. Extremely thoughtful.

3. **Scorecard `persist-credentials: false`** — Line 33 on the checkout step. Prevents the GITHUB_TOKEN from persisting into the next steps. Correct.

4. **Least-privilege permissions throughout** — Every workflow sets `contents: read` (or `read-all`) at the top level. Jobs that need more (`security-events: write`, `id-token: write`) re-declare it job-scoped. No `permissions: write-all` anywhere.

5. **Honest gate disclosure** — Coverage gate doesn't claim 85% when it measures 77%. mutmut labeled "informational, non-blocking" with a comment explaining why. mypy described as a "floor." This honesty culture is rare and valuable.

6. **`actionlint` + `verify_action_pins` both in every PR** — Catches the exact class of error that shipped `ossf/scorecard-action@v2` (unresolvable tag) before it reaches main.

7. **`workflow_dispatch` on scorecard.yml** — Deliberate design choice: Scorecard has no PR trigger (needs `id-token: write`), so `workflow_dispatch` lets you test after merge before the weekly cron. Documented at lines 13-21.

8. **Fuzz matrix `fail-fast: false`** — One parser crash doesn't kill the other two fuzz runs. Correct.

---

## CI/CD Maturity Comparison

| Capability | FENGARDE | Industry OSS Median |
|---|---|---|
| SHA-pinned actions | ✅ All | ❌ Most use floating tags |
| Pin comment verification | ✅ Automated | ❌ Almost never |
| Scorecard | ✅ Weekly + badge | Rare |
| CodeQL security-extended | ✅ PR + push | Uncommon (most use `default`) |
| Secret scanning (gitleaks) | ✅ Blocking | Common |
| CVE audit (pip-audit) | ✅ Blocking `--strict` | Rare |
| Mutation testing | ⚠️ Informational only | Almost never attempted |
| SBOM (CycloneDX) | ✅ Auto-generated + freshness-gated | Rare |
| Nightly fuzzing | ✅ 3 targets | Rare |
| Real infra in CI | ⚠️ Redis only | Rare (most use mocks) |
| Falsifiable negative tests | ✅ `test_fire_check.py` | Almost never |

---

## Fix Priority (CI/CD)

1. **Add `devkit-feeder/requirements.txt`** and include in SBOM + pip-audit → closes H1
2. **Add `test_sessions.py` + `test_window.py` to `redis-integration`** with `SESSION_TEST_REDIS=1` → closes H2
3. **Remove `|| true`** from Dockerfiles → closes M1
4. **Add gitleaks to pre-commit** → closes M4
5. **Add `opensearch-integration` CI job** with OpenSearch service container → closes M3
6. **Broaden mutmut scope + flip to blocking** after establishing baseline → closes M2
7. **Expand fuzz targets** to include `db_audit`, `vmware_vsphere` (crash paths)
8. **Bump `quality` Python to 3.12** for consistency

---

## Bottom Line

FENGARDE's CI/CD pipeline is **genuinely exceptional for open-source** — SHA-pinned verified actions, least-privilege permissions, blocking CVE audit, CodeQL security-extended, Scorecard, automated SBOM, and the best action-pin verification I've seen. The two HIGH findings (devkit-feeder blind spot, Redis-critical tests absent from CI) are surgical gaps, not architectural weaknesses.

**CI/CD Grade: A−**

---

*Audit performed 2026-08-06. All findings verified against current `d701c2f` disk state.*