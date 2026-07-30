# FENGARDE — Code Quality Review

**Reviewer role:** Code Quality (swarm review — architecture/security/logic covered separately)
**Scope:** `services/`, `tools/`, `eval/` (179 Python files)
**Method:** Direct code reading (file sizes, function sizes, grep sweeps for error-handling/logging patterns, dependency manifests, lint/format config), cross-checked against `SSOT.md`'s own disclosed-gap table to avoid re-reporting already-tracked items as new.

**Overall:** this is an unusually self-aware codebase — `SSOT.md` already discloses most coverage/scope gaps honestly, `pyproject.toml`'s comments explain *why* each lint/format/mutation gate is scoped the way it is, and parsers share a well-designed `base.py` (no copy-pasted OCSF scaffolding). The findings below are the real gaps that survived that baseline, ranked by impact.

---

## 1. HIGH — Silent `except Exception: pass` defeats the exact correctness guarantee the surrounding code exists for

Two call sites swallow **every** exception from Redis setup with zero logging, silently downgrading a production service to a mode the codebase's own comments say is broken:

**`services/shared/bus.py:391-398`**
```python
def Bus():
    backend = os.getenv("BUS_BACKEND", "memory").lower()
    if backend == "redis":
        try:
            return _RedisBus(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
        except Exception:
            pass
    return _MemoryBus()
```
The docstring justifies this as "falls back to in-memory when the redis lib is unavailable" (an `ImportError`), but the `except` clause is `Exception`, not `ImportError` — it also catches a malformed `REDIS_URL`, a non-numeric `BUS_XREADGROUP_COUNT` (`int(os.getenv(...))` inside `_RedisBus.__init__`), or any future constructor change that can raise. `BUS_BACKEND=redis` requested but silently downgraded to `_MemoryBus()` means the service is no longer coupled to the rest of the pipeline at all (events produced never reach other services, nothing consumed ever arrives) — with **no log line, no metric, no exit code** signaling it happened.

**`services/ws4-detection/main.py:271-284`**
```python
if os.getenv("BUS_BACKEND", "memory").lower() == "redis":
    try:
        import redis
        from window import RedisWindowCounter
        ...
        detector._window_counter = counter
        for r in detector.rules:
            if r.stateful: r.set_counter(counter)
    except Exception:  # redis missing/unreachable -> per-replica deque fallback
        pass
```
The comment three lines above this block explains *why* this exists: "a per-process deque would split the count and the brute-force alert would never fire under scaling" (T6). If this `except` fires in production — for any reason, not just "redis missing" — the service silently reverts to exactly that broken-under-scale per-replica counting, defeating T6's own purpose, with zero operator visibility.

**Why this is inconsistent, not just risky:** this same file already imports and uses the structured logger two lines earlier and elsewhere (`services/ws4-detection/main.py:262-299`, `log.warn(...)` at line 113), and `services/ws5-ai/llm_adapter.py` shows the pattern done correctly nearby (`_log.warn("llm primary failed; degrading to backup", error=str(exc))` before every fallback). The bus.py/main.py sites are the outliers, not the house style.

**Fix:** narrow both to `except ImportError` (or `except (ImportError, redis.exceptions.RedisError)`), and log a `warn`/`error` on the fallback path using the logger that's already imported two lines away in `main.py`.

---

## 2. MEDIUM — God-function: `make_handler()` is a 471-line closure-in-a-function

`services/ws3-indexer/triage_api.py:126-597` — `make_handler()` defines an entire `Handler(BaseHTTPRequestHandler)` class (11 routes: triage GET/POST, report GET/POST, auth login/logout/me, list alerts/events/rules, plus CSRF/session/tenant-gate helpers) all as nested closures inside one factory function.

- No individual route handler (`_route_get`, `_route_post`, `_route_auth_login`, etc.) can be unit-tested without constructing the full HTTP server via `make_handler()` + a live socket — the module's own test files (`test_rbac_api.py`, `test_storage_cas.py`) confirm this, driving everything through real HTTP requests rather than calling a route function directly.
- Shared state (`store`, `users_db`, `sessions`, `rate_limiter`, `rbac_enabled`) is captured by closure across ~15 nested methods rather than passed explicitly (e.g. via `self` on a real class or a small context object) — readable in isolation, but every method implicitly depends on the outer scope, which is easy to get wrong when adding a 12th route later.
- The docstring says this closure pattern "matches the pattern main.py already uses" — worth confirming that pattern is also review-worthy elsewhere rather than treating precedent as sufficient justification on its own.

Not a bug today (the code is careful and well-commented throughout), but it is the single largest complexity concentration in the repo and the place future route additions are most likely to introduce a scoping mistake (e.g. forgetting `_tenant_gate` on a new route — there's no structural guard forcing every route to call it, only convention).

**Suggestion:** extract route bodies into module-level functions/methods taking `(store, session, ...)` as explicit parameters, with `make_handler()` reduced to wiring. Lower priority than #1, but flagged because at 471 lines it's over 3x the next-largest function in the repo (`engine.py`'s `Rule.evaluate` at 69 lines).

---

## 3. MEDIUM — Logging is inconsistent: some modules bypass the shared structured logger with hand-rolled `print()`

`services/shared/log.py`'s own docstring states its purpose: *"Replaces bare `print()` in long-running service code so logs are machine-parseable and greppable."* Every service's `main.py` (WS-1 through WS-5) and `llm_adapter.py` follow this. Four other modules don't:

| File | Line | What it does |
|---|---|---|
| `services/shared/authz.py:32` | `warn_if_disabled` | Hand-builds a JSON string via f-string: `f'{{"level": "warning", ... "msg": "auth disabled: {env_var} not set"}}'` |
| `services/ws6-inventory/authz.py:24` | same function, duplicated copy | Same hand-rolled JSON pattern |
| `services/ws4-detection/engine.py:129` | `load_allowlist` | Plain text, not JSON at all: `print(f"[engine] WARNING: allowlist '{name}' failed to load ({exc}); ...")` |
| `services/ws4-detection/tenants.py:97` | tenant config load failure | Same `[tenants] WARNING: ...` plain-text pattern |

Two separate problems bundled here:
- **`engine.py`/`tenants.py`** emit plain-text lines in a codebase whose logging convention (and presumably log-shipping/parsing setup, given the Prometheus/Grafana observability work in SSOT §1) is one-JSON-object-per-line. A log pipeline expecting JSON will either drop or mis-index these two warning types.
- **Both `authz.py` copies** hand-escape JSON via string formatting rather than `json.dumps(...)`. `env_var` and `service` are currently internal constants (low risk today), but the pattern itself is fragile — if either ever carries a value with a quote or newline, the output is invalid JSON, exactly the class of bug `shared/log.py`'s real `json.dumps(..., default=str)` was written to avoid.

**Fix:** route all four through `shared.log.get_logger(...).warn(...)`, consistent with every other module in the repo.

---

## 4. LOW-MEDIUM — Duplicated `authz.py` has no automated sync check

`services/ws6-inventory/authz.py` is a deliberate, disclosed standalone copy of `services/shared/authz.py`'s `check_api_key`/`warn_if_disabled` logic (WS-6's Docker image doesn't bundle `services/shared`). The header comment says "keep both in sync if the check logic ever changes" — but nothing enforces that. No test asserts the two files' behavior (or source) matches; `grep` shows only `services/ws3-indexer/test_auth.py` tests the shared copy, nothing tests the WS-6 copy against it. This is exactly the kind of manual-discipline-only invariant that survives the first change and silently drifts on the second.

**Fix:** a lightweight test importing both modules and asserting `inspect.getsource()` (or at least the constant-time-compare behavior under a matrix of inputs) matches would turn "keep in sync" from a comment into a CI-enforced fact.

---

## 5. LOW — Style/formatting gate is a documented floor, not the working style

`pyproject.toml` configures `black` but explicitly does not enforce it repo-wide: *"black --check flags 98 of 100 files at landing time... this codebase has its own established compact style (dense one-liners...) that predates this config."* Similarly `ruff`'s `E702` (multiple statements per line via semicolon) is blanket-ignored for 23+ existing instances. This is a reasonable, disclosed decision (avoiding a mass mechanical reformat PR), but it means:
- New code is black-formatted (via pre-commit) while ~98% of the existing codebase isn't — two visibly different styles will coexist indefinitely unless the deferred full-repo reformat actually happens.
- The `E702` exemption is unbounded (not scoped to the 23 known instances via `# noqa`), so new semicolon-joined statements outside test-file `finally:` blocks won't be caught even where the original justification (test-file idiom) doesn't apply.

Not urgent, but worth tracking as intentional debt rather than "already handled," since `pyproject.toml`'s comment describing it is 350+ days-implicit and the full-repo reformat it promises ("a separate, deliberate, owner-approved PR") isn't scheduled anywhere visible.

---

## 6. LOW — Test-coverage and mutation-testing floors are narrow relative to the codebase's real size

Both are honestly disclosed in `SSOT.md`/`pyproject.toml`, but worth naming together as a code-quality risk surface rather than a set of unrelated footnotes:
- The coverage gate targets only WS-2/WS-3 core (~85-90%); WS-1 (collectors), WS-4 (detection engine — the security-critical scoring/rule logic), WS-5 (AI triage), and WS-6 (inventory) have tests but no enforced coverage floor.
- Mutation testing (`[tool.mutmut]`) is scoped to exactly one file, `services/shared/sessions.py`, and even there only 50 of 142 generated mutants are in tested code (`RedisSessionStore`'s 92 are out of scope); of those 50, 14 survived (72% kill rate) and are disclosed as unaddressed.
- No other module in the repo has ever had a mutation-testing pass, so for everywhere else, "tests exist and pass" is unverified against "tests would actually catch a real regression" — a materially weaker claim than it's easy to assume from green CI alone.

**Suggestion (not urgent, given the honest disclosure already in place):** if `services/ws4-detection/engine.py` — the largest, most logic-dense file in the repo and the one that decides whether a real attack fires an alert — is ever going to get a mutation-testing pass, it's the highest-value next target given its size and role, ahead of expanding coverage breadth elsewhere.

---

## 7. LOW — Dependency-pinning discipline has one inconsistent file

Every active `requirements.txt` in the repo pins exact versions (`redis==5.0.8`, `PyYAML==6.0.2`) as part of the documented M2 supply-chain hardening (pip-audit CVE gate, SBOM). `services/ws6-inventory/requirements.txt` is the one exception — its (currently commented-out, not-yet-installed) production extras use unpinned floor specifiers:
```
#   fastapi>=0.110
#   uvicorn>=0.29
#   redis>=5.0
```
Harmless today since nothing installs them, but if/when WS-6's FastAPI wrap ships, these will need tightening to `==` to match the rest of the repo's convention and stay inside the `pip-audit`/SBOM guarantees the other five services already have. Flagging now so it isn't missed when that work lands.

---

## Summary table

| # | Finding | Severity | File(s) |
|---|---|---|---|
| 1 | Silent `except Exception: pass` on Redis bus/window-counter setup — no log, defeats documented multi-replica correctness | HIGH | `services/shared/bus.py`, `services/ws4-detection/main.py` |
| 2 | 471-line closure-based HTTP handler factory, hard to unit-test per-route | MEDIUM | `services/ws3-indexer/triage_api.py` |
| 3 | Logging inconsistency: hand-rolled `print()`/fragile f-string JSON instead of shared structured logger | MEDIUM | `services/shared/authz.py`, `services/ws6-inventory/authz.py`, `services/ws4-detection/engine.py`, `services/ws4-detection/tenants.py` |
| 4 | Duplicated `authz.py` copy has no automated sync check | LOW-MEDIUM | `services/ws6-inventory/authz.py` |
| 5 | Black/E702 style floor, not enforced style — old vs. new code visibly diverge | LOW | repo-wide, `pyproject.toml` |
| 6 | Coverage/mutation-testing floors narrow relative to repo size (mostly self-disclosed already) | LOW | WS-1/4/5/6, `services/shared/` beyond `sessions.py` |
| 7 | One `requirements.txt` uses unpinned specifiers (inactive today) | LOW | `services/ws6-inventory/requirements.txt` |
