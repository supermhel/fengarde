# FENGARDE — developer entry points.
# Quick start:  make preflight && make demo
# Contributor loop (no Docker):  make test

COMPOSE := docker compose -f infra/docker-compose.yml

.PHONY: help preflight demo test e2e nis2-demo up down ha-up ha-down chaos test-live ha-verify attack-scorecard eval-detection mutation-test bench

PYTHON ?= python3

help:
	@echo "FENGARDE targets:"
	@echo "  make preflight  - check this machine is ready (vm.max_map_count, Docker RAM, free ports)"
	@echo "  make demo       - preflight + bring up the full stack (see banner for current limits)"
	@echo "  make test       - run the full zero-infra contract test suite (no Docker needed)"
	@echo "  make e2e        - zero-infra ACCEPTANCE test: SSH brute-force -> real alert (no Docker)"
	@echo "  make nis2-demo  - zero-infra: bank-DB priv-esc alert -> German NIS2 draft (no Docker)"
	@echo "  make up         - start the stack detached (docker compose up -d)"
	@echo "  make down       - stop the stack and remove volumes"
	@echo "  make ha-up      - OPT-IN: Sentinel + 3-node OpenSearch HA profile (needs REDIS_PASSWORD)"
	@echo "  make ha-down    - stop the HA profile and remove its volumes"
	@echo "  make chaos      - M1 correctness gate: kill each service mid-replay,"
	@echo "                    assert zero lost/duplicate alerts (needs 'make up' first)"
	@echo "  make test-live  - OPT-IN: real Redis + OpenSearch (needs 'make up' or REDIS_URL/OPENSEARCH_URL)"
	@echo "  make attack-scorecard - P3-2: declared ATT&CK/ATLAS coverage + Navigator layer export (zero infra)"
	@echo "  make eval-detection   - P3 eval lane: EVTX/Splunk oracle-replay detection accuracy (needs datasets, see eval/detection_accuracy/README.md)"

# DX3 — the "doctor". Fails fast with plain-English remedies before anything starts.
preflight:
	@sh infra/preflight.sh

# v0.4 Track D1: the 10-minute quickstart. `devkit-feeder` (DX2-live) injects
# a real SSH brute-force burst into the live pipeline on every `up`, so a
# fresh stack shows a REAL alert in the dashboard with no manual step.
demo: preflight
	@echo ""
	@echo "=================================================================="
	@echo " Bringing up the full stack. Within ~30-60s of every service being"
	@echo " healthy, a real SSH brute-force alert appears in the dashboard --"
	@echo " http://localhost:8080 -- no manual step needed (devkit-feeder)."
	@echo " Zero-Docker proof of the same pipeline logic: make e2e"
	@echo "=================================================================="
	@echo ""
	$(COMPOSE) up

# Contributor inner loop — zero infrastructure.
test:
	@bash run_all_tests.sh

# Phase 1 twin (WP-1-F): full AI-to-OT attack-chain scorecard, zero infra.
# Runs eval/twin/report.py (PLC sim -> real parsers -> real detector -> oracle
# grading), writes eval/twin/report.json, appends one row to eval/trend.jsonl.
twin:
	@$(PYTHON) eval/twin/report.py

# v0.1 acceptance test — proves SSH brute-force -> real alert in the index,
# idempotent under replay, with no Docker/Redis/OpenSearch.
e2e:
	@$(PYTHON) tools/demo_e2e.py

# M5: proves the NIS2 public template layer end to end -- a real alert
# (bank_db_priv_esc.yml) becomes a German NIS2/SS32 BSIG notification
# draft, zero infra, zero manual steps (docs/nis2-report-generator.md).
nis2-demo:
	@$(PYTHON) tools/demo_nis2.py

up: preflight
	$(COMPOSE) up -d

down:
	$(COMPOSE) down -v

# Opt-in HA profile: Redis Sentinel (1 primary + 2 replicas + 3 Sentinels) +
# 3-node OpenSearch, on top of the default single-instance stack. Requires
# REDIS_PASSWORD to be set. See infra/docker-compose.ha.yml's header comment.
ha-up:
	$(COMPOSE) -f infra/docker-compose.ha.yml --profile ha up -d

ha-down:
	$(COMPOSE) -f infra/docker-compose.ha.yml --profile ha down -v

# M1 (combined roadmap) correctness gate: proves effectively-once alerting
# (at-least-once delivery + idempotent alert_id) survives a service dying
# mid-replay, not just the zero-infra unit tests. Requires the live stack
# ('make up') already running -- this is not part of the zero-infra 'make test'.
chaos:
	@$(PYTHON) tools/chaos_test.py

# P2.6 — opt-in live-infra lane. The default `make test` gate is entirely
# zero-infra (MemoryBus + MemoryStore); this exercises the two paths that
# only exist against real backends: _RedisBus consume/ack/XAUTOCLAIM/DLQ
# (services/shared/test_runner.py, redis-parametrized) and OpenSearchStore's
# real HTTP wire format + optimistic-concurrency 409
# (services/ws3-indexer/storage/test_opensearch_live.py). Both SKIP cleanly
# (not fail) if their backend isn't reachable, so this target is safe to run
# without infra up -- it just proves nothing that time. Bring up real infra
# first: `make up`, or point REDIS_URL/OPENSEARCH_URL at your own instances.
#
# The session line needs FENGARDE_SESSION_SECRET because RedisSessionStore
# refuses to construct without it (mandatory session signing, FIX 5). CI has
# always supplied one; this target did not, so `make test-live` failed at that
# step for anyone running it locally while CI stayed green -- found 2026-08-11
# by running the lane by hand. Throwaway default, overridable, never a real
# credential: it signs only the rows this test creates.
SESSION_TEST_SECRET ?= local-test-session-secret-not-for-production

test-live:
	@BUS_BACKEND=redis $(PYTHON) services/shared/test_runner.py
	@BUS_BACKEND=redis $(PYTHON) services/shared/test_bus_trim_acked.py
	@BUS_BACKEND=redis $(PYTHON) services/shared/test_bus_lag.py
	@BUS_BACKEND=redis $(PYTHON) services/shared/test_bus_read_count.py
	@$(PYTHON) services/ws3-indexer/storage/test_opensearch_live.py
	@$(PYTHON) services/ws3-indexer/storage/test_opensearch_ha_failover_live.py
	@$(PYTHON) services/ws3-indexer/storage/test_opensearch_cas_concurrency_live.py
	@$(PYTHON) services/ws3-indexer/storage/test_opensearch_shared_store_concurrent_live.py
	@SESSION_TEST_REDIS=1 FENGARDE_SESSION_SECRET=$(SESSION_TEST_SECRET) $(PYTHON) services/shared/test_sessions.py

# Failover-scoped live proofs (2026-08-11). Separate from `test-live` because
# these KILL a Redis primary and need the HA profile up (`make ha-up`), not the
# default single-instance stack -- running them against `make up` would prove
# nothing and stop the only broker. Both skip cleanly if the HA profile isn't
# active. Each drives an in-network probe over `docker exec` while performing
# the kill from the host, because the HA Redis nodes are not host-published and
# the defect classes both need ONE long-lived client spanning the promotion.
ha-verify:
	@$(PYTHON) tools/sentinel_failover_live.py
	@$(PYTHON) tools/chaos_failover_test.py

# P3-2 (2026-07-21 audit fix plan) -- declared ATT&CK/ATLAS coverage
# scorecard + MITRE ATT&CK Navigator layer export. Zero infra, zero
# prerequisites: pure metadata parsed from contracts/rules/*.yml's `mitre:`
# blocks. This is DECLARED coverage only -- see eval/attack/coverage_layer.py's
# module docstring for why that's a different (and lesser) claim than the
# empirical `make eval-detection` number below.
attack-scorecard:
	@$(PYTHON) eval/attack/coverage_layer.py
	@$(PYTHON) eval/attack/test_coverage_layer.py
	@$(PYTHON) eval/attack/fire_check.py
	@$(PYTHON) eval/attack/test_fire_check.py

# P3 eval lane (Test-data integration section of the audit fix plan) --
# independent-oracle detection-accuracy replay against real EVTX-ATTACK-
# SAMPLES / Splunk attack_data corpora. OPT-IN and dataset-gated: these
# corpora are third-party (their own licenses, not vendored into this repo --
# see eval/detection_accuracy/README.md), so this target SKIPS cleanly (not
# fail) when the datasets aren't present locally, same "safe to run with no
# setup, just proves nothing that time" convention as `make test-live`.
eval-detection:
	@$(PYTHON) eval/detection_accuracy/evtx_eval.py
	@$(PYTHON) eval/detection_accuracy/splunk_eval.py
	@$(PYTHON) eval/detection_accuracy/test_evtx_eval.py

# M2 mutation-testing gate (see pyproject.toml [tool.mutmut]). Scoped narrow
# for its first pass (services/shared/sessions.py only) -- informational in
# CI, not blocking, until a real number exists to gate against. Native
# Windows mutmut isn't supported (upstream issue #397); this target assumes
# a POSIX shell (Linux CI, macOS, or WSL on Windows).
mutation-test:
	@python3 -m mutmut run || true
	@python3 -m mutmut results

# M2 public proof artifact (PLAN_C Tier 2.1): reproducible throughput /
# footprint benchmark for the normalize->detect->index path. Zero infra
# (memory bus + MemoryStore) by design -- see tools/fengarde_bench.py's
# docstring for exactly what these numbers ARE and are NOT.
#
# Gap-hunt finding (2026-08-23): this and its live sibling were wired to NO
# make target and NO CI job -- hand-runnable only, silently absent from
# `make help`. `make bench` now runs the zero-infra harness (fast, --events
# 2000) and is wired into CI (contract-tests gate). The LIVE sibling
# tools/fengarde_bench_live.py is deliberately MANUAL-ONLY: it needs the
# full Docker/Redis/OpenSearch stack up and produces real latency numbers
# that are host-dependent and not CI-deterministic -- same opt-in convention
# as `make test-live`/`make chaos`.
bench:
	@$(PYTHON) tools/fengarde_bench.py --events 2000
