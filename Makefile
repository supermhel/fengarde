# FENGARDE — developer entry points.
# Quick start:  make preflight && make demo
# Contributor loop (no Docker):  make test

COMPOSE := docker compose -f infra/docker-compose.yml

.PHONY: help preflight demo test e2e nis2-demo up down chaos test-live attack-scorecard eval-detection

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
	@sh run_all_tests.sh

# v0.1 acceptance test — proves SSH brute-force -> real alert in the index,
# idempotent under replay, with no Docker/Redis/OpenSearch.
e2e:
	@$(PYTHON) tools/demo_e2e.py

# M5: proves the NIS2 public template layer end to end -- a real alert
# (bank_db_priv_esc.yml) becomes a German NIS2/SS32 BSIG notification
# draft, zero infra, zero manual steps (docs/nis2-report-generator.md).
nis2-demo:
	@$(PYTHON) tools/demo_nis2.py

up:
	$(COMPOSE) up -d

down:
	$(COMPOSE) down -v

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
test-live:
	@BUS_BACKEND=redis $(PYTHON) services/shared/test_runner.py
	@BUS_BACKEND=redis $(PYTHON) services/shared/test_bus_trim_acked.py
	@BUS_BACKEND=redis $(PYTHON) services/shared/test_bus_lag.py
	@BUS_BACKEND=redis $(PYTHON) services/shared/test_bus_read_count.py
	@$(PYTHON) services/ws3-indexer/storage/test_opensearch_live.py
	@SESSION_TEST_REDIS=1 $(PYTHON) services/shared/test_sessions.py

# P3-2 (2026-07-21 audit fix plan) -- declared ATT&CK/ATLAS coverage
# scorecard + MITRE ATT&CK Navigator layer export. Zero infra, zero
# prerequisites: pure metadata parsed from contracts/rules/*.yml's `mitre:`
# blocks. This is DECLARED coverage only -- see eval/attack/coverage_layer.py's
# module docstring for why that's a different (and lesser) claim than the
# empirical `make eval-detection` number below.
attack-scorecard:
	@$(PYTHON) eval/attack/coverage_layer.py

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
