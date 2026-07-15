# ARGIEM — developer entry points.
# Quick start:  make preflight && make demo
# Contributor loop (no Docker):  make test

COMPOSE := docker compose -f infra/docker-compose.yml

.PHONY: help preflight demo test e2e up down test-live

PYTHON ?= python3

help:
	@echo "ARGIEM targets:"
	@echo "  make preflight  - check this machine is ready (vm.max_map_count, Docker RAM, free ports)"
	@echo "  make demo       - preflight + bring up the full stack (see banner for current limits)"
	@echo "  make test       - run the full zero-infra contract test suite (no Docker needed)"
	@echo "  make e2e        - zero-infra ACCEPTANCE test: SSH brute-force -> real alert (no Docker)"
	@echo "  make up         - start the stack detached (docker compose up -d)"
	@echo "  make down       - stop the stack and remove volumes"
	@echo "  make test-live  - OPT-IN: real Redis + OpenSearch (needs 'make up' or REDIS_URL/OPENSEARCH_URL)"

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

up:
	$(COMPOSE) up -d

down:
	$(COMPOSE) down -v

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
	@$(PYTHON) services/ws3-indexer/storage/test_opensearch_live.py
