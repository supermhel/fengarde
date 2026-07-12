# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

ARGIEM — an open-source SIEM pipeline (Apache-2.0). Remote: https://github.com/supermhel/argiem.git. Raw security logs are collected, normalized to OCSF, run through correlation rules, and indexed as alerts.

**Read `SSOT.md` first for current status.** It is the canonical status/roadmap index; other docs (especially `docs/superpowers/specs/` and per-service `INTERFACE.md` files) may be historical, aspirational, or partially stale — SSOT.md says which is which. If a doc disagrees with SSOT.md, SSOT.md wins.

## Commands

Everything below the Docker section is **zero-infra** (memory bus, in-memory store, stub LLM) — no Docker/Redis/OpenSearch needed. This is the normal dev loop.

```sh
make test                 # full CI gate: contract validator + every workstream's tests (= ./run_all_tests.sh)
make e2e                  # acceptance test: SSH brute-force burst -> real alert, idempotent under replay (tools/demo_e2e.py)
python tools/integration_e2e.py   # pipeline smoke test: WS-1 -> WS-2 -> WS-4 -> WS-3 on one memory bus

# Single workstream test (each service has its own test_contract.py):
cd services/ws2-normalization && python test_contract.py

# Targeted suites (see run_all_tests.sh for the full list):
python services/ws4-detection/test_window.py
python services/shared/test_runner.py
```

`Makefile` uses `python3`; on Windows override with `PYTHON=python` or invoke scripts directly.

### Docker stack (full live pipeline)

**Docker Desktop must be started manually first** — check with `docker version` once; if the engine is down, ask the user to start Docker Desktop, don't try to launch/poll it.

```sh
make preflight    # doctor: checks vm.max_map_count, Docker RAM, free ports (required before first run)
make up           # docker compose -f infra/docker-compose.yml up -d
make down         # stop stack + remove volumes
```

Ports: 6379 Redis (bus), 9200 OpenSearch, 5601 OpenSearch Dashboards, 8000 inventory API, 8080 ARGIEM alert console. On Linux/WSL2, OpenSearch needs `sudo sysctl -w vm.max_map_count=262144` or it crashes the JVM.

## Architecture

Seven workstreams (WS) under `services/`, coupled **only** through a message bus — no service imports or calls another. Bus topics, payloads, and partition keys are frozen in `contracts/bus-topics.md`.

Pipeline stages and topic names (the WS-1..WS-4 naming you'll see in test output):

```
WS-1 collectors  --raw.events-->  WS-2 normalization  --normalized.events-->  WS-4 detection  --scored.events / alerts-->  WS-3 indexer --> OpenSearch
                                  (parsers -> OCSF)         |                       |--ai.requests--> WS-5 ai (triage)
                                                            +--> WS-6 inventory     WS-7 dashboard reads alerts + WS-6 API
```

i.e. events flow **raw → normalized → scored → indexed**.

Key pieces:

- `services/shared/bus.py` — the bus abstraction: Redis Streams (`BUS_BACKEND=redis`) in the stack, in-memory (`BUS_BACKEND=memory`) in all tests. Kafka is **not** implemented despite older docs.
- `contracts/` — frozen Phase-0 contracts: OCSF event schema (`ocsf-event.schema.json`), bus topics, detection rules (`contracts/rules/*.yml`), scoring config, OpenSearch mappings. These are the schema source of truth; validate with `python tools/validate_contract.py`.
- `services/ws2-normalization/parsers/` — one parser module per log source, registered in `parsers/__init__.py`. Adding a parser: copy `linux_ssh.py`, register it, add a sample to `test_contract.py` (walkthrough: `docs/adding-a-parser.md`).
- `services/ws3-indexer/storage/` — storage adapter with `memory` and `opensearch` backends (`STORAGE_BACKEND` env).
- `services/ws4-detection` — sliding-window correlation rules + scoring; deterministic `alert_id` makes indexing idempotent under at-least-once redelivery.
- `services/ws5-ai` — LLM triage via `llm_adapter.py::make_llm()`: real Ollama if `OLLAMA_URL` is set, StubLLM fallback otherwise.

Delivery is at-least-once everywhere; consumers must stay idempotent on `ingest_id` / `event_id` / `alert_id`.

## Conventions

- New behavior needs a contract test; `make test` must be green before claiming done.
- Keep parsers isolated (one module per source); derive `type_uid`, never hand-set it.
- The detection engine executes rule files — review any rule's `condition` carefully; security findings go through `SECURITY.md`, not public issues.
- Honest status is a core project value: don't label stubbed capabilities as working (see SSOT.md §2 "proven vs. claim").
