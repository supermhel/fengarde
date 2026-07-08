# WS-3 Indexer — Interface Declaration

## Consumes
- Topics `normalized.events`, `scored.events`, `alerts`, `ai.results` (group `cg-index`).
- Contracts: A (events), E (index templates / ILM), B (bus).

## Produces
- Writes to OpenSearch indices: `events-{bank|dc|common}-YYYY.MM.DD`, `alerts-YYYY.MM.DD`.

## Triage API (v0.3 C1) — HTTP, separate listener
- `TRIAGE_PORT` (default `8013`), on its own thread alongside the bus consumer.
- `GET /alerts/{id}/triage` → current `{status, note, updated_at}` (defaults to
  `status: "new"` for an alert with no triage yet — tolerant reader).
- `POST /alerts/{id}/triage` → `{status?, note?}`; partial update (an omitted field
  is preserved), status enum-validated, note length + body size capped,
  concurrent writes to one alert serialized (in-process). Adds an OCSF-additive
  `triage` field to the existing alert doc via `store.find_alert(id)`.
- Unauthenticated write surface — keep on the management network (SECURITY.md §7).

## Storage adapter (swappable)
- `MemoryStore` (default, tests) / `OpenSearchStore` (env `STORAGE_BACKEND=opensearch`,
  skeleton — not exercised offline).
- Idempotent on `siem.ingest_id` / `alert_id` (at-least-once delivery).

## Contract tests
- `python test_contract.py`  (MemoryStore; routing + idempotency)

## Run locally
- `python main.py`  (memory store + memory bus by default)
