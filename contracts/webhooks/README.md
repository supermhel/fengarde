# Outbound alert webhooks (M4.4)

One optional file per webhook subscription: `<id>.yml`. This directory ships
empty — no files here means `services/ws3-indexer/webhooks.py::run()` never
starts a bus consumer, zero behavior change for every deployment that
doesn't use this (same opt-in convention as `contracts/tenants/`).

```yaml
# contracts/webhooks/msp-ticketing.yml
id: msp-ticketing
url: https://msp.example.com/fengarde/webhook
secret_env: FENGARDE_WEBHOOK_SECRET_MSP_TICKETING   # name of an env var, NEVER the secret itself
tenant_id: acme        # optional; omit for "every tenant"
min_score: 60           # optional; default 0 = every alert (scoring.yaml's llm_min threshold)
```

`secret_env` names an **environment variable** holding the real HMAC key —
the actual secret is never written to this file, so this directory stays
safe to commit (SECURITY.md §4: never commit real credentials). If that
env var is unset when an alert fires, delivery for that one config is
skipped (fail closed); every other configured webhook still fires normally.

## Delivery

Each matching alert is POSTed as JSON:

```json
{"delivery_id": "<uuid4>", "alert": { ...the alert document... }}
```

with headers:

- `X-Fengarde-Signature-256: sha256=<hex hmac-sha256 of the raw body>` —
  keyed with the `secret_env` value. Verify with `hmac.compare_digest`
  (constant-time), same convention as GitHub's `X-Hub-Signature-256`. See
  `services/ws3-indexer/webhooks.py::verify_signature` for the reference
  implementation and `docs/webhooks.md` for a receiver-side example.
- `X-Fengarde-Delivery-Id` — the same `delivery_id` as the body, for
  receiver-side dedup (delivery is at-least-once, like every other part of
  this pipeline: a bounded retry on connection errors / 5xx can, rarely,
  deliver the same alert twice).

A 4xx response is treated as permanent (bad payload/config) and is not
retried. Connection errors and 5xx get up to 3 attempts with exponential
backoff, then are given up on — a receiver outage never blocks alert
indexing, since webhook dispatch runs as its own bus consumer group
(`cg-webhook`), independent of WS-3's indexing group (`cg-index`).
