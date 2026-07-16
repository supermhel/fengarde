# Outbound alert webhooks (M4.4)

FENGARDE can POST every new alert (or a filtered subset) to an external HTTP
endpoint — a ticketing system, a Slack relay, a PagerDuty integration —
signed with HMAC-SHA256 so the receiver can verify it actually came from
this deployment and wasn't tampered with in transit.

**Honest scope, read this first:** this is opt-in and off by default — no
files under `contracts/webhooks/` means the dispatcher never starts (see
`contracts/webhooks/README.md`). It is bounded, filtered delivery of the
existing alert document, not a general event-streaming/export feature: only
the `alerts` bus topic is dispatched, not `normalized.events`/`scored.events`.

## Configure a webhook

1. Create `contracts/webhooks/<id>.yml`:

   ```yaml
   id: msp-ticketing
   url: https://msp.example.com/fengarde/webhook
   secret_env: FENGARDE_WEBHOOK_SECRET_MSP_TICKETING
   tenant_id: acme      # optional
   min_score: 60        # optional, default 0
   ```

2. Set the secret as an environment variable on the WS-3 (indexer) process —
   never in the YAML file itself:

   ```sh
   export FENGARDE_WEBHOOK_SECRET_MSP_TICKETING="$(openssl rand -hex 32)"
   ```

3. Restart `ws3-indexer`. `main.py` loads every `contracts/webhooks/*.yml` at
   startup; if the list is non-empty it starts one extra daemon thread
   consuming the `alerts` bus topic under consumer group `cg-webhook` —
   independent of the `cg-index` group WS-3 already uses to write to
   OpenSearch, so a slow/down webhook receiver can never delay or duplicate
   indexing (Redis Streams: two consumer groups reading the same stream).

## Verifying a delivery (receiver side)

Every request carries:

- `X-Fengarde-Signature-256: sha256=<hex>` — HMAC-SHA256 of the raw request
  body, keyed with your `secret_env` value. Same header convention as
  GitHub's `X-Hub-Signature-256`.
- `X-Fengarde-Delivery-Id` — a UUID, also present in the body, for
  receiver-side dedup (delivery is at-least-once: a bounded retry on a
  connection error or 5xx can, rarely, resend the same alert).

```python
import hmac, hashlib

def verify(secret: bytes, body: bytes, header_value: str) -> bool:
    expected = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header_value or "")
```

`services/ws3-indexer/webhooks.py::verify_signature` is the exact same
logic, reused by the test suite to prove the sender and a hypothetical
receiver agree.

## Delivery semantics

- **Filtering**: `tenant_id` (omit for every tenant) and `min_score`
  (default 0 = every alert; `contracts/scoring.yaml`'s `llm_min: 60` is a
  reasonable "only the alerts that were serious enough to reach LLM triage"
  cutoff, but any integer works).
- **Retries**: a 4xx response is treated as permanent (bad payload or a
  misconfigured URL/secret on either side) and is not retried. Connection
  errors and 5xx get up to 3 attempts with exponential backoff, then are
  given up on silently — there is no dead-letter queue for failed webhook
  deliveries yet (unlike the bus's own DLQ for redelivery exhaustion,
  `tools/dlq_peek.py`). A webhook receiver that is down for an extended
  period will simply miss alerts fired during that window.
- **Fail-closed on a missing secret**: if `secret_env` names an environment
  variable that isn't set, delivery for THAT config is skipped every time
  (never sends an unsigned or garbage-keyed request) — every other
  configured webhook still fires normally.
- **Not exactly-once**: like every other consumer of this bus, a webhook
  receiver must be idempotent on `delivery_id` (or the alert's own
  `alert_id`, also present in the body) if it can't tolerate an occasional
  duplicate.

## What this does NOT give you

- No per-webhook UI — configuration is a file on disk, not a dashboard
  form. A future entry-points-based extension mechanism (M4.5) doesn't
  change this by itself.
- No webhook-delivery history/audit log in FENGARDE itself — check your
  receiver's own logs, or `ws3-indexer`'s service log (delivery failures
  are currently silent past the retry budget; not wired to a metric yet,
  tracked under M7's self-observability track).
- No mTLS or IP-allowlisting of the receiver — the security boundary is
  entirely the HMAC signature; run the receiver behind normal HTTPS/TLS
  and rotate the shared secret like any other credential.
