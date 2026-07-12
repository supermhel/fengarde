# ARGIEM — Architecture & Design Review (v0.2, as-built)

**Date:** 2026-07-02
**Scope:** cross-cutting structural review of the shipped code (github.com/supermhel/argiem @ v0.2.0)
plus the private ARGIEM-Sec seam. This is the "design & architecture" lens of the multi-agent
sweep — the one that produces a document, not a diff. Grounded in the actual code, not the
roadmap's intentions.

Companion docs: `2026-06-27-argiem-production-roadmap-design.md` (the 3-tier target + §9 open-core),
`2026-06-27-argiem-v0.1-build-plan.md` (what shipped).

---

## 1. Verdict

The core architecture is **genuinely sound and, more importantly, *disciplined*** — the invariants
it claims are actually enforced in the code, not just asserted in comments. That is rare and it is
the project's biggest asset. The risks below are about *reach* (what happens at scale, on real
infra, across tiers), not about the shape of what exists. Nothing here says "scrap it and start
over." The right move is to protect the keystone while filling three real gaps.

---

## 2. What is well-designed (verified against the code, not assumed)

### 2.1 Bus-only coupling is real, not aspirational
Grep across `services/**` for cross-workstream imports (`from wsN` / `import wsN`) returns **zero**.
Every service imports only `shared` + its own local modules. Services communicate *exclusively*
through the bus (Contract B). This is the single most important structural property of the system
and it holds. It is what makes the 3-tier topology (edge/local/central) a *packaging* concern
rather than a rewrite: you can place any service anywhere because none of them reach into another.

### 2.2 One schema, absorbed at the edge
OCSF (Contract A) is the only internal schema. Heterogeneity (6 log sources, different vendors)
is absorbed entirely in WS-2 parsers; everything downstream sees uniform events. `validate_event`
enforces the `type_uid = class_uid*100 + activity_id` invariant. Adding a source is adding one
parser file — the per-parser isolation is clean (each parser is its own module, registered in one
registry, with its own test).

### 2.3 Stateless workers, externalized state
Detection windows live in Redis sorted sets (T6), durable data in OpenSearch. Workers hold no
authoritative state, so horizontal scaling doesn't split correlation — the global window counter
(`RedisWindowCounter`) was specifically built so N replicas share one count. This is the correct
pattern and it's implemented, not just planned.

### 2.4 Delivery semantics are thought-through
At-least-once + deterministic `alert_id` (T7) = idempotent under redelivery. The shared runner
gives every consumer ack-after-handler, XAUTOCLAIM redelivery, an XPENDING-backed redelivery cap,
and (as of the security sweep) poison-entry quarantine to `<topic>.deadletter`. Delivery
correctness is a solved problem here, not a TODO.

### 2.5 The AI backend is a clean seam
`ws5-ai/llm_adapter.py::make_llm()` selects `StubLLM` / `OllamaLLM` by env. This is the exact
insertion point for the proprietary ARGIEM-Sec model (open-core §9.7) — a third branch, no
architecture change. The behavior/output contract (`_normalize_verdict` → 3-field enum) means a
swapped model can't inject bad data downstream. Good boundary.

---

## 3. Structural risks (cross-cutting — what a per-file review can't see), ranked

### R-A [HIGH] Kafka is vaporware; the "same API, swap by env" claim is half-true
`bus.py` documents "Prod backend = Kafka (same API)" and the roadmap's central tier depends on it,
but **there is no `_KafkaBus`** — the factory only builds `_RedisBus` or `_MemoryBus`. The
abstraction *shape* is proven across two backends, which de-risks a third, but the central-tier
scaling story rests on code that doesn't exist. Worse: the two existing backends have subtly
different semantics the interface hides — `_MemoryBus.consume()` drains-and-returns (no real PEL,
ack is a no-op), while `_RedisBus` has a real pending-entries list and blocking reads. Tests run on
MemoryBus; production runs on Redis. **Anything that only works because MemoryBus fakes it (the
redelivery/DLQ semantics are re-created in tests via a re-produce loop, per bus.py's own comment)
is unproven on the real backend until exercised live.** The live smoke tests this session helped,
but the memory/redis semantic gap is a permanent test-vs-prod fidelity risk.
*Recommendation:* either implement `_KafkaBus` when the central tier is actually built (not before —
YAGNI), OR downgrade the docs to "Redis Streams is the bus; Kafka is a candidate for the central
tier" so nobody builds on a promise. And add a "contract test" that runs the SAME behavioral suite
against both backends to close the fidelity gap.

### R-B [HIGH] Single points of failure with no story yet
Redis and OpenSearch are each single instances (compose). Redis holds all correlation windows +
the bus itself; if it dies, detection state is lost and the pipeline stops. OpenSearch single-node
= no durability guarantee. This is *documented and accepted* for v0.1/v0.2 (roadmap R-4), and
correct for the local/air-gapped tier. But there is no design yet for the central tier's HA (Redis
Sentinel/Cluster, OpenSearch replicas). Flagging so it's a conscious Phase-3 decision, not a
surprise.

### R-C [MEDIUM] Backpressure is unmodeled
Producers `xadd` unconditionally. If a downstream consumer (WS-3 indexing to a slow OpenSearch, or
WS-5 waiting on a slow LLM) falls behind, the Redis stream grows unbounded — there's no
MAXLEN/backpressure/lag-based shedding. Under a log flood (or the unauthenticated syslog listener
being hammered), memory grows on the broker until it OOMs. The syslog listener even drops-on-produce-
failure now (good), but nothing bounds the *stream* itself.
*Recommendation — and a real tension, not a free fix:* `XADD ... MAXLEN ~ N` bounds memory but
**trims the OLDEST entries when the cap is hit — which for a stream a consumer hasn't drained yet is
silent EVENT LOSS**, directly against the audit-completeness goal (roadmap R-1: a bank cannot lose
security events). So stream-capping is a *conscious tradeoff* (bound broker memory vs. never drop an
event), not an obvious win — the correct answer under sustained flood is **backpressure** (slow/shed
the producer, ideally at the untrusted syslog edge) plus alerting on stream depth, not trimming.
Treat this as a design decision for the user, not an auto-applied patch.

### R-D [MEDIUM] WS-5 LLM latency is on the critical path shape
The funnel (score ≥60 → LLM) is right, but a slow/hanging Ollama call blocks that consumer's
worker for up to `timeout`. At volume, the AI tier is the throughput ceiling. The buffered
`ai.requests` queue decouples it correctly, but there's no concurrency model for the AI worker
(one call at a time per replica). Fine at demo scale; a real bottleneck at the "millions in →
handful out" promise. GPU pool + worker concurrency is a Phase-2/3 design, not started.

### R-E [LOW] `sys.path.insert` bootstrapping is fragile
Every `main.py` manually inserts paths (`HERE`, `SERVICES`) so imports resolve in both the host and
container layouts. It works (and was hardened this session for the container layout), but it's
per-service boilerplate that has already caused packaging bugs twice. A proper package layout
(installable `shared`, or a src-layout with `PYTHONPATH` set once in the image) would remove a
recurring failure class. Low priority — it works — but it's tech debt that bites during packaging.

### R-F [LOW] No schema/contract versioning
Contracts are frozen files with no version field on the wire. The day WS-2 emits a new OCSF field
or a rule schema gains a key, there's no negotiation — every consumer must update in lockstep. Fine
for a monorepo shipped together; a real constraint once edge nodes run older versions than central
(the 3-tier world). A `schema_version` on events + tolerant readers is the standard fix; defer to
when tiers actually diverge.

---

## 4. What breaks at 10x (scaling analysis)

- **10x sources:** fine — parsers are stateless, add WS-2 replicas. The bottleneck is the single
  Redis (R-B) and unbounded streams (R-C), not the parsing.
- **10x events/sec:** WS-3 OpenSearch indexing and WS-5 LLM (R-D) are the first ceilings. WS-4
  detection scales (global windows), but Redis ZSET ops per event become the Redis hotspot.
- **10x rules:** the detection engine evaluates every rule against every event (linear). At
  thousands of rules (the SigmaHQ scale ARGIEM-Sec trains on) this is O(rules×events) — needs a
  pre-filter/index by class_uid so an event only hits candidate rules. Not a problem at 5 rules;
  a real one at 500. **This is the most likely v0.3+ architectural refactor.**
- **10x sites (edge):** the store-and-forward + mTLS transport is designed (roadmap) but not built.

---

## 5. Recommendations, prioritized

**Do in v0.3 (small, high-leverage, protect the keystone):**
1. **Honest bus docs** (R-A): stop claiming Kafka until `_KafkaBus` exists. *(Applied in the same
   change as this review — no code tradeoff, just accuracy.)*
2. **Dual-backend behavioral contract test** (R-A): run the runner's ack/redelivery/DLQ suite against
   *both* MemoryBus and RedisBus in CI (the redis-integration CI job exists — extend it to the full
   behavioral suite, not just the smoke path). Closes the test-vs-prod fidelity gap permanently.
   Moderate effort, no product-behavior change — safe to schedule.
3. **Decide the backpressure policy** (R-C): stream memory-bound vs. audit-completeness is a genuine
   product decision (see R-C). NOT auto-applied — needs the user to choose drop-vs-block-vs-shed
   before any `MAXLEN`/backpressure code lands.

**Design before Phase 2/3 (don't build yet, but decide):**
4. **Rule pre-filtering** (§4): index rules by `class_uid`/`activity_id` so event→rule matching isn't
   O(all rules). Required before the rule set grows past ~50. This is the one change that's a real
   *architecture* shift, not a patch — design it deliberately.
5. **HA story** (R-B): Redis Sentinel + OpenSearch replicas for the central tier. Conscious Phase-3
   decision.
6. **Backpressure/lag signal** (R-C/R-D): the autoscale + shed design for central.

**Leave alone (YAGNI / correct as-is):**
- The bus abstraction shape, OCSF-only coupling, stateless workers, T6/T7 — these are right. Don't
  refactor them.
- Single-node Redis/OpenSearch for the local/air-gapped tier — correct by design (R-4).

---

## 6. Open-core architectural note (ARGIEM-Sec seam)

The `make_llm()` seam is the right and only integration point, and keeping ARGIEM-Sec in a separate
private repo makes the license boundary a filesystem boundary (§9.7). One architectural caution: the
seam currently swaps the *whole* triage step. When ARGIEM-Sec adds the regulatory-mapping output
(jurisdiction → DORA/NIS2 article), that's a *new field* on the alert, which touches Contract E
(indexer routing) and WS-7 (display) — i.e. it crosses the open/closed boundary. Design that field
as an *optional, additive* OCSF/alert extension (tolerant readers, R-F) so the open-source pipeline
ignores it gracefully when the proprietary model isn't present. Otherwise the open core develops a
hard dependency on a closed field, which breaks the open-core promise.

---

## 7. Bottom line

The architecture is disciplined where it counts (coupling, schema, state, delivery) and those
properties are *enforced*, not just documented — that's what makes the ambitious 3-tier roadmap
credible rather than fantasy. The real work ahead is reach: bound the streams, prove the bus on the
real backend, and design rule-matching + HA *before* scale forces them. None of that requires
disturbing the core. Protect the keystone; fill the three gaps.
