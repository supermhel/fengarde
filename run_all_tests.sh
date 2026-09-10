#!/usr/bin/env bash
# CI gate: Phase 0 contract validator + every workstream's contract test.
# Zero infrastructure required (memory bus, in-memory stores, stub LLM).
set -u
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
PY="${PYTHON:-python3}"
fail=0
FAILED=""; LAST_HEADER=""

# Reject positional args (R4-#127): this script takes none; an arg used to be
# silently ignored, so `./run_all_tests.sh --help` (or a typo) ran the WHOLE
# suite invisible to the caller. Unknown/extra args now fail fast with usage.
if [ "$#" -gt 0 ]; then
  echo "usage: $0   (no arguments; the zero-infra CI gate has no options)" >&2
  exit 64
fi

echo "== Phase 0: contract validator =="; LAST_HEADER="== Phase 0: contract validator =="
$PY tools/validate_contract.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
$PY tools/test_validate_contract.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== A6: anti-dormancy check (rules must be satisfiable by a real parser) =="; LAST_HEADER="== A6: anti-dormancy check (rules must be satisfiable by a real parser) =="
$PY tools/check_rule_producers.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== WP-0.1-A: lane-coverage meta-guard (services/parsers/rules/live-tests/HTTP-surface/pin-consistency) =="; LAST_HEADER="== WP-0.1-A: lane-coverage meta-guard (services/parsers/rules/live-tests/HTTP-surface/pin-consistency) =="
$PY tools/check_lane_coverage.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
$PY tools/check_lane_coverage.py --self-test || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== B4: rule validation gate (schema, condition parse, operator safety) =="; LAST_HEADER="== B4: rule validation gate (schema, condition parse, operator safety) =="
$PY tools/validate_rules.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
$PY tools/test_validate_rules.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== coverage gate floor/buffer tests (was orphaned -- only run directly) =="; LAST_HEADER="== coverage gate floor/buffer tests (was orphaned -- only run directly) =="
$PY tools/test_coverage_gate.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== R4-#123: every test_*.py must be wired (or a documented live-only orphan) =="; LAST_HEADER="== R4-#123: every test_*.py must be wired (or a documented live-only orphan) =="
$PY tools/check_test_wiring.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== WP-3-E: ot-points business_context schema (additive optional block, yaml.safe_load-validated) =="; LAST_HEADER="== WP-3-E: ot-points business_context schema (additive optional block, yaml.safe_load-validated) =="
$PY tools/test_ot_points_business_context.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== Sigma import: regex->glob translation + rule sanitization =="; LAST_HEADER="== Sigma import: regex->glob translation + rule sanitization =="
$PY tools/test_fix_m18_sigma_glob.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
$PY tools/test_import_sigma_rules.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }

for ws in ws1-collectors ws2-normalization ws3-indexer ws4-detection ws5-ai ws6-inventory ws7-dashboard ws8-correlation ws9-resolver; do
  echo
  echo "== $ws =="; LAST_HEADER="== $ws =="
  ( cd "services/$ws" && $PY test_contract.py ) || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
done

echo
echo "== ws8 sensitivity: promotion trigger + no-transitive-merge guarantees actually break under mutation =="; LAST_HEADER="== ws8 sensitivity: promotion trigger + no-transitive-merge guarantees actually break under mutation =="
$PY services/ws8-correlation/test_correlator_sensitivity.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== WP-2-C: incident.graph provenance edges (no transitive inference) =="; LAST_HEADER="== WP-2-C: incident.graph provenance edges (no transitive inference) =="
$PY services/ws8-correlation/test_incident_graph.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== WP-3-A: incident.graph v2 typed causal DAG (canonical entity_id nodes, typed kinds, v1 builder byte-for-byte) =="; LAST_HEADER="== WP-3-A: incident.graph v2 typed causal DAG (canonical entity_id nodes, typed kinds, v1 builder byte-for-byte) =="
$PY services/ws8-correlation/test_incident_graph_v2.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws8 NEW-hunt regression: flat prometheus skip keys + skew-future/NaN time rejected + fully-anonymous deterministic member id + oldest-by-time member-cap eviction =="; LAST_HEADER="== ws8 NEW-hunt regression: flat prometheus skip keys + skew-future/NaN time rejected + fully-anonymous deterministic member id + oldest-by-time member-cap eviction =="
$PY services/ws8-correlation/test_correlator_new_hunt.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws3 WS-8 wiring: incident routing (day-stable across growth), storage list_incidents, OpenSearch wire format =="; LAST_HEADER="== ws3 WS-8 wiring: incident routing (day-stable across growth), storage list_incidents, OpenSearch wire format =="
$PY services/ws3-indexer/test_ws8_incidents_routing.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }

echo
echo "== ws3 v0.3 (C1): triage API (persistence, tolerant defaults, malformed input) =="; LAST_HEADER="== ws3 v0.3 (C1): triage API (persistence, tolerant defaults, malformed input) =="
$PY services/ws3-indexer/test_triage_api.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws3 read-plane (2026-08-27 gap-hunt): list_alerts/events/incidents default-tenant parity =="; LAST_HEADER="== ws3 read-plane (2026-08-27 gap-hunt): list_alerts/events/incidents default-tenant parity =="
$PY services/ws3-indexer/test_opensearch_list_default_filters.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws3 MemoryStore (R4-#4): find_report returns the NEWEST across a daily rollover =="; LAST_HEADER="== ws3 MemoryStore (R4-#4): find_report returns the NEWEST across a daily rollover =="
$PY services/ws3-indexer/test_find_report_newest.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws4 _emit funnel key (R4-#27: present-but-None ingest_id falls back to src-ip) =="; LAST_HEADER="== ws4 _emit funnel key (R4-#27: present-but-None ingest_id falls back to src-ip) =="
$PY services/ws3-indexer/test_ws4_emit_ingest_key.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws3 optimistic concurrency (CAS) for multi-replica triage writes =="; LAST_HEADER="== ws3 optimistic concurrency (CAS) for multi-replica triage writes =="
$PY services/ws3-indexer/test_storage_cas.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== WP-2-I: triage_api.py make_handler decomposition (per-route testability) =="; LAST_HEADER="== WP-2-I: triage_api.py make_handler decomposition (per-route testability) =="
$PY services/ws3-indexer/test_route_decomposition.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== WP-3-B: evidence package (hash-chained, tamper-evident, reporting.md seam) =="; LAST_HEADER="== WP-3-B: evidence package (hash-chained, tamper-evident, reporting.md seam) =="
$PY services/ws3-indexer/test_evidence_package.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== Phase 5 (2026-09-04): entity/causal-graph/evidence read path =="; LAST_HEADER="== Phase 5 (2026-09-04): entity/causal-graph/evidence read path =="
$PY services/ws3-indexer/test_phase5_read_path.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws3 (P1.3): OpenSearch index transient-retry / permanent-surface =="; LAST_HEADER="== ws3 (P1.3): OpenSearch index transient-retry / permanent-surface =="
$PY services/ws3-indexer/test_opensearch_retry.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws3 P1-4 (2026-07-21 audit): OpenSearch _bulk API (NDJSON, partial-failure parsing) =="; LAST_HEADER="== ws3 P1-4 (2026-07-21 audit): OpenSearch _bulk API (NDJSON, partial-failure parsing) =="
$PY services/ws3-indexer/test_bulk_index.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws3 P1-4 remainder: normalized/scored double-index is order-independent =="; LAST_HEADER="== ws3 P1-4 remainder: normalized/scored double-index is order-independent =="
$PY services/ws3-indexer/test_double_index_order.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws3 M4.3: rule-summary read model (list_rule_summaries, tenant disable, _contracts_dir) =="; LAST_HEADER="== ws3 M4.3: rule-summary read model (list_rule_summaries, tenant disable, _contracts_dir) =="
$PY services/ws3-indexer/test_rules_view.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws3: StorageAdapter legacy CAS/versioning default methods =="; LAST_HEADER="== ws3: StorageAdapter legacy CAS/versioning default methods =="
$PY services/ws3-indexer/test_adapter_defaults.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws3: redelivered alerts preserve analyst triage (CAS guard against clobber) =="; LAST_HEADER="== ws3: redelivered alerts preserve analyst triage (CAS guard against clobber) =="
$PY services/ws3-indexer/test_alert_triage_clobber.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== v0.4 (S1): opt-in API-key auth (ws3 triage, ws6 inventory) =="; LAST_HEADER="== v0.4 (S1): opt-in API-key auth (ws3 triage, ws6 inventory) =="
$PY services/ws3-indexer/test_auth.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
$PY services/ws6-inventory/test_auth.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws6 tenant isolation (F1, 2026-07-29 audit): schema/route/migration scoping =="; LAST_HEADER="== ws6 tenant isolation (F1, 2026-07-29 audit): schema/route/migration scoping =="
$PY services/ws6-inventory/test_tenant_isolation.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws6 per-tenant API keys, hashed at rest (F1 2nd follow-up, 2026-07-30 audit) =="; LAST_HEADER="== ws6 per-tenant API keys, hashed at rest (F1 2nd follow-up, 2026-07-30 audit) =="
$PY services/ws6-inventory/test_keystore.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws6 manage_keys.py operator CLI (provision/revoke/list) =="; LAST_HEADER="== ws6 manage_keys.py operator CLI (provision/revoke/list) =="
$PY services/ws6-inventory/test_manage_keys.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws6 new-device diff (M7 Track Y): baseline, per-tenant state, restart durability =="; LAST_HEADER="== ws6 new-device diff (M7 Track Y): baseline, per-tenant state, restart durability =="
$PY services/ws6-inventory/test_new_device_diff.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws6 bus consumer (M7 Track Y follow-up): assets.updates -> raw.events, real parser round-trip =="; LAST_HEADER="== ws6 bus consumer (M7 Track Y follow-up): assets.updates -> raw.events, real parser round-trip =="
$PY services/ws6-inventory/test_bus_consumer.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== M4.2 RBAC: users/sessions/roles (unit) =="; LAST_HEADER="== M4.2 RBAC: users/sessions/roles (unit) =="
$PY services/shared/test_rbac.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== session-store lifecycle (memory; redis half is opt-in via make test-live) =="; LAST_HEADER="== session-store lifecycle (memory; redis half is opt-in via make test-live) =="
$PY services/shared/test_sessions.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== M4.2 RBAC: login/logout/roles/tenant isolation (real HTTP) =="; LAST_HEADER="== M4.2 RBAC: login/logout/roles/tenant isolation (real HTTP) =="
$PY services/ws3-indexer/test_rbac_api.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== M4.3 versioned REST API: GET /alerts, /events, /rules (+/api/v1 aliases), spec-vs-code =="; LAST_HEADER="== M4.3 versioned REST API: GET /alerts, /events, /rules (+/api/v1 aliases), spec-vs-code =="
$PY services/ws3-indexer/test_api_v1.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== Design-C (2026-07-29 audit): list_alerts actor/src_ip manual correlation filters =="; LAST_HEADER="== Design-C (2026-07-29 audit): list_alerts actor/src_ip manual correlation filters =="
$PY services/ws3-indexer/test_list_alerts_correlation.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== M4.4 outbound webhooks: HMAC sign/verify, delivery, retry policy, tenant/score filtering =="; LAST_HEADER="== M4.4 outbound webhooks: HMAC sign/verify, delivery, retry policy, tenant/score filtering =="
$PY services/ws3-indexer/test_webhooks.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== v0.4 (R): incident-report hook (template backend, contract, HTTP fallback) =="; LAST_HEADER="== v0.4 (R): incident-report hook (template backend, contract, HTTP fallback) =="
$PY services/ws3-indexer/test_reporting.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== F3: router.py rejects (never normalizes) a malformed tenant_id in index names =="; LAST_HEADER="== F3: router.py rejects (never normalizes) a malformed tenant_id in index names =="
$PY services/ws3-indexer/test_router.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }

# Extended zero-infra suite (runner, window counters, boolean evaluator, e2e).
# Still no Docker/Redis/OpenSearch — all on the memory bus + in-memory store.
echo
echo "== shared runner =="; LAST_HEADER="== shared runner =="
$PY services/shared/test_runner.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== shared runner P1-8 remainder: XACK batching in the real consume loop =="; LAST_HEADER="== shared runner P1-8 remainder: XACK batching in the real consume loop =="
$PY services/shared/test_ack_batching.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== shared envelope v1 (M1) =="; LAST_HEADER="== shared envelope v1 (M1) =="
$PY services/shared/test_envelope.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== shared ocsf helpers (P0-1: IPv4-mapped-IPv6 normalization) =="; LAST_HEADER="== shared ocsf helpers (P0-1: IPv4-mapped-IPv6 normalization) =="
$PY services/shared/test_ocsf.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== shared bus trim_acked (P0-5: acked-stream reaper; RedisBus half is opt-in via make test-live) =="; LAST_HEADER="== shared bus trim_acked (P0-5: acked-stream reaper; RedisBus half is opt-in via make test-live) =="
$PY services/shared/test_bus_trim_acked.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== shared bus lag (P1-7: real backlog signal; RedisBus half is opt-in via make test-live) =="; LAST_HEADER="== shared bus lag (P1-7: real backlog signal; RedisBus half is opt-in via make test-live) =="
$PY services/shared/test_bus_lag.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== shared bus fan-out (multi-consumer-group fan-out + ack independence) =="; LAST_HEADER="== shared bus fan-out (multi-consumer-group fan-out + ack independence) =="
$PY services/shared/test_bus_groups.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== shared bus PEL-cap in-flight eviction (2026-08-27 gap-hunt #1: at-least-once) =="; LAST_HEADER="== shared bus PEL-cap in-flight eviction (2026-08-27 gap-hunt #1: at-least-once) =="
$PY services/shared/test_bus_pel_cap.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== shared runner metrics provider error logging (2026-08-27 gap-hunt #3) =="; LAST_HEADER="== shared runner metrics provider error logging (2026-08-27 gap-hunt #3) =="
$PY services/shared/test_runner_metrics.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== shared outbound_http SSRF guard + pinned opener (2026-08-27 gap-hunt #5/#9, R3-58/65) =="; LAST_HEADER="== shared outbound_http SSRF guard + pinned opener (2026-08-27 gap-hunt #5/#9, R3-58/65) =="
$PY services/shared/test_outbound_http.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== shared window redelivery timestamp-refresh parity (2026-08-27 gap-hunt #6, R3-61) =="; LAST_HEADER="== shared window redelivery timestamp-refresh parity (2026-08-27 gap-hunt #6, R3-61) =="
$PY services/shared/test_window.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== shared bus read count (P1-8: XREADGROUP batch size; RedisBus-only, opt-in via make test-live) =="; LAST_HEADER="== shared bus read count (P1-8: XREADGROUP batch size; RedisBus-only, opt-in via make test-live) =="
$PY services/shared/test_bus_read_count.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== shared bus redis-fallback exception narrowing (code-quality #1, 2026-07-29 audit) =="; LAST_HEADER="== shared bus redis-fallback exception narrowing (code-quality #1, 2026-07-29 audit) =="
$PY services/shared/test_bus_redis_fallback.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== shared bus Sentinel failover on the generator methods (2026-08-05) =="; LAST_HEADER="== shared bus Sentinel failover on the generator methods (2026-08-05) =="
$PY services/shared/test_sentinel_failover.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== shared log level gate (P2-3, 2026-07-21 audit) =="; LAST_HEADER="== shared log level gate (P2-3, 2026-07-21 audit) =="
$PY services/shared/test_log.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== shared runner traceback throttle (P2-4, 2026-07-21 audit) =="; LAST_HEADER="== shared runner traceback throttle (P2-4, 2026-07-21 audit) =="
$PY services/shared/test_runner_throttle.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== shared MemoryBus produce/consume race (L1/L2, 2026-07-30/2026-08-06 audits) =="; LAST_HEADER="== shared MemoryBus produce/consume race (L1/L2, 2026-07-30/2026-08-06 audits) =="
$PY services/shared/test_bus_memory_race.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== shared per-tenant fair consume ordering (Task M / Finding F4, 2026-08-07) =="; LAST_HEADER="== shared per-tenant fair consume ordering (Task M / Finding F4, 2026-08-07) =="
$PY services/shared/test_fairness.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== shared allowlist (moved from ws4-detection 2026-08-18 for WS-8 reuse): CIDR/exact match, fail-closed load =="; LAST_HEADER="== shared allowlist (moved from ws4-detection 2026-08-18 for WS-8 reuse): CIDR/exact match, fail-closed load =="
$PY services/shared/test_allowlist.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws2 property-based parser hardening (M1, Hypothesis) =="; LAST_HEADER="== ws2 property-based parser hardening (M1, Hypothesis) =="
$PY services/ws2-normalization/parsers/test_property_hardening.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws2 log-injection defense (M1, ANSI/control-char sanitize) =="; LAST_HEADER="== ws2 log-injection defense (M1, ANSI/control-char sanitize) =="
$PY services/ws2-normalization/test_sanitize.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws2 chaos-ws8 gap-hunt findings (#4 _int_env degrade-not-crash, #5 unmapped top-level LIST wildcard) =="; LAST_HEADER="== ws2 chaos-ws8 gap-hunt findings (#4 _int_env degrade-not-crash, #5 unmapped top-level LIST wildcard) =="
$PY services/ws2-normalization/test_fix_chaos_gap_hunt.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo "== ws2 modbus changeTicketId trust boundary (PR #80 finding 1: meta-only ticket, shape check) =="; LAST_HEADER="== ws2 modbus changeTicketId trust boundary (PR #80 finding 1: meta-only ticket, shape check) =="
$PY services/ws2-normalization/test_fix_modbus_ticket_boundary.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws4 window counters (T6) =="; LAST_HEADER="== ws4 window counters (T6) =="
$PY services/ws4-detection/test_window.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws4 v0.5 (A3): periodicity/beaconing window primitive (deque + redis-fake parity) =="; LAST_HEADER="== ws4 v0.5 (A3): periodicity/beaconing window primitive (deque + redis-fake parity) =="
$PY services/ws4-detection/test_window_periodic.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws4 P1-5 (2026-07-21 audit): window dedup O(1) not O(n) (perf regression trip-wire) =="; LAST_HEADER="== ws4 P1-5 (2026-07-21 audit): window dedup O(1) not O(n) (perf regression trip-wire) =="
$PY services/ws4-detection/test_window_perf.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws4 boolean evaluator + alert id (T4/T7) =="; LAST_HEADER="== ws4 boolean evaluator + alert id (T4/T7) =="
$PY services/ws4-detection/test_engine_boolean.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws4 P0 hardening: time-guard (poison/future) + alert-id collapse =="; LAST_HEADER="== ws4 P0 hardening: time-guard (poison/future) + alert-id collapse =="
$PY services/ws4-detection/test_engine_hardening.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws4 P1-1 (2026-07-21 audit): non-stateful alert_key tenant isolation =="; LAST_HEADER="== ws4 P1-1 (2026-07-21 audit): non-stateful alert_key tenant isolation =="
$PY services/ws4-detection/test_p1_1_alert_key_tenant.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws4 Design-A (2026-07-29 audit): make_alert() records all contributing event ids =="; LAST_HEADER="== ws4 Design-A (2026-07-29 audit): make_alert() records all contributing event ids =="
$PY services/ws4-detection/test_design_a_event_ids.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws4 Design-B (2026-07-29 audit): siem.llm_gate decouples funnel routing from severity_floor =="; LAST_HEADER="== ws4 Design-B (2026-07-29 audit): siem.llm_gate decouples funnel routing from severity_floor =="
$PY services/ws4-detection/test_design_b_llm_gate.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws4/ws5 P1-2 (2026-07-21 audit): 20-59 classifier band now routes to WS-5 =="; LAST_HEADER="== ws4/ws5 P1-2 (2026-07-21 audit): 20-59 classifier band now routes to WS-5 =="
$PY services/ws4-detection/test_p1_2_classifier_band.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws4 distinct-count window + port-scan/lateral-movement rules (v0.2) =="; LAST_HEADER="== ws4 distinct-count window + port-scan/lateral-movement rules (v0.2) =="
$PY services/ws4-detection/test_window_distinct.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
$PY services/ws4-detection/test_engine_distinct_rules.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws4 v0.3: password-spray + priv-grant fire on REAL parser output =="; LAST_HEADER="== ws4 v0.3: password-spray + priv-grant fire on REAL parser output =="
$PY services/ws4-detection/test_v03_new_rules.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws4 v0.4 (P4): impossible-travel fires on REAL parser + enrichment output =="; LAST_HEADER="== ws4 v0.4 (P4): impossible-travel fires on REAL parser + enrichment output =="
$PY services/ws4-detection/test_v04_new_rules.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws4 v0.5 (A3): common_beaconing.yml fires on regular cadence, not on irregular =="; LAST_HEADER="== ws4 v0.5 (A3): common_beaconing.yml fires on regular cadence, not on irregular =="
$PY services/ws4-detection/test_v05_beaconing.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws4 OT inventory-diff rule (new OT device on segment) =="; LAST_HEADER="== ws4 OT inventory-diff rule (new OT device on segment) =="
$PY services/ws4-detection/test_ot_inventory_diff_rule.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo

echo "== ws4 agent rule pack (PLAN_A P3 R1/R3/R4/R5): fire on REAL parser output =="; LAST_HEADER="== ws4 agent rule pack (PLAN_A P3 R1/R3/R4/R5): fire on REAL parser output =="
$PY services/ws4-detection/test_v05_agent_rules.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws4 P0-2 (2026-07-21 audit): sourceless brute-force fires on REAL parser output =="; LAST_HEADER="== ws4 P0-2 (2026-07-21 audit): sourceless brute-force fires on REAL parser output =="
$PY services/ws4-detection/test_p0_2_sourceless_bruteforce.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws4 v0.3 (A3): rule grammar (comparison ops + allowlist), fail-closed =="; LAST_HEADER="== ws4 v0.3 (A3): rule grammar (comparison ops + allowlist), fail-closed =="
$PY services/ws4-detection/test_v03_rule_grammar.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws4 v0.3 (A3): time-of-day predicate (outside_hours) + after-hours rule =="; LAST_HEADER="== ws4 v0.3 (A3): time-of-day predicate (outside_hours) + after-hours rule =="
$PY services/ws4-detection/test_v03_time_predicate.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws4 v0.4 (P1.7): rule tuning (after-hours service-account allowlist) =="; LAST_HEADER="== ws4 v0.4 (P1.7): rule tuning (after-hours service-account allowlist) =="
$PY services/ws4-detection/test_v04_rule_tuning.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== M4.5 rule-pack plugin discovery (entry points) + Detector merge/collision =="; LAST_HEADER="== M4.5 rule-pack plugin discovery (entry points) + Detector merge/collision =="
$PY services/ws4-detection/test_plugins.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws4 B4: rule hot-reload (mtime poll, fail-closed on malformed edit) =="; LAST_HEADER="== ws4 B4: rule hot-reload (mtime poll, fail-closed on malformed edit) =="
$PY services/ws4-detection/test_hot_reload.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== F3: tenants.py::load_disabled_rules fails open on a malformed/path-traversal tenant_id =="; LAST_HEADER="== F3: tenants.py::load_disabled_rules fails open on a malformed/path-traversal tenant_id =="
$PY services/ws4-detection/test_tenants.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== M7 follow-up: rule-health watchdog (last-fired timestamp per rule on /metrics/prom) =="; LAST_HEADER="== M7 follow-up: rule-health watchdog (last-fired timestamp per rule on /metrics/prom) =="
$PY services/ws4-detection/test_rule_health.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== WP-2-F: exposure-aware risk scoring extension (schema-additive, inert) =="; LAST_HEADER="== WP-2-F: exposure-aware risk scoring extension (schema-additive, inert) =="
$PY services/ws4-detection/test_exposure_scoring.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== WP-2-D: behavioral baselines (learn/detect, bounded, DequeWindowCounter reuse) =="; LAST_HEADER="== WP-2-D: behavioral baselines (learn/detect, bounded, DequeWindowCounter reuse) =="
$PY services/ws4-detection/test_behavioral_baseline.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws4 FIX 1/2/13/14/22/L1 regression: Sentinel HA wiring, poison-pill rejection, clock-skew warn =="; LAST_HEADER="== ws4 FIX 1/2/13/14/22/L1 regression: Sentinel HA wiring, poison-pill rejection, clock-skew warn =="
$PY services/ws4-detection/test_fix_detection_engine.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws4 R4-30/F7/F8 regression: Detector owns ITS rule dirs, plugin packs hot-reload via fingerprint, ai_enqueued counts LLM tier only =="; LAST_HEADER="== ws4 R4-30/F7/F8 regression: Detector owns ITS rule dirs, plugin packs hot-reload via fingerprint, ai_enqueued counts LLM tier only =="
$PY services/ws4-detection/test_fix_plugin_reload_and_llm_metrics.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws2 parsers: generic syslog + windows event log (v0.2) =="; LAST_HEADER="== ws2 parsers: generic syslog + windows event log (v0.2) =="
$PY services/ws2-normalization/parsers/test_generic_syslog.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
$PY services/ws2-normalization/parsers/test_windows_eventlog.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws2 parsers: active_directory (F6: wrong-typed ip/mac/uid fields must drop, not crash) =="; LAST_HEADER="== ws2 parsers: active_directory (F6: wrong-typed ip/mac/uid fields must drop, not crash) =="
$PY services/ws2-normalization/parsers/test_active_directory.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws2 registry routing (P0.4: non-shadowing content-sniff) =="; LAST_HEADER="== ws2 registry routing (P0.4: non-shadowing content-sniff) =="
$PY services/ws2-normalization/parsers/test_registry_routing.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== M4.5 parser plugin discovery (entry points, additive, collision-safe) =="; LAST_HEADER="== M4.5 parser plugin discovery (entry points, additive, collision-safe) =="
$PY services/ws2-normalization/parsers/test_plugins.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws2 parser hardening (P0.5-7: port guard, IP bounds, status-from-outcome) =="; LAST_HEADER="== ws2 parser hardening (P0.5-7: port guard, IP bounds, status-from-outcome) =="
$PY services/ws2-normalization/parsers/test_parser_hardening.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws2 severity rubric + sector override (P2.2) =="; LAST_HEADER="== ws2 severity rubric + sector override (P2.2) =="
$PY services/ws2-normalization/parsers/test_v05_severity_sector.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws2 A5 enrichment (reputation + geo, additive/offline/fail-open) =="; LAST_HEADER="== ws2 A5 enrichment (reputation + geo, additive/offline/fail-open) =="
$PY services/ws2-normalization/enrichment/test_enrichment.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws2 timeutil (P1.6: epoch/ISO/FILETIME normalization) =="; LAST_HEADER="== ws2 timeutil (P1.6: epoch/ISO/FILETIME normalization) =="
$PY services/ws2-normalization/parsers/test_timeutil.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws2 parsers: db_audit (v0.3, un-dormants bank_db_priv_esc.yml) =="; LAST_HEADER="== ws2 parsers: db_audit (v0.3, un-dormants bank_db_priv_esc.yml) =="
$PY services/ws2-normalization/parsers/test_db_audit.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws2 parsers: mcp_agent (v0.4 P1, agent/MCP tool-call audit rules) =="; LAST_HEADER="== ws2 parsers: mcp_agent (v0.4 P1, agent/MCP tool-call audit rules) =="
$PY services/ws2-normalization/parsers/test_mcp_agent.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws2 parsers: opcua_audit (v0.4 P2, OT/industrial control-system rules) =="; LAST_HEADER="== ws2 parsers: opcua_audit (v0.4 P2, OT/industrial control-system rules) =="
$PY services/ws2-normalization/parsers/test_opcua_audit.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws2 parsers: n8n_audit (v0.4 P3, automation-platform rules) =="; LAST_HEADER="== ws2 parsers: n8n_audit (v0.4 P3, automation-platform rules) =="
$PY services/ws2-normalization/parsers/test_n8n_audit.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws2 parsers: dns_query (v0.5 A4, un-dormants common_dns_exfil.yml) =="; LAST_HEADER="== ws2 parsers: dns_query (v0.5 A4, un-dormants common_dns_exfil.yml) =="
$PY services/ws2-normalization/parsers/test_dns_query.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws2 parsers: k8s_audit (v0.5 A4, un-dormants dc_privileged_container.yml) =="; LAST_HEADER="== ws2 parsers: k8s_audit (v0.5 A4, un-dormants dc_privileged_container.yml) =="
$PY services/ws2-normalization/parsers/test_k8s_audit.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws2 parsers: cef (v0.5 A4, feeds existing common_* rules from any CEF source) =="; LAST_HEADER="== ws2 parsers: cef (v0.5 A4, feeds existing common_* rules from any CEF source) =="
$PY services/ws2-normalization/parsers/test_cef.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws2 parsers: cloudtrail (v0.5 A4, un-dormants cloud_root_console_login.yml) =="; LAST_HEADER="== ws2 parsers: cloudtrail (v0.5 A4, un-dormants cloud_root_console_login.yml) =="
$PY services/ws2-normalization/parsers/test_cloudtrail.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws2 parsers: sysmon (P0-3, 2026-07-21 audit: first class-1001 producer) =="; LAST_HEADER="== ws2 parsers: sysmon (P0-3, 2026-07-21 audit: first class-1001 producer) =="
$PY services/ws2-normalization/parsers/test_sysmon.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws2 parsers: modbus_anomaly (M7 Track X, 2026-07-22: OT protocol-anomaly detector, not a vendor-log parser -- un-dormants ot_modbus_unauthorized_write.yml) =="; LAST_HEADER="== ws2 parsers: modbus_anomaly (M7 Track X, 2026-07-22: OT protocol-anomaly detector, not a vendor-log parser -- un-dormants ot_modbus_unauthorized_write.yml) =="
$PY services/ws2-normalization/parsers/test_modbus_anomaly.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws2 inventory_diff parser (M7 Track Y): OCSF shape + edge rejection =="; LAST_HEADER="== ws2 inventory_diff parser (M7 Track Y): OCSF shape + edge rejection =="
$PY services/ws2-normalization/parsers/test_inventory_diff.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws2 parser-integrity fix regressions (non-string operation fields, VM undeploy/remove, GRANT SELECT, IPv4-mapped IPv6, inventory epoch seconds, MCP short-word false positives, OPC UA/n8n routing edges) =="; LAST_HEADER="== ws2 parser-integrity fix regressions (non-string operation fields, VM undeploy/remove, GRANT SELECT, IPv4-mapped IPv6, inventory epoch seconds, MCP short-word false positives, OPC UA/n8n routing edges) =="
$PY services/ws2-normalization/parsers/test_fix_parser_integrity.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws5 ollama adapter + fallback (v0.2) =="; LAST_HEADER="== ws5 ollama adapter + fallback (v0.2) =="
$PY services/ws5-ai/test_llm_adapter.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws5 LLM dedup fix regression =="; LAST_HEADER="== ws5 LLM dedup fix regression =="
$PY services/ws5-ai/test_fix_llm_dedup.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws5 ai_triage engine-mix metrics (was orphaned -- never wired) =="; LAST_HEADER="== ws5 ai_triage engine-mix metrics (was orphaned -- never wired) =="
$PY services/ws5-ai/test_ai_engine_metrics.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws5 gap-hunt fixes (siem:null poison-pill + id-less event ids) =="; LAST_HEADER="== ws5 gap-hunt fixes (siem:null poison-pill + id-less event ids) =="
$PY services/ws5-ai/test_fix_ws5_gap_hunt.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== WP-3-D: ws5 bounded-LLM concurrency (pool overlap, admission bound, dedup under concurrency) =="; LAST_HEADER="== WP-3-D: ws5 bounded-LLM concurrency (pool overlap, admission bound, dedup under concurrency) =="
$PY services/ws5-ai/test_concurrency.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws1 syslog UDP listener (v0.2) =="; LAST_HEADER="== ws1 syslog UDP listener (v0.2) =="
$PY services/ws1-collectors/test_syslog_udp.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws1 health/metrics (gap-hunt #70/#71/#76: /health 503 on bus outage, flat gauges) =="; LAST_HEADER="== ws1 health/metrics (gap-hunt #70/#71/#76: /health 503 on bus outage, flat gauges) =="
$PY services/ws1-collectors/test_main_health_metrics.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws1 P1-6 (2026-07-21 audit): spool drain O(n) + lock released across produce() =="; LAST_HEADER="== ws1 P1-6 (2026-07-21 audit): spool drain O(n) + lock released across produce() =="
$PY services/ws1-collectors/test_spool_perf.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws1 asset observations: only MAC-bearing observations reach assets.updates (2026-08-05) =="; LAST_HEADER="== ws1 asset observations: only MAC-bearing observations reach assets.updates (2026-08-05) =="
$PY services/ws1-collectors/test_asset_observations.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== integration e2e (WS-1->2->4->3) =="; LAST_HEADER="== integration e2e (WS-1->2->4->3) =="
$PY tools/integration_e2e.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== acceptance e2e (brute-force -> alert, idempotent) =="; LAST_HEADER="== acceptance e2e (brute-force -> alert, idempotent) =="
$PY tools/demo_e2e.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== agent_log_shipper e2e (JSONL file -> raw.events -> R1+R3 alerts) =="; LAST_HEADER="== agent_log_shipper e2e (JSONL file -> raw.events -> R1+R3 alerts) =="
$PY tools/test_agent_log_shipper.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== M4 gate: two-tenant isolation (separate indices, per-tenant rule enablement) =="; LAST_HEADER="== M4 gate: two-tenant isolation (separate indices, per-tenant rule enablement) =="
$PY tools/test_multi_tenant_isolation.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== M4.6 ops lifecycle: users.db schema migration (upgrade with data intact) =="; LAST_HEADER="== M4.6 ops lifecycle: users.db schema migration (upgrade with data intact) =="
$PY services/shared/test_users_migration.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== M4.6 ops lifecycle: disk-headroom guardrail (real shutil.disk_usage) =="; LAST_HEADER="== M4.6 ops lifecycle: disk-headroom guardrail (real shutil.disk_usage) =="
$PY services/shared/test_diskguard.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== M4.6 ops lifecycle: backup/restore (real SQLite + contracts/, checksum-verified) =="; LAST_HEADER="== M4.6 ops lifecycle: backup/restore (real SQLite + contracts/, checksum-verified) =="
$PY tools/test_backup_restore.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== M4.6 ops lifecycle: OpenSearch template migration (versioned, plan-then-apply) =="; LAST_HEADER="== M4.6 ops lifecycle: OpenSearch template migration (versioned, plan-then-apply) =="
$PY tools/test_migrate_opensearch.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== M5 NIS2 template: DE/EN renderer, stage cumulativeness, HTTP wiring =="; LAST_HEADER="== M5 NIS2 template: DE/EN renderer, stage cumulativeness, HTTP wiring =="
$PY services/ws3-indexer/test_nis2_template.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== M5 eval: >=10 synthetic incidents -> NIS2 drafts -> checklist (CI-runnable) =="; LAST_HEADER="== M5 eval: >=10 synthetic incidents -> NIS2 drafts -> checklist (CI-runnable) =="
$PY eval/report_generator/run_eval.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== M5 demo: bank-DB priv-esc -> real alert -> German NIS2 draft, zero infra =="; LAST_HEADER="== M5 demo: bank-DB priv-esc -> real alert -> German NIS2 draft, zero infra =="
$PY tools/demo_nis2.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== P3-2 (2026-07-21 audit): declared ATT&CK/ATLAS coverage scorecard =="; LAST_HEADER="== P3-2 (2026-07-21 audit): declared ATT&CK/ATLAS coverage scorecard =="
$PY eval/attack/test_coverage_layer.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== M7 (2026-07-22): MITRE empirical firing check -- tagged rules fire on their own real fixture =="; LAST_HEADER="== M7 (2026-07-22): MITRE empirical firing check -- tagged rules fire on their own real fixture =="
$PY eval/attack/fire_check.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== M7 follow-up: fire_check boundary probes are sensitive (a green negative must be able to go red) =="; LAST_HEADER="== M7 follow-up: fire_check boundary probes are sensitive (a green negative must be able to go red) =="
$PY eval/attack/test_fire_check.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== action-pin gate: every workflow SHA-pinned, incl. workflows with no pull_request trigger =="; LAST_HEADER="== action-pin gate: every workflow SHA-pinned, incl. workflows with no pull_request trigger =="
$PY tools/test_verify_action_pins.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
$PY tools/verify_action_pins.py --offline || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }

# == Detection quality canary (docs/detection-quality.md): engine-vs-labels ==
echo
echo "== detection-quality: precision/recall/F1 canary over the labeled corpus (real engine + real rules) =="; LAST_HEADER="== detection-quality: precision/recall/F1 canary over the labeled corpus (real engine + real rules) =="
$PY tools/test_detection_quality.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
$PY tools/detection_quality_eval.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }

echo
echo "== Phase 5 item 6 (2026-09-04): eval/trend.jsonl viewer generator =="; LAST_HEADER="== Phase 5 item 6 (2026-09-04): eval/trend.jsonl viewer generator =="
$PY tools/test_generate_trend_viewer.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }

# == AI-to-OT twin (WP-1-A..F): PLC sim, attack chain, degradation rig, FPR ==
echo
echo "== twin: telemetry-degradation rig self-check (delay/duplicate/reorder/loss determinism + loss-subset proof) =="; LAST_HEADER="== twin: telemetry-degradation rig self-check (delay/duplicate/reorder/loss determinism + loss-subset proof) =="
$PY eval/twin/degradation.py --selfcheck || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== twin: attack-chain scenario self-check (real-parser integrity + determinism + loud-failure negative control) =="; LAST_HEADER="== twin: attack-chain scenario self-check (real-parser integrity + determinism + loud-failure negative control) =="
$PY eval/twin/scenario.py --selfcheck || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== twin: negative controls (FPR source) -- four benign scenarios, all must yield zero incidents =="; LAST_HEADER="== twin: negative controls (FPR source) -- four benign scenarios, all must yield zero incidents =="
$PY eval/twin/negative_controls.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }

# == Phase 4 adversarial system-level validation (WP-4-A) ==
# Layer A is DETERMINISTIC and BLOCKING (determinism is what licenses
# blocking); Layer B curated corpus is deterministic + blocking; the
# stochastic Layer C (adaptive LLM adversary) NEVER runs in this gate --
# it lives only in .github/workflows/nightly-adversary.yml.
echo
echo "== Phase 4: mutation engine self-check (8 axes, every variant byte-changes, deterministic catalogue) =="; LAST_HEADER="== Phase 4: mutation engine self-check (8 axes, every variant byte-changes, deterministic catalogue) =="
$PY eval/adversarial/mutate.py --selfcheck || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== Phase 4 Layer A: deterministic BLOCKING mutation matrix (every catalogue variant vs the real WS-2->WS-4->WS-8 path) =="; LAST_HEADER="== Phase 4 Layer A: deterministic BLOCKING mutation matrix (every catalogue variant vs the real WS-2->WS-4->WS-8 path) =="
$PY eval/adversarial/layer_a.py --seed 7 || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== Phase 4 Layer B: curated attack corpus replayed through the real path (hard positives must fire; cross-case merge check) =="; LAST_HEADER="== Phase 4 Layer B: curated attack corpus replayed through the real path (hard positives must fire; cross-case merge check) =="
$PY eval/adversarial/corpus_b.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== Phase 4 Layer A acceptance: determinism double-run, sensitivity both ways, causal-join-break = FAILURE, weakened-rule drop =="; LAST_HEADER="== Phase 4 Layer A acceptance: determinism double-run, sensitivity both ways, causal-join-break = FAILURE, weakened-rule drop =="
$PY eval/adversarial/test_layer_a.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== twin: full scorecard smoke run (report.py must complete without error on the real cascade) =="; LAST_HEADER="== twin: full scorecard smoke run (report.py must complete without error on the real cascade) =="
# PR #80 finding 10: write to a GITIGNORED last-run path, NOT the committed
# eval/twin/report.json -- a gate run must not dirty a tracked artifact.
$PY eval/twin/report.py --no-trend --out eval/twin/report.latest.json || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== WP-3-C: twin chain-fidelity graded against the real v2 incident graph (determinism + mutation-soundness) =="; LAST_HEADER="== WP-3-C: twin chain-fidelity graded against the real v2 incident graph (determinism + mutation-soundness) =="
$PY eval/twin/test_chain_fidelity.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== WP-3.5-A: twin Phase 3.5 operational outcome metrics (alert reduction, false correlation, reconstruction, investigation, severity confusion -- determinism + mutation-soundness) =="; LAST_HEADER="== WP-3.5-A: twin Phase 3.5 operational outcome metrics (alert reduction, false correlation, reconstruction, investigation, severity confusion -- determinism + mutation-soundness) =="
$PY eval/twin/test_phase3_5.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }

# == Phase 4 (2026-08-06) enhancement + fix regression tests ==
echo
echo "== ws3 FIX H6: OpenSearch multi-node writer failover (2026-08-06) =="; LAST_HEADER="== ws3 FIX H6: OpenSearch multi-node writer failover (2026-08-06) =="
$PY services/ws3-indexer/test_fix_h6_opensearch_failover.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws3 E1: audit log (append-only, admin-scoped, fail-open, capacity cap) =="; LAST_HEADER="== ws3 E1: audit log (append-only, admin-scoped, fail-open, capacity cap) =="
$PY services/ws3-indexer/test_fix_audit.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws3 E3: opt-in MFA/TOTP (stdlib generate+verify, login gating, backward compat) =="; LAST_HEADER="== ws3 E3: opt-in MFA/TOTP (stdlib generate+verify, login gating, backward compat) =="
$PY services/ws3-indexer/test_fix_mfa.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws3 FIX-4/5/6/L4: no-redirect SSRF hardening, session signing, require_auth_or_die, rate limiter =="; LAST_HEADER="== ws3 FIX-4/5/6/L4: no-redirect SSRF hardening, session signing, require_auth_or_die, rate limiter =="
$PY services/ws3-indexer/test_fix_security.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws1 E6: per-source syslog metrics (bounded, thread-safe) =="; LAST_HEADER="== ws1 E6: per-source syslog metrics (bounded, thread-safe) =="
$PY services/ws1-collectors/test_fix_metric_sources.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws1: fix-counters determinism (no double-count/race under concurrent produce) =="; LAST_HEADER="== ws1: fix-counters determinism (no double-count/race under concurrent produce) =="
$PY services/ws1-collectors/test_fix_counters_deterministic.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== H7 regression: EVTX business-hours boundary (oracle vs real engine at 18:00:00) =="; LAST_HEADER="== H7 regression: EVTX business-hours boundary (oracle vs real engine at 18:00:00) =="
$PY eval/detection_accuracy/test_evtx_eval.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws7 UX fixes: saved searches, dark mode, alert lifecycle (static assertions) =="; LAST_HEADER="== ws7 UX fixes: saved searches, dark mode, alert lifecycle (static assertions) =="
$PY services/ws7-dashboard/test_fix_ux.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== ws7 read-plane regression: LIVE ownership, outage marker, config.js gate, badge copy =="; LAST_HEADER="== ws7 read-plane regression: LIVE ownership, outage marker, config.js gate, badge copy =="
$PY services/ws7-dashboard/test_fix_read_plane.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== Phase 5 item 4 (2026-09-04): GET /assets/{mac} wired into the Inventory drill-in =="; LAST_HEADER="== Phase 5 item 4 (2026-09-04): GET /assets/{mac} wired into the Inventory drill-in =="
$PY services/ws7-dashboard/test_phase5_asset_detail.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }
echo
echo "== Phase 5 item 3 (2026-09-04): incident detail renders the causal graph + evidence package =="; LAST_HEADER="== Phase 5 item 3 (2026-09-04): incident detail renders the causal graph + evidence package =="
$PY services/ws7-dashboard/test_phase5_incident_graph_evidence.py || { fail=1; FAILED="${FAILED} ${LAST_HEADER}"; }

echo
if [ "$fail" -eq 0 ]; then
  echo "ALL TESTS PASS"
else
  echo "SOME TESTS FAILED"
  echo "failed invocations (by last section header):"
  echo "$FAILED" | tr ' ' '\n' | grep -v '^$' | sort -u
fi
exit $fail
