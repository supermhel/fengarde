#!/usr/bin/env bash
# CI gate: Phase 0 contract validator + every workstream's contract test.
# Zero infrastructure required (memory bus, in-memory stores, stub LLM).
set -u
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
PY="${PYTHON:-python3}"
fail=0

echo "== Phase 0: contract validator =="
$PY tools/validate_contract.py || fail=1
echo
echo "== A6: anti-dormancy check (rules must be satisfiable by a real parser) =="
$PY tools/check_rule_producers.py || fail=1
echo
echo "== B4: rule validation gate (schema, condition parse, operator safety) =="
$PY tools/validate_rules.py || fail=1
$PY tools/test_validate_rules.py || fail=1

for ws in ws1-collectors ws2-normalization ws3-indexer ws4-detection ws5-ai ws6-inventory ws7-dashboard; do
  echo
  echo "== $ws =="
  ( cd "services/$ws" && $PY test_contract.py ) || fail=1
done

echo
echo "== ws3 v0.3 (C1): triage API (persistence, tolerant defaults, malformed input) =="
$PY services/ws3-indexer/test_triage_api.py || fail=1
echo
echo "== ws3: optimistic concurrency (CAS) for multi-replica triage writes =="
$PY services/ws3-indexer/test_storage_cas.py || fail=1
echo
echo "== ws3 (P1.3): OpenSearch index transient-retry / permanent-surface =="
$PY services/ws3-indexer/test_opensearch_retry.py || fail=1
echo
echo "== v0.4 (S1): opt-in API-key auth (ws3 triage, ws6 inventory) =="
$PY services/ws3-indexer/test_auth.py || fail=1
$PY services/ws6-inventory/test_auth.py || fail=1
echo
echo "== M4.2 RBAC: users/sessions/roles (unit) =="
$PY services/shared/test_rbac.py || fail=1
echo
echo "== M4.2 RBAC: login/logout/roles/tenant isolation (real HTTP) =="
$PY services/ws3-indexer/test_rbac_api.py || fail=1
echo
echo "== v0.4 (R): incident-report hook (template backend, contract, HTTP fallback) =="
$PY services/ws3-indexer/test_reporting.py || fail=1

# Extended zero-infra suite (runner, window counters, boolean evaluator, e2e).
# Still no Docker/Redis/OpenSearch — all on the memory bus + in-memory store.
echo
echo "== shared runner =="
$PY services/shared/test_runner.py || fail=1
echo
echo "== shared envelope v1 (M1) =="
$PY services/shared/test_envelope.py || fail=1
echo
echo "== ws2 property-based parser hardening (M1, Hypothesis) =="
$PY services/ws2-normalization/parsers/test_property_hardening.py || fail=1
echo
echo "== ws2 log-injection defense (M1, ANSI/control-char sanitize) =="
$PY services/ws2-normalization/test_sanitize.py || fail=1
echo
echo "== ws4 window counters (T6) =="
$PY services/ws4-detection/test_window.py || fail=1
echo
echo "== ws4 boolean evaluator + alert id (T4/T7) =="
$PY services/ws4-detection/test_engine_boolean.py || fail=1
echo
echo "== ws4 P0 hardening: time-guard (poison/future) + alert-id collapse =="
$PY services/ws4-detection/test_engine_hardening.py || fail=1
echo
echo "== ws4 distinct-count window + port-scan/lateral-movement rules (v0.2) =="
$PY services/ws4-detection/test_window_distinct.py || fail=1
$PY services/ws4-detection/test_engine_distinct_rules.py || fail=1
echo
echo "== ws4 v0.3: password-spray + priv-grant fire on REAL parser output =="
$PY services/ws4-detection/test_v03_new_rules.py || fail=1
echo
echo "== ws4 v0.4 (P4): impossible-travel fires on REAL parser + enrichment output =="
$PY services/ws4-detection/test_v04_new_rules.py || fail=1
echo
echo "== ws4 agent rule pack (PLAN_A P3 R1/R3/R4/R5): fire on REAL parser output =="
$PY services/ws4-detection/test_v05_agent_rules.py || fail=1
echo
echo "== ws4 v0.3 (A3): rule grammar (comparison ops + allowlist), fail-closed =="
$PY services/ws4-detection/test_v03_rule_grammar.py || fail=1
echo
echo "== ws4 v0.3 (A3): time-of-day predicate (outside_hours) + after-hours rule =="
$PY services/ws4-detection/test_v03_time_predicate.py || fail=1
echo
echo "== ws4 v0.4 (P1.7): rule tuning (after-hours service-account allowlist) =="
$PY services/ws4-detection/test_v04_rule_tuning.py || fail=1
echo
echo "== ws2 parsers: generic syslog + windows event log (v0.2) =="
$PY services/ws2-normalization/parsers/test_generic_syslog.py || fail=1
$PY services/ws2-normalization/parsers/test_windows_eventlog.py || fail=1
echo
echo "== ws2 registry routing (P0.4: non-shadowing content-sniff) =="
$PY services/ws2-normalization/parsers/test_registry_routing.py || fail=1
echo
echo "== ws2 parser hardening (P0.5-7: port guard, IP bounds, status-from-outcome) =="
$PY services/ws2-normalization/parsers/test_parser_hardening.py || fail=1
echo
echo "== ws2 A5 enrichment (reputation + geo, additive/offline/fail-open) =="
$PY services/ws2-normalization/enrichment/test_enrichment.py || fail=1
echo
echo "== ws2 timeutil (P1.6: epoch/ISO/FILETIME normalization) =="
$PY services/ws2-normalization/parsers/test_timeutil.py || fail=1
echo
echo "== ws2 parsers: db_audit (v0.3, un-dormants bank_db_priv_esc.yml) =="
$PY services/ws2-normalization/parsers/test_db_audit.py || fail=1
echo
echo "== ws2 parsers: mcp_agent (v0.4 P1, agent/MCP tool-call audit rules) =="
$PY services/ws2-normalization/parsers/test_mcp_agent.py || fail=1
echo
echo "== ws2 parsers: opcua_audit (v0.4 P2, OT/industrial control-system rules) =="
$PY services/ws2-normalization/parsers/test_opcua_audit.py || fail=1
echo
echo "== ws2 parsers: n8n_audit (v0.4 P3, automation-platform rules) =="
$PY services/ws2-normalization/parsers/test_n8n_audit.py || fail=1
echo
echo "== ws5 ollama adapter + fallback (v0.2) =="
$PY services/ws5-ai/test_llm_adapter.py || fail=1
echo
echo "== ws1 syslog UDP listener (v0.2) =="
$PY services/ws1-collectors/test_syslog_udp.py || fail=1
echo
echo "== integration e2e (WS-1->2->4->3) =="
$PY tools/integration_e2e.py || fail=1
echo
echo "== acceptance e2e (brute-force -> alert, idempotent) =="
$PY tools/demo_e2e.py || fail=1
echo
echo "== agent_log_shipper e2e (JSONL file -> raw.events -> R1+R3 alerts) =="
$PY tools/test_agent_log_shipper.py || fail=1
echo
echo "== M4 gate: two-tenant isolation (separate indices, per-tenant rule enablement) =="
$PY tools/test_multi_tenant_isolation.py || fail=1

echo
if [ "$fail" -eq 0 ]; then echo "ALL TESTS PASS"; else echo "SOME TESTS FAILED"; fi
exit $fail
