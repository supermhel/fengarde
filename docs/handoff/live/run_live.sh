#!/usr/bin/env bash
# Live verification lane, sequential. Each step prints "RESULT <name> rc=<n> <secs>s".
cd "/c/Users/Mel Dylan Djomou/Claude/Projects/SIEM App" || exit 2
export MSYS_NO_PATHCONV=1
step() {
  local name="$1"; shift
  local s=$(date +%s)
  echo "=================== $name"
  "$@" 2>&1 | tail -n 25
  local rc=${PIPESTATUS[0]}
  echo "RESULT $name rc=$rc $(( $(date +%s) - s ))s"
}
step container_smoke env FENGARDE_E2E_STRICT=1 python tools/container_smoke.py
step live_companion_e2e env FENGARDE_E2E_STRICT=1 python tools/live_companion_e2e.py
step live_companion_selfcheck python tools/live_companion_e2e.py --selfcheck

docker rm -f live-redis >/dev/null 2>&1
docker run -d --name live-redis -p 6390:6379 redis:7 >/dev/null 2>&1 && sleep 3
export BUS_BACKEND=redis REDIS_URL=redis://localhost:6390/0 BUS_PARITY_REDIS_URL=redis://localhost:6390/0
for t in services/shared/test_runner.py services/shared/test_bus_trim_acked.py services/shared/test_bus_lag.py \
         services/shared/test_bus_read_count.py services/shared/test_ack_batching.py services/shared/test_sessions.py \
         services/ws4-detection/test_window.py services/shared/test_bus_wire_parity.py; do
  step "redis:$t" python "$t"
done
unset BUS_BACKEND REDIS_URL BUS_PARITY_REDIS_URL

step opensearch_live python services/ws3-indexer/storage/test_opensearch_live.py
step migrate_opensearch python tools/test_migrate_opensearch.py
step opensearch_cas python services/ws3-indexer/storage/test_opensearch_cas_concurrency_live.py
step opensearch_shared python services/ws3-indexer/storage/test_opensearch_shared_store_concurrent_live.py

docker build -q -f services/ws3-indexer/Dockerfile -t ws3-indexer-mfa-e2e . >/dev/null 2>&1
docker rm -f mfa-e2e >/dev/null 2>&1
docker run -d --name mfa-e2e ws3-indexer-mfa-e2e tail -f /dev/null >/dev/null 2>&1
docker cp services/ws3-indexer/test_mfa_live_e2e.py mfa-e2e:/tmp/test_mfa_live_e2e.py
step mfa_live_e2e docker exec mfa-e2e python /tmp/test_mfa_live_e2e.py
docker rm -f mfa-e2e >/dev/null 2>&1

step chaos_test python tools/chaos_test.py
docker rm -f live-redis >/dev/null 2>&1
echo "ALL-LIVE-DONE"
