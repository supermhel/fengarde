#!/usr/bin/env bash
# Live proof for WS-8 shared correlator state on the Redis SENTINEL path
# (infra/docker-compose.ws8-sentinel-proof.yml, COMPOSE_PROJECT_NAME=ws8sentproof). Exit 1 on failure.
#   B. 2 replicas, per-alert trace (log line "handled alert" carrying the replica hostname), 20 chains
#   A. kill the Redis MASTER between the two tactics of one chain; the incident must still form once
set -u
export COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME:-ws8sentproof}
export REDIS_PASSWORD=${REDIS_PASSWORD:-proofpw}
DC="docker compose -f infra/docker-compose.ws8-sentinel-proof.yml"
TRACE_PY="$(dirname "$0")/ws8_sentinel_trace.py"
fail=0

send() {  # send <actor> <alert_id> <tactic>; retries across a failover window
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if $DC exec -T ws8a python -c '
import sys, time
from shared.bus import Bus
actor, aid, tactic = sys.argv[1:4]
Bus().produce("alerts", key=actor, payload={"alert_id": aid, "tenant_id": "acme", "time": int(time.time()*1000) - 5000,
  "rule_id": "r", "level": "high", "score": 10, "mitre": {"tactic": tactic}, "actor": {"user": {"name": actor}}})
' "$@" 2>/dev/null; then return 0; fi
    sleep 3
  done
  echo "send $2 FAILED"; return 1
}
incidents() {  # emitted incidents, read through Sentinel (follows the current master)
  $DC exec -T ws8a python -c '
import json
from shared.window import redis_client_for_backend
for _id, f in redis_client_for_backend("redis-sentinel").xrange("incidents"):
    p = json.loads(f["payload"])
    print(p["incident_id"], p["tactics"], "members=%d" % p["member_count"])
'
}
master() { $DC exec -T sentinel-1 redis-cli -p 26379 sentinel get-master-addr-by-name mymaster | head -1 | tr -d '\r'; }
trace() { for r in ws8a ws8b; do $DC logs --no-log-prefix "$r" 2>/dev/null | grep 'handled alert' | sed "s/^/$r /"; done; }

echo "master at start: $(master)"
for r in ws8a ws8b; do echo "$r: $($DC logs --no-log-prefix $r 2>/dev/null | grep -o 'track_state[^,}]*' | head -1)"; done

echo; echo "### B. two replicas, per-alert trace (20 chains = 40 alerts)"
for i in $(seq 1 20); do send "u$i" "b-$i-1" TA0006; send "u$i" "b-$i-2" TA0008; done
sleep 8
trace > "$TRACE_PY.log"
read -r traced nrep nsplit < <(python "$TRACE_PY" "$TRACE_PY.log")
rm -f "$TRACE_PY.log"
inc=$(incidents | grep -E 'acme:actor:u[0-9]+:')
ids=$(echo "$inc" | awk '{print $1}' | sort -u | wc -l); full=$(echo "$inc" | grep -c 'members=2')
echo "distinct incident ids: $ids ; emissions with both members: $full"
if [ "$traced" = 40 ] && [ "$nrep" = 2 ] && [ "$nsplit" -ge 1 ] && [ "$ids" = 20 ]; then
  echo "RESULT B: PASS (both replicas handled alerts, $nsplit chains had their tactics on different replicas, one incident per chain)"
else echo "RESULT B: FAIL"; fail=1; fi

echo; echo "### A. kill the Redis MASTER between the two tactics"
old=$(master); send carol c-1 TA0006; sleep 3
trace | grep c-1
echo "state keys for carol before the kill:"
$DC exec -T ws8a python -c '
from shared.window import redis_client_for_backend
print(sorted(redis_client_for_backend("redis-sentinel").scan_iter("ws8:state:*carol*")))'
$DC kill redis-1 >/dev/null; echo "redis-1 (master $old) KILLED at $(date +%T)"
n=$old
for i in $(seq 1 60); do n=$(master); [ -n "$n" ] && [ "$n" != "$old" ] && break; sleep 1; done
echo "new master: $n (after ~${i}s of polling)"
send carol c-2 TA0008
out=
for _ in $(seq 1 20); do out=$(incidents | grep 'acme:actor:carol'); [ -n "$out" ] && break; sleep 2; done
trace | grep c-2
echo "$out"
cnt=$(echo "$out" | grep -c .); uniq=$(echo "$out" | awk '{print $1}' | sort -u | wc -l)
echo "carol emissions=$cnt distinct incident ids=$uniq"
if echo "$out" | grep -q "TA0006.*TA0008.*members=2" && [ "$uniq" = 1 ] && [ "$n" != "$old" ]; then
  echo "RESULT A: PASS (master killed mid-chain, failover to $n, one incident id with 2 members, emissions=$cnt)"
else echo "RESULT A: FAIL"; fail=1; fi
exit $fail
