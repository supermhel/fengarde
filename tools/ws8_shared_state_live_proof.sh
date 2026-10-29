#!/usr/bin/env bash
# Live proof for WS-8 shared correlator state against the isolated compose project
# (infra/docker-compose.ws8-proof.yml, COMPOSE_PROJECT_NAME=ws8proof). Prints evidence; exit 1 on failure.
set -u
export COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME:-ws8proof}
DC="docker compose -f infra/docker-compose.ws8-proof.yml"
fail=0
send() {  # send <tenant> <actor> <alert_id> <tactic>  (via the real Bus in a ws8 container)
  $DC exec -T ws8a python - "$@" <<'PY'
import sys, time
from shared.bus import Bus
tenant, actor, aid, tactic = sys.argv[1:5]
Bus().produce("alerts", key=actor, payload={"alert_id": aid, "tenant_id": tenant, "time": int(time.time()*1000) - 5000,
  "rule_id": "r", "level": "high", "score": 10, "mitre": {"tactic": tactic}, "actor": {"user": {"name": actor}}})
PY
}
incidents() { $DC exec -T redis redis-cli --raw XRANGE incidents - + | python -c "
import sys, json
lines = sys.stdin.read().split('\n')
out = []
for i, l in enumerate(lines):
    if l == 'payload':
        out.append(json.loads(lines[i+1]))
for p in out:
    print(p['incident_id'], p['tactics'], 'members=%d' % p['member_count'])
"; }
echo "### A. restart survival: tactic 1 -> kill ws8 -> restart -> tactic 2"
$DC stop ws8b >/dev/null 2>&1
send acme alice a-1 TA0006; sleep 3
echo "tracks in Redis after alert 1:"; $DC exec -T redis redis-cli --scan --pattern 'ws8:state:*'
$DC kill ws8a >/dev/null; echo "ws8a KILLED"; $DC up -d ws8a >/dev/null; sleep 6
send acme alice a-2 TA0008; sleep 4
out=$(incidents | grep 'acme:actor:alice'); echo "$out"
echo "$out" | grep -q "TA0006.*TA0008.*members=2" && echo "RESULT A: PASS (incident formed across a restart)" || { echo "RESULT A: FAIL"; fail=1; }
echo
echo "### B. two replicas share state: 10 chains, alerts split across both replicas"
$DC up -d ws8a ws8b >/dev/null; sleep 6
for i in $(seq 1 10); do send acme "u$i" "b-$i-1" TA0006; send acme "u$i" "b-$i-2" TA0008; done
sleep 8
for r in ws8a ws8b; do echo "$r handled: $($DC logs $r 2>/dev/null | grep -c 'alerts' ) log lines mentioning alerts"; done
$DC exec -T redis redis-cli XINFO CONSUMERS alerts cg-correlate | tr '\n' ' ' | sed 's/name/\nname/g'; echo
ids=$(incidents | grep -E 'acme:actor:u[0-9]+:' | awk '{print $1}' | sort -u | wc -l)
full=$(incidents | grep -E 'acme:actor:u[0-9]+:' | grep -c 'members=2')
echo "distinct incident ids for 10 chains: $ids ; emissions with both members: $full"
[ "$ids" = 10 ] && [ "$full" -ge 10 ] && echo "RESULT B: PASS (one incident per chain, 2 members each)" || { echo "RESULT B: FAIL"; fail=1; }
exit $fail
