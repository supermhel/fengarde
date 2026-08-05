#!/bin/sh
set -eu
if [ -z "${REDIS_PASSWORD:-}" ]; then
  echo "REDIS_PASSWORD must be set for HA Sentinel" >&2
  exit 1
fi
cat > /tmp/sentinel.conf <<EOF
port 26379
sentinel monitor mymaster ${REDIS_SENTINEL_MASTER:-mymaster} ${REDIS_SENTINEL_PRIMARY_HOST:-redis-1} ${REDIS_SENTINEL_PRIMARY_PORT:-6379} 2
sentinel auth-pass mymaster ${REDIS_PASSWORD}
sentinel down-after-milliseconds mymaster 5000
sentinel parallel-syncs mymaster 1
sentinel failover-timeout mymaster 60000
EOF
exec redis-sentinel /tmp/sentinel.conf
