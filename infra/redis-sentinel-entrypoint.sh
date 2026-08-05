#!/bin/sh
set -eu
if [ -z "${REDIS_PASSWORD:-}" ]; then
  echo "REDIS_PASSWORD must be set for HA Sentinel" >&2
  exit 1
fi
MASTER_NAME="${REDIS_SENTINEL_MASTER:-mymaster}"
cat > /tmp/sentinel.conf <<EOF
port 26379
sentinel resolve-hostnames yes
sentinel announce-hostnames yes
sentinel monitor ${MASTER_NAME} ${REDIS_SENTINEL_PRIMARY_HOST:-redis-1} ${REDIS_SENTINEL_PRIMARY_PORT:-6379} 2
sentinel auth-pass ${MASTER_NAME} ${REDIS_PASSWORD}
sentinel down-after-milliseconds ${MASTER_NAME} 5000
sentinel parallel-syncs ${MASTER_NAME} 1
sentinel failover-timeout ${MASTER_NAME} 60000
EOF
exec redis-sentinel /tmp/sentinel.conf
