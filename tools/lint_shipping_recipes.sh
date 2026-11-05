#!/usr/bin/env bash
# OPTIONAL config lint for docs/shipping/configs/. NOT part of the default gate.
# Each tool is skipped (not failed) when it is not installed. Exit 1 only if an installed tool rejects a config.
# Flags below are from vendor docs and unverified here (none of these tools were available when this was written).
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)/docs/shipping/configs"
export FENGARDE_INGEST_TOKEN="${FENGARDE_INGEST_TOKEN:-lint-placeholder}" COMPUTERNAME="${COMPUTERNAME:-lint-host}"
rc=0
run() { # tool, description, command...
  local tool="$1"; shift
  if ! command -v "$tool" >/dev/null 2>&1; then echo "SKIP $1 ($tool not installed)"; return; fi
  if "${@:2}" >/dev/null 2>&1; then echo "OK   $1"; else echo "FAIL $1"; rc=1; fi
}
for f in "$DIR"/vector-*.toml; do run vector "$(basename "$f")" vector validate --no-environment "$f"; done
for f in "$DIR"/fluent-bit-*.conf; do
  [ "$(basename "$f")" = fluent-bit-docker-parsers.conf ] && continue
  run fluent-bit "$(basename "$f")" fluent-bit --dry-run -c "$f"
done
for f in "$DIR"/rsyslog-*.conf; do run rsyslogd "$(basename "$f")" rsyslogd -N1 -f "$f"; done
for f in "$DIR"/syslog-ng-*.conf; do run syslog-ng "$(basename "$f")" syslog-ng --syntax-only -f "$f"; done
exit $rc
