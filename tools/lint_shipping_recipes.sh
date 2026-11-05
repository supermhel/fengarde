#!/usr/bin/env bash
# OPTIONAL config lint for docs/shipping/configs/. NOT part of the default gate.
# A tool that is not installed is skipped (not failed); so are Windows-only (winevtlog) and journald configs on a non-matching OS.
# Exit 1 only if an installed tool rejects a config; the tool's output stays visible on FAIL.
# Flags below are from vendor docs and unverified here (none of these tools were available when this was written).
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)/docs/shipping/configs"
export FENGARDE_INGEST_TOKEN="${FENGARDE_INGEST_TOKEN:-lint-placeholder}" COMPUTERNAME="${COMPUTERNAME:-lint-host}"
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) OS=windows ;; Linux) OS=linux ;; *) OS=other ;; esac
rc=0
run() { # tool, config file (basename), command... ; each tool runs with the config's directory as cwd (relative script/parser paths)
  local tool="$1" name="$2"; shift 2
  if ! command -v "$tool" >/dev/null 2>&1; then echo "SKIP $name ($tool not installed)"; return; fi
  case "$name" in
    fluent-bit-windows.conf) [ "$OS" = windows ] || { echo "SKIP $name (Windows-only winevtlog input; this is $OS)"; return; } ;;
    *journald*) [ "$OS" = linux ] || { echo "SKIP $name (needs a systemd journal; this is $OS)"; return; } ;;
  esac
  local out
  if out="$(cd "$DIR" && "$@" 2>&1)"; then echo "OK   $name"; else echo "FAIL $name"; echo "$out" | sed 's/^/     | /'; rc=1; fi
}
for f in "$DIR"/vector-*.toml; do n="$(basename "$f")"; run vector "$n" vector validate --no-environment "$n"; done
for f in "$DIR"/fluent-bit-*.conf; do
  n="$(basename "$f")"
  [ "$n" = fluent-bit-docker-parsers.conf ] && continue
  run fluent-bit "$n" fluent-bit --dry-run -c "$n"
done
for f in "$DIR"/rsyslog-*.conf; do n="$(basename "$f")"; run rsyslogd "$n" rsyslogd -N1 -f "$n"; done
for f in "$DIR"/syslog-ng-*.conf; do n="$(basename "$f")"; run syslog-ng "$n" syslog-ng --syntax-only -f "$n"; done
exit $rc
