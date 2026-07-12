#!/bin/sh
# ARGIEM pre-flight "doctor".
#
# Checks this machine is ready to run the ARGIEM stack BEFORE Docker starts, so a
# first run fails with a plain-English remedy instead of a JVM stack trace.
#
# Checks:
#   1. vm.max_map_count >= 262144  (OpenSearch won't boot otherwise on Linux/WSL2)
#   2. Docker is installed and the daemon is reachable (+ a >= 4 GB RAM hint)
#   3. The ports ARGIEM publishes are free (6379, 9200, 5601, 8000, 8080)
#
# Exits non-zero if a BLOCKER is found. POSIX sh; works on Linux, macOS, WSL2.
set -u

REQUIRED_MAP_COUNT=262144
PORTS="6379 9200 5601 8000 8080"

problems=0
warnings=0

note()  { printf '  %s\n' "$1"; }
ok()    { printf '  [ OK ]   %s\n' "$1"; }
warn()  { printf '  [ WARN ] %s\n' "$1"; warnings=$((warnings + 1)); }
fail()  { printf '  [ FAIL ] %s\n' "$1"; problems=$((problems + 1)); }

# Detect OS so we can tailor remedies / skip Linux-only checks.
OS="$(uname -s 2>/dev/null || echo unknown)"

echo "ARGIEM pre-flight check"
echo "----------------------"

# --- 1. vm.max_map_count -------------------------------------------------------
echo "1. Kernel: vm.max_map_count (OpenSearch requirement)"
case "$OS" in
  Linux)
    current=""
    if [ -r /proc/sys/vm/max_map_count ]; then
      current="$(cat /proc/sys/vm/max_map_count 2>/dev/null)"
    elif command -v sysctl >/dev/null 2>&1; then
      current="$(sysctl -n vm.max_map_count 2>/dev/null)"
    fi
    if [ -z "$current" ]; then
      warn "Could not read vm.max_map_count. If OpenSearch fails to boot, run:"
      note "         sudo sysctl -w vm.max_map_count=$REQUIRED_MAP_COUNT"
    elif [ "$current" -ge "$REQUIRED_MAP_COUNT" ] 2>/dev/null; then
      ok "vm.max_map_count = $current (>= $REQUIRED_MAP_COUNT)"
    else
      fail "vm.max_map_count = $current — too low; OpenSearch will crash on boot."
      note "         Fix (this boot):"
      note "           sudo sysctl -w vm.max_map_count=$REQUIRED_MAP_COUNT"
      note "         Fix (persist across reboots):"
      note "           echo 'vm.max_map_count=$REQUIRED_MAP_COUNT' | sudo tee /etc/sysctl.d/99-argiem.conf"
    fi
    ;;
  Darwin)
    ok "macOS: vm.max_map_count is managed inside the Docker Desktop VM (skipped)."
    note "         If OpenSearch still fails to boot, ensure Docker Desktop is up to date."
    ;;
  *)
    warn "Unknown OS ($OS): cannot check vm.max_map_count."
    note "         On Linux/WSL2 this must be >= $REQUIRED_MAP_COUNT:"
    note "           sudo sysctl -w vm.max_map_count=$REQUIRED_MAP_COUNT"
    ;;
esac
echo ""

# --- 2. Docker -----------------------------------------------------------------
echo "2. Docker engine + memory"
if ! command -v docker >/dev/null 2>&1; then
  fail "Docker is not installed (or not on PATH)."
  note "         Install Docker Desktop (>= 4 GB RAM) or Docker Engine + Compose v2:"
  note "           https://docs.docker.com/get-docker/"
elif ! docker info >/dev/null 2>&1; then
  fail "Docker is installed but the daemon is not reachable."
  note "         Start Docker Desktop (or 'sudo systemctl start docker') and retry."
else
  ok "Docker daemon is reachable."
  # Best-effort RAM check (field name varies; treat as a hint, never a blocker).
  mem_bytes="$(docker info --format '{{.MemTotal}}' 2>/dev/null || echo '')"
  if [ -n "$mem_bytes" ] && [ "$mem_bytes" -gt 0 ] 2>/dev/null; then
    mem_gib=$((mem_bytes / 1024 / 1024 / 1024))
    if [ "$mem_gib" -ge 4 ] 2>/dev/null; then
      ok "Docker has ~${mem_gib} GiB RAM (>= 4 GB recommended)."
    else
      warn "Docker has only ~${mem_gib} GiB RAM; ARGIEM needs >= 4 GB."
      note "         Raise it in Docker Desktop -> Settings -> Resources -> Memory."
    fi
  else
    note "         (Could not read Docker memory; ensure >= 4 GB is allocated.)"
  fi
  # Compose v2?
  if ! docker compose version >/dev/null 2>&1; then
    fail "'docker compose' (v2) is not available."
    note "         Install the Docker Compose v2 plugin: https://docs.docker.com/compose/install/"
  else
    ok "docker compose (v2) is available."
  fi
fi
echo ""

# --- 3. Port availability ------------------------------------------------------
echo "3. Required ports are free ($PORTS)"
port_in_use() {
  p="$1"
  if command -v lsof >/dev/null 2>&1; then
    lsof -iTCP:"$p" -sTCP:LISTEN -Pn >/dev/null 2>&1 && return 0 || return 1
  fi
  if command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | grep -q "[:.]$p[[:space:]]" && return 0 || return 1
  fi
  if command -v netstat >/dev/null 2>&1; then
    netstat -an 2>/dev/null | grep -i 'listen' | grep -q "[:.]$p[[:space:]]" && return 0 || return 1
  fi
  return 2  # no tool available -> unknown
}
checked_ports=0
for p in $PORTS; do
  port_in_use "$p"
  rc=$?
  if [ "$rc" -eq 0 ]; then
    fail "Port $p is already in use — ARGIEM needs it free."
    note "         Find the process:  lsof -iTCP:$p -sTCP:LISTEN   (or: ss -ltnp | grep $p)"
    note "         Then stop it, or change the host port mapping in infra/docker-compose.yml."
  elif [ "$rc" -eq 2 ]; then
    checked_ports=1
  fi
done
if [ "$checked_ports" -eq 1 ]; then
  warn "No port-checking tool found (lsof/ss/netstat); could not verify ports."
fi
echo ""

# --- Summary -------------------------------------------------------------------
echo "----------------------"
if [ "$problems" -gt 0 ]; then
  echo "PRE-FLIGHT FAILED: $problems blocker(s), $warnings warning(s)."
  echo "Fix the [FAIL] items above, then re-run: make preflight"
  exit 1
fi
if [ "$warnings" -gt 0 ]; then
  echo "PRE-FLIGHT PASSED with $warnings warning(s). Review the [WARN] items above."
else
  echo "PRE-FLIGHT PASSED. You're ready: run 'make demo'."
fi
exit 0
