#!/bin/sh
# FENGARDE pre-flight "doctor".
#
# Checks this machine is ready to run the FENGARDE stack BEFORE Docker starts, so a
# first run fails with a plain-English remedy instead of a JVM stack trace.
#
# Checks:
#   1. vm.max_map_count >= 262144  (OpenSearch won't boot otherwise on Linux/WSL2)
#   2. Docker is installed and the daemon is reachable (+ a >= 4 GB RAM hint)
#   3. The ports FENGARDE publishes are free (TCP 6379, 9200, 5601, 8000, 8080;
#      UDP 5514 -- ws1-collectors' syslog listener, easy to miss since every
#      other port here is TCP)
#
# Exits non-zero if a BLOCKER is found. POSIX sh; works on Linux, macOS, WSL2.
set -u

REQUIRED_MAP_COUNT=262144
TCP_PORTS="6379 9200 5601 8000 8080"
UDP_PORTS="5514"

problems=0
warnings=0

note()  { printf '  %s\n' "$1"; }
ok()    { printf '  [ OK ]   %s\n' "$1"; }
warn()  { printf '  [ WARN ] %s\n' "$1"; warnings=$((warnings + 1)); }
fail()  { printf '  [ FAIL ] %s\n' "$1"; problems=$((problems + 1)); }

# Detect OS so we can tailor remedies / skip Linux-only checks.
OS="$(uname -s 2>/dev/null || echo unknown)"

echo "FENGARDE pre-flight check"
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
      fail "Could not read vm.max_map_count. OpenSearch WILL crash on boot if it is"
      note "         too low. Could you check it yourself, then set:"
      note "         sudo sysctl -w vm.max_map_count=$REQUIRED_MAP_COUNT"
    elif [ "$current" -ge "$REQUIRED_MAP_COUNT" ] 2>/dev/null; then
      ok "vm.max_map_count = $current (>= $REQUIRED_MAP_COUNT)"
    else
      fail "vm.max_map_count = $current — too low; OpenSearch will crash on boot."
      note "         Fix (this boot):"
      note "           sudo sysctl -w vm.max_map_count=$REQUIRED_MAP_COUNT"
      note "         Fix (persist across reboots):"
      note "           echo 'vm.max_map_count=$REQUIRED_MAP_COUNT' | sudo tee /etc/sysctl.d/99-fengarde.conf"
    fi
    ;;
  Darwin)
    ok "macOS: vm.max_map_count is managed inside the Docker Desktop VM (skipped)."
    note "         If OpenSearch still fails to boot, ensure Docker Desktop is up to date."
    ;;
  *)
    fail "Unknown OS ($OS): cannot verify vm.max_map_count -- cannot bless this machine."
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
      warn "Docker has only ~${mem_gib} GiB RAM; FENGARDE needs >= 4 GB."
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
echo "3. Required ports are free (TCP: $TCP_PORTS; UDP: $UDP_PORTS)"
# proto: "tcp" or "udp". UDP support was previously missing entirely -- this
# check only ever looked at TCP listeners, so port 5514 (ws1-collectors'
# syslog UDP listener, published on all interfaces by docker-compose.yml)
# was never verified free even though every other published port was.
#
# Gap-hunt (2026-08-26): with NONE of lsof/ss/netstat installed, every probe
# landed in the `return 2` "no tool available" branch and the script ended
# with a single WARN + exit 0 -- a pre-flight that PASSED having verified
# ZERO ports. That is the one outcome worse than failing: an operator with
# something already on :9200 got told "You're ready: run 'make demo'". This
# is now a hard FAIL -- pre-flight must not bless a machine it could not
# check. (rc==2 below is kept only as a defensive tripwire; the guard above
# makes it unreachable.)
if ! command -v lsof >/dev/null 2>&1 && ! command -v ss >/dev/null 2>&1 && ! command -v netstat >/dev/null 2>&1; then
  fail "No port-checking tool found (lsof/ss/netstat) -- cannot verify required ports are free."
  note "         Install one of:  iproute2 (ss)  |  lsof  |  net-tools (netstat)"
  note "         Debian/Ubuntu: sudo apt install iproute2   |   RHEL: sudo dnf install iproute"
else
  port_in_use() {
    p="$1"; proto="$2"
    if command -v lsof >/dev/null 2>&1; then
      if [ "$proto" = "udp" ]; then
        lsof -iUDP:"$p" -Pn >/dev/null 2>&1 && return 0 || return 1
      fi
      lsof -iTCP:"$p" -sTCP:LISTEN -Pn >/dev/null 2>&1 && return 0 || return 1
    fi
    if command -v ss >/dev/null 2>&1; then
      if [ "$proto" = "udp" ]; then
        ss -lun 2>/dev/null | grep -q "[:.]$p[[:space:]]" && return 0 || return 1
      fi
      ss -ltn 2>/dev/null | grep -q "[:.]$p[[:space:]]" && return 0 || return 1
    fi
    if command -v netstat >/dev/null 2>&1; then
      if [ "$proto" = "udp" ]; then
        netstat -an 2>/dev/null | grep -i '^udp' | grep -q "[:.]$p[[:space:]]" && return 0 || return 1
      fi
      netstat -an 2>/dev/null | grep -i 'listen' | grep -q "[:.]$p[[:space:]]" && return 0 || return 1
    fi
    return 2  # no tool available -> unknown (unreachable: guarded above)
  }
  for p in $TCP_PORTS; do
    port_in_use "$p" tcp
    rc=$?
    if [ "$rc" -eq 0 ]; then
      fail "TCP port $p is already in use — FENGARDE needs it free."
      note "         Find the process:  lsof -iTCP:$p -sTCP:LISTEN   (or: ss -ltnp | grep $p)"
      note "         Then stop it, or change the host port mapping in infra/docker-compose.yml."
    elif [ "$rc" -eq 2 ]; then
      fail "TCP port $p could not be checked (no lsof/ss/netstat)."
    fi
  done
  for p in $UDP_PORTS; do
    port_in_use "$p" udp
    rc=$?
    if [ "$rc" -eq 0 ]; then
      fail "UDP port $p is already in use — ws1-collectors' syslog listener needs it free."
      note "         Find the process:  lsof -iUDP:$p   (or: ss -lunp | grep $p)"
      note "         Then stop it, or change SYSLOG_UDP_PORT / the host port mapping."
    elif [ "$rc" -eq 2 ]; then
      fail "UDP port $p could not be checked (no lsof/ss/netstat)."
    fi
  done
fi
echo ""

# --- 4. REDIS_PASSWORD URL safety -------------------------------------------------
# R3-28: infra/docker-compose.yml interpolates the bus URL as
# redis://:${REDIS_PASSWORD}@redis:6379/0 -- no URL-encoding. If the password
# contains one of the reserved URL characters (@ : / %), the URL is malformed:
# the password (or a split after "/") corrupts the URL and every service that
# builds its Redis client off REDIS_URL fails to authenticate, with an opaque
# "wrong number of arguments for 'auth'"-class error. Best-fail-loud: block
# REDIS_PASSWORD (when set) from containing those characters, so an operator
# finds out in the doctor, not after a green-looking `make up`.
echo "4. REDIS_PASSWORD (if set) contains no unencoded URL-reserved characters"
if [ -n "${REDIS_PASSWORD:-}" ]; then
  case "$REDIS_PASSWORD" in
    *'@'*|*':'*|*'/'*|*'%'*)
      fail "REDIS_PASSWORD contains @, :, /, or % -- those break the bus URL"
      note "         (infra/docker-compose.yml uses redis://:${REDIS_PASSWORD}@redis:6379)."
      note "         Set REDIS_PASSWORD to a value without those characters and re-run:"
      note "           export REDIS_PASSWORD=\$(openssl rand -hex 16)"
      ;;
    *)
      ok "REDIS_PASSWORD is URL-safe (no @ : / % characters)."
      ;;
  esac
else
  note "         (REDIS_PASSWORD unset -> Redis AUTH off; nothing to check.)"
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
