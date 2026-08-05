#!/bin/sh
set -eu
if [ -z "${REDIS_PASSWORD:-}" ]; then
  echo "REDIS_PASSWORD must be set for HA Sentinel" >&2
  exit 1
fi
MASTER_NAME="${REDIS_SENTINEL_MASTER:-mymaster}"
RAW_HOST="${REDIS_SENTINEL_PRIMARY_HOST:-172.28.0.11}"
RAW_PORT="${REDIS_SENTINEL_PRIMARY_PORT:-6379}"

# Resolve the primary to an IP HERE, in the shell, once, at startup -- never
# inside Sentinel's event loop.
#
# Live-verified bug (2026-08-05, measured not inferred): the previous config
# used `sentinel resolve-hostnames yes` and monitored the primary by the
# hostname `redis-1`. Sentinel then re-resolves that hostname on every health
# check, using a BLOCKING getaddrinfo() on its single-threaded event loop. When
# the primary container dies, Docker's embedded DNS (127.0.0.11) no longer has
# the name and forwards the query upstream, where it takes the stock resolv.conf
# timeout to come back NXDOMAIN. Measured from inside this container: an
# existing name resolves in 0.00s, a dead/unknown name takes 5.06s.
#
# Sentinel's TILT trigger is a hardcoded 2000ms (SENTINEL_TILT_TRIGGER in
# sentinel.c -- a compile-time constant, NOT settable from this config file), so
# a 5.06s stall trips it every time. TILT suspends the failover state machine
# for 30s; on exit Sentinel immediately retries the same dead hostname, blocks
# 5s again, and re-tilts. Observed live: perpetual `+tilt` loop, `+sdown master`
# but never `+odown`, never `+try-failover`, zero promotions -- the primary
# stayed dead and every replica sat at `master_link_status:down` indefinitely.
# `SENTINEL ckquorum` reported OK the whole time, which is what isolates this to
# the failure-detection path rather than quorum or connectivity.
#
# This is NOT a Docker Desktop quirk: the 5s is the stock resolv.conf upstream
# timeout, so any Docker host resolves a dead container name the same way.
#
# Feeding Sentinel a literal IP means it never calls the resolver at all, so the
# event loop can't stall and TILT can't trigger. Accepting a hostname here and
# resolving it ourselves keeps REDIS_SENTINEL_PRIMARY_HOST backward compatible
# for anyone who overrides it -- blocking in this shell, before Sentinel starts,
# is harmless. docker-compose.ha.yml pins the Redis nodes to static IPs so the
# address resolved at boot stays correct for the life of the cluster.
case "$RAW_HOST" in
  *[!0-9.]*)
    # Bounded on ELAPSED WALL-CLOCK, not on an iteration count.
    #
    # This loop used to run `30` iterations of getent + `sleep 1` and report
    # "after 30s" on failure. Those are not the same thing: an unresolvable name
    # is exactly the case where getent BLOCKS for the resolv.conf timeout (the
    # 5s+ stall this whole script exists to keep off Sentinel's event loop), so
    # each iteration costs that timeout plus the sleep, not one second. Measured
    # end to end against a name that does not resolve: 179 seconds before the
    # script gave up and printed "after 30s". An operator sees a Sentinel wedged
    # in `starting` for three minutes and a message understating it 6x, which
    # points diagnosis away from DNS -- the actual cause.
    RESOLVE_TIMEOUT_S="${REDIS_SENTINEL_RESOLVE_TIMEOUT_S:-60}"
    started_at=$(date +%s)
    PRIMARY_IP=""
    while :; do
      PRIMARY_IP=$(getent hosts "$RAW_HOST" 2>/dev/null | awk '{print $1; exit}')
      [ -n "$PRIMARY_IP" ] && break
      elapsed=$(( $(date +%s) - started_at ))
      if [ "$elapsed" -ge "$RESOLVE_TIMEOUT_S" ]; then
        echo "Could not resolve REDIS_SENTINEL_PRIMARY_HOST='$RAW_HOST' after
${elapsed}s (limit ${RESOLVE_TIMEOUT_S}s). A name that does not resolve makes
each lookup block for the resolver's own timeout, so this can overshoot the
limit by one lookup. Set REDIS_SENTINEL_PRIMARY_HOST to a literal IP to skip
resolution entirely." >&2
        exit 1
      fi
      sleep 1
    done
    echo "Resolved primary '$RAW_HOST' -> $PRIMARY_IP (monitoring by IP)"
    ;;
  *)
    PRIMARY_IP="$RAW_HOST"
    ;;
esac

# resolve-hostnames/announce-hostnames must both stay "no" -- see the header
# comment. "yes" reintroduces blocking DNS on Sentinel's event loop and with it
# the perpetual-tilt failover deadlock.
#
# failover-timeout is 20s, not the 60s this script used to carry. Sentinel's
# leader election is Raft-like and CAN split: measured live (2026-08-05) on this
# exact 3-node setup, all three Sentinels saw the master go objectively down
# within ~80ms of each other, each voted for itself, none reached the 2-vote
# majority, and the round died with "failover-abort-not-elected". That is normal
# protocol behaviour, not a misconfiguration -- but Sentinel gates the retry at
# 2x failover-timeout, so 60000 meant a single split vote cost ~2 MINUTES of
# write-unavailability before the next round (which then elected a leader and
# finished the switch in 0.7s). Measured failover duration once a leader is
# elected is under 3s, so 20s keeps a wide margin for a slow replica sync while
# capping the split-vote penalty at ~40s. Raise it if your replicas carry enough
# data that promotion is slow.
#
# NOTE: this rationale lives out here as shell comments on purpose. The heredoc
# below is unquoted (it has to be -- it interpolates the password and master
# name), so backticks or $ inside it get command-substituted by the shell rather
# than written to the file. An earlier revision put this text inside the heredoc
# and the shell tried to execute a backticked Sentinel event name out of the
# prose, logging "-failover-abort-not-elected: not found" on every boot.
cat > /tmp/sentinel.conf <<EOF
port 26379
sentinel resolve-hostnames no
sentinel announce-hostnames no
sentinel monitor ${MASTER_NAME} ${PRIMARY_IP} ${RAW_PORT} 2
sentinel auth-pass ${MASTER_NAME} ${REDIS_PASSWORD}
sentinel down-after-milliseconds ${MASTER_NAME} ${REDIS_SENTINEL_DOWN_AFTER_MS:-5000}
sentinel parallel-syncs ${MASTER_NAME} 1
sentinel failover-timeout ${MASTER_NAME} ${REDIS_SENTINEL_FAILOVER_TIMEOUT_MS:-20000}
EOF
exec redis-sentinel /tmp/sentinel.conf
