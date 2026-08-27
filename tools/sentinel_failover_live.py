"""Orchestrate the live Sentinel primary-failover proof for the window counter.

Two halves that cannot live in one process: the counter probe must run INSIDE
the HA network (Redis nodes are not host-published and Sentinel returns
container-internal addresses), while `docker kill` must run on the HOST. This
script runs the host half and drives the container half over `docker exec`.

Sequence:
  1. copy the probe into the ws4-detection container and start it detached
  2. wait for its READY-FOR-KILL marker (phase 1 proved the counter works)
  3. resolve the CURRENT master's container from Sentinel, and kill it
  4. let the probe observe the promotion with its long-lived client
  5. restart the killed node so the environment is left whole
  6. relay the probe's exit code

Requires the HA profile up (`make ha-up`). Exits non-zero only on a real
failure; a missing HA stack skips, matching the other live lanes.
"""
from __future__ import annotations

import subprocess
import sys
import time

WS4 = "infra-ws4-detection-1"
PROBE_SRC = "services/ws4-detection/test_window_sentinel_failover_live.py"
PROBE_DST = "/tmp/test_window_sentinel_failover_live.py"
LOG = "/tmp/sentinel_failover_probe.log"

# Static IPs are pinned by the HA compose (taking Sentinel off the resolver was
# the 2026-08-05 fix for its blocking-DNS tilt), so mapping a discovered master
# address back to a container is a table lookup, not a guess.
IP_CONTAINER = {"172.28.0.11": "siem-bus-ha-1",
                "172.28.0.12": "siem-bus-ha-2",
                "172.28.0.13": "siem-bus-ha-3"}


def sh(*args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), capture_output=True, text=True, timeout=timeout)


def discover_master() -> str | None:
    """(host, port) of the current master, as Sentinel sees it from inside."""
    code = (
        "import os;from redis.sentinel import Sentinel;"
        "h=[(p.split(':')[0],int(p.split(':')[1])) "
        "for p in os.environ['REDIS_SENTINEL_HOSTS'].split(',')];"
        "s=Sentinel(h,password=os.environ.get('REDIS_PASSWORD') or None,"
        "socket_timeout=1,decode_responses=True);"
        "print(s.discover_master(os.getenv('REDIS_SENTINEL_MASTER','mymaster'))[0])"
    )
    r = sh("docker", "exec", WS4, "python", "-c", code)
    return r.stdout.strip() if r.returncode == 0 else None


def main() -> int:
    if sh("docker", "version").returncode != 0:
        print("[SKIP] sentinel failover: docker is not reachable.")
        return 0
    if sh("docker", "inspect", WS4).returncode != 0:
        print(f"[SKIP] sentinel failover: {WS4} is not running -- bring up the "
              f"HA profile (make ha-up).")
        return 0

    master_ip = discover_master()
    if not master_ip:
        print("[SKIP] sentinel failover: could not discover a master (HA profile "
              "not active?).")
        return 0
    container = IP_CONTAINER.get(master_ip)
    if not container:
        print(f"[SKIP] sentinel failover: master {master_ip} is not one of the "
              f"known HA nodes {sorted(IP_CONTAINER)} -- refusing to kill an "
              f"unidentified container.")
        return 0

    if sh("docker", "cp", PROBE_SRC, f"{WS4}:{PROBE_DST}").returncode != 0:
        print("[SKIP] sentinel failover: could not copy the probe into the container.")
        return 0

    print(f"[host] starting probe in {WS4}")
    sh("docker", "exec", "-d", WS4, "sh", "-c",
       f"python {PROBE_DST} > {LOG} 2>&1")

    # Wait for phase 1 to prove the counter works BEFORE killing anything --
    # killing early would make a failed probe ambiguous between "the counter
    # broke" and "the counter never started".
    for _ in range(60):
        time.sleep(1)
        log = sh("docker", "exec", WS4, "sh", "-c", f"cat {LOG} 2>/dev/null").stdout
        if "READY-FOR-KILL" in log:
            break
        if "[SKIP]" in log:
            print(log.strip())
            return 0
    else:
        print("[FAIL] probe never reached READY-FOR-KILL -- phase 1 did not "
              "complete, nothing was tested.")
        print(sh("docker", "exec", WS4, "sh", "-c", f"cat {LOG}").stdout)
        return 1

    print(f"[host] killing current master {container} ({master_ip})")
    if sh("docker", "kill", container).returncode != 0:
        print(f"[FAIL] docker kill {container} failed.")
        return 1

    # The probe polls until it sees the master move; give the whole election +
    # client-reconnect cycle room, then collect its verdict.
    rc = 1
    for _ in range(190):
        time.sleep(1)
        done = sh("docker", "exec", WS4, "sh", "-c",
                  f"grep -cE '^\\[OK\\]|^\\[FAIL\\]|^\\[SKIP\\]' {LOG} || true").stdout.strip()
        if done and done != "0":
            break

    log = sh("docker", "exec", WS4, "sh", "-c", f"cat {LOG}").stdout
    print(log.strip())
    # Gap-hunt (2026-08-26) R4-111: a post-kill [SKIP] is Sentinel FAILING to
    # promote -- the exact HA property under test -- but it used to count as
    # success here (rc=0 when "[OK]" OR "[SKIP]"), so "master never moved off
    # the killed primary" passed green. After the kill ONLY "[OK]" proves the
    # failover happened; [SKIP]/[FAIL]/no-verdict are all failures.
    rc = 0 if "[OK]" in log else 1
    if rc != 0:
        print("[FAIL] post-kill probe did not report [OK] -- the Sentinel "
              "election did not move the master (a no-promotion IS a failover "
              "failure, not a skip).")

    print(f"[host] restarting {container}")
    if sh("docker", "start", container).returncode != 0:
        print(f"[FAIL] could not restart {container} -- environment left one "
              f"node down.")
        return 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
