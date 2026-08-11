"""FAILOVER-scoped chaos gate: acked events survive a real primary promotion.

Host half. `tools/chaos_test.py` covers CONSUMER kills; this covers the failure
class SSOT.md §2 records that gate structurally cannot see -- a Redis primary
acking a write it never replicated, then dying. See `chaos_failover_probe.py`
for the contract under test and why refused writes are not violations.

Requires the HA profile (`make ha-up`). Skips cleanly without it.
"""
from __future__ import annotations

import subprocess
import sys
import time

WS4 = "infra-ws4-detection-1"
PROBE_SRC = "tools/chaos_failover_probe.py"
PROBE_DST = "/tmp/chaos_failover_probe.py"
LOG = "/tmp/chaos_failover_probe.log"

IP_CONTAINER = {"172.28.0.11": "siem-bus-ha-1",
                "172.28.0.12": "siem-bus-ha-2",
                "172.28.0.13": "siem-bus-ha-3"}


def sh(*args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), capture_output=True, text=True, timeout=timeout)


def discover_master() -> str | None:
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
        print("[SKIP] failover chaos: docker is not reachable.")
        return 0
    if sh("docker", "inspect", WS4).returncode != 0:
        print(f"[SKIP] failover chaos: {WS4} not running -- bring up the HA "
              f"profile (make ha-up).")
        return 0

    master_ip = discover_master()
    if not master_ip:
        print("[SKIP] failover chaos: no master discovered (HA profile not active?).")
        return 0
    container = IP_CONTAINER.get(master_ip)
    if not container:
        print(f"[SKIP] failover chaos: master {master_ip} is not a known HA node "
              f"{sorted(IP_CONTAINER)} -- refusing to kill an unidentified container.")
        return 0

    if sh("docker", "cp", PROBE_SRC, f"{WS4}:{PROBE_DST}").returncode != 0:
        print("[SKIP] failover chaos: could not copy the probe into the container.")
        return 0

    print(f"[host] starting probe in {WS4}")
    sh("docker", "exec", "-d", WS4, "sh", "-c", f"python {PROBE_DST} > {LOG} 2>&1")

    for _ in range(90):
        time.sleep(1)
        log = sh("docker", "exec", WS4, "sh", "-c", f"cat {LOG} 2>/dev/null").stdout
        if "READY-FOR-KILL" in log:
            break
        if "[SKIP]" in log:
            print(log.strip())
            return 0
    else:
        print("[FAIL] probe never reached READY-FOR-KILL -- nothing was tested.")
        print(sh("docker", "exec", WS4, "sh", "-c", f"cat {LOG}").stdout)
        return 1

    print(f"[host] killing current primary {container} ({master_ip})")
    if sh("docker", "kill", container).returncode != 0:
        print(f"[FAIL] docker kill {container} failed.")
        return 1

    for _ in range(220):
        time.sleep(1)
        done = sh("docker", "exec", WS4, "sh", "-c",
                  f"grep -cE '^\\[OK\\]|^\\[FAIL\\]|^\\[SKIP\\]' {LOG} || true").stdout.strip()
        if done and done != "0":
            break

    log = sh("docker", "exec", WS4, "sh", "-c", f"cat {LOG}").stdout
    print(log.strip())
    rc = 0 if ("[OK]" in log or "[SKIP]" in log) else 1

    print(f"[host] restarting {container}")
    if sh("docker", "start", container).returncode != 0:
        print(f"[FAIL] could not restart {container} -- environment left one node down.")
        return 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
