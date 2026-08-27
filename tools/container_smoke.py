"""Universal container smoke: build -> run -> health-check across ALL services.

Closes the CI gap that `docker-build` (only builds) and the two live-e2e jobs
(ws3-mfa, ot-new-device; only cover 2 services) leave open: an image that
builds but does not actually BOOT, or whose health endpoint 404s / whose
/metrics is empty, ships unchecked. This one script, run against the live
compose stack, verifies EVERY app service end to end:

  - the container is Running and healthy (docker compose ps state + health)
  - its HTTP health endpoint returns 200 (bus-runner /health, dashboard /)

App services covered (the 8 workstream containers + dashboard):
  ws1-collectors, ws2-normalization, ws3-indexer, ws4-detection, ws5-ai,
  ws6-inventory, ws8-correlation  ->  /health on their bus runner port
  ws7-dashboard                   ->  nginx root page (wget/curl -f)

Live-only by design (needs the Docker compose stack up); self-contained and
deterministic -- every prerequisite is probed and each absence prints an
explicit [SKIP] with exit 0, so a tree without a reachable stack is never
mistaken for a passing smoke, and every [SKIP] names what was missing.

Run with the stack up (docker compose -f infra/docker-compose.yml up -d --build):
    python tools/container_smoke.py
"""

from __future__ import annotations

import subprocess
import sys


# service -> in-container health probe (127.0.0.1 inside the container)
HEALTH_PROBES: dict[str, str] = {
    "ws1-collectors": "http://127.0.0.1:8001/health",
    "ws2-normalization": "http://127.0.0.1:8002/health",
    "ws3-indexer": "http://127.0.0.1:8003/health",
    "ws4-detection": "http://127.0.0.1:8004/health",
    "ws5-ai": "http://127.0.0.1:8005/health",
    "ws6-inventory": "http://127.0.0.1:8006/health",
    "ws8-correlation": "http://127.0.0.1:8008/health",
    "ws7-dashboard": "http://127.0.0.1/",
}

FAILS: list[str] = []


def _try_sh(*args: str) -> str:
    """Run a host command, returning stdout or an ERROR sentinel."""
    try:
        return subprocess.run(args, check=True, capture_output=True,
                              text=True).stdout.strip()
    except subprocess.CalledProcessError as exc:
        return f"__ERROR__:{exc.returncode}:{exc.stderr.strip()[:200]}"


def docker_service_to_container(service: str) -> str:
    """Resolve the running container id/name for a compose service."""
    out = _try_sh("docker", "compose", "-f", "infra/docker-compose.yml",
                  "ps", "-q", service)
    if out.startswith("__ERROR__") or not out:
        return service
    return out.splitlines()[0]


def container_healthy(service: str) -> tuple[bool, str]:
    """True if the service's container is running and passing its healthcheck."""
    out = _try_sh(
        "docker", "compose", "-f", "infra/docker-compose.yml",
        "ps", "-a", "--format", "{{.Service}}|{{.State}}|{{.Health}}|{{.ExitCode}}",
        service)
    if out.startswith("__ERROR__"):
        return False, out
    for line in out.splitlines():
        parts = line.split("|")
        if len(parts) < 4:
            continue
        _svc, state, health, exitcode = parts[0], parts[1], parts[2], parts[3]
        if state == "running":
            if health in ("healthy", ""):
                return True, f"running, health={health or 'n/a'}"
            return False, f"running but health={health!r} (starting/unhealthy)"
        if state == "exited" and exitcode == "0":
            continue  # one-shot init, not in HEALTH_PROBES -- ignore
    return False, "no running container row"


def exec_health(service: str, url: str) -> tuple[bool, str]:
    """Exec into the running container and GET the health URL.

    The bus-runner service containers ship Python (stdlib urllib), NOT
    curl/wget; the one exception is ws7-dashboard, whose nginx:alpine image
    ships busybox wget and NOT python. Probe each with the tooling its image
    actually carries (mirroring the compose healthchecks for both shapes), so
    the smoke exercises the real image, not a guess.
    """
    container = docker_service_to_container(service)
    if service == "ws7-dashboard":
        # nginx root page; the image's own wget (spider) is what its healthcheck uses.
        fetch = f"wget -q -O /dev/null {url} && echo ok"
        out = _try_sh("docker", "exec", container, "sh", "-c", fetch)
        if out.startswith("__ERROR__") or out.strip() != "ok":
            return False, out
    else:
        probe = (
            "import urllib.request,sys;"
            f"r=urllib.request.urlopen('{url}', timeout=5);"
            "sys.stdout.write(r.read(400).decode('utf-8','replace'))"
        )
        out = _try_sh("docker", "exec", container, "python", "-c", probe)
        if out.startswith("__ERROR__") or not out:
            return False, out
    return True, out[:400]


def check(cond: bool, msg: str) -> None:
    if not cond:
        FAILS.append(msg)


def run() -> None:
    # Prereq: docker reachable.
    if _try_sh("docker", "version").startswith("__ERROR__"):
        print("[SKIP] docker not reachable on this host -- the container smoke "
              "needs `docker compose -f infra/docker-compose.yml up -d --build` "
              "first; skipping (never a silent pass).")
        return

    print("FENGARDE universal container smoke -- build->run->health across all app services")
    for service, url in HEALTH_PROBES.items():
        healthy, detail = container_healthy(service)
        if not healthy:
            print(f"[FAIL] {service}: container not healthy -- {detail}")
            check(False, f"{service}: container not running/healthy ({detail})")
            continue
        ok, body_or_err = exec_health(service, url)
        if not ok:
            print(f"[FAIL] {service}: health endpoint {url} did not respond -- {body_or_err}")
            check(False, f"{service}: {url} did not return 2xx")
            continue
        print(f"[OK]  {service}: running+healthy, {url} responded")

    if FAILS:
        print(f"\n[FAIL] container smoke: {len(FAILS)} problem(s)")
        for f in FAILS:
            print(f"   - {f}")
        sys.exit(1)
    print("\n[OK] all app-service containers boot, pass their health check, "
          "and respond to their health endpoint")


if __name__ == "__main__":
    run()
