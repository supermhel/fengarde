"""OT new-device sighting: WS-6 -> bus -> WS-2 -> WS-4 -> alert, LIVE.

Closes the gap SSOT.md §2 records against the M7 Track Y row: the
`ot_new_device_on_segment` rule was proven to FIRE on its own anti-dormancy
fixture, and the WS-6 -> `raw.events` transport was proven zero-infra on a
memory bus, but the two had never been joined on real infrastructure. The row's
own words: "the only thing that has ever fired this rule is its own
anti-dormancy fixture" and "still NOT live-verified against a real
Docker/Redis stack".

This drives the whole chain for real:

    produce to `assets.updates` (the bus)
      -> WS-6 bus_consumer -> InventoryStore.upsert_with_diff() detects a
         first-ever MAC for the tenant
      -> republished onto raw.events as an inventory_diff notification
      -> WS-2's InventoryDiffParser normalizes it to OCSF (class_uid 4001)
      -> WS-4's ot_new_device_on_segment rule fires
      -> WS-3 indexes the alert

and asserts an alert actually lands, keyed to a MAC this run invented so a
stale alert from an earlier run cannot be mistaken for a fresh pass.

**The entry point is the bus topic, NOT `POST /assets/upsert`.** The HTTP route
reports `new_device` in its own response but does not republish anything; only
`bus_consumer.make_handler` produces to `raw.events`. Driving the HTTP surface
instead (the first attempt at this test) gets a truthful 200 back and then waits
forever for an alert that was never going to come.

**`sector` must be on the observation.** `build_notification` passes
`sector`/`device_type` straight through from the assets.updates payload and
deliberately never fabricates `"ot"` -- a guessed sector would wrongly escalate
severity for a device never actually seen on an OT segment. The store does not
persist sector either, so it has to come from the observation itself or the
rule's `unmapped.ot.sector: ot` selection never matches.

**Requires `INVENTORY_BASELINE_SECONDS=0` AND a tenant with no prior state.**
The default 3600s window treats devices seen just after a tenant first appears
as pre-existing inventory (populate, don't alert). A tenant whose baseline row
already exists keeps its original window even if the env var changes later, so
this test invents a fresh tenant per run rather than reusing `default`.

Run with the stack up:
    INVENTORY_BASELINE_SECONDS=0 docker compose ... up -d ws6-inventory
    python tools/ot_new_device_e2e.py
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
import uuid

def _container(service: str) -> str:
    """Resolve the real container name for a compose service, regardless of
    COMPOSE_PROJECT_NAME. Falls back to the legacy `<project>_<service>-1`
    pattern when ps can't be parsed (e.g. running outside compose)."""
    try:
        out = sh("docker", "compose", "-f", "infra/docker-compose.yml", "ps", "--format", "{{.Name}}", service).stdout.strip()
        if out:
            return out.splitlines()[-1]
    except Exception:
        pass
    # Fallback: inspect project from running containers with the known legacy name.
    try:
        legacy = f"infra-{service}-1"
        out = sh("docker", "ps", "--filter", f"name={legacy}", "--format", "{{.Names}}").stdout.strip()
        if out:
            return out.splitlines()[0]
    except Exception:
        pass
    raise SystemExit(f"[ot-e2e] cannot resolve container for service '{service}' -- is the stack up?")


WS6 = _container("ws6-inventory")
WS3 = _container("ws3-indexer")
RULE_ID = "7f8091a2-b3c4-4d53-9e6f-1a2b3c4d5e6f"  # ot_new_device_on_segment
_SETTLE_S = 25

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def sh(*args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), capture_output=True, text=True, timeout=timeout)


def _env(container: str, name: str) -> str:
    return sh("docker", "exec", container, "sh", "-c", f"echo ${name}").stdout.strip()


def main() -> int:
    if sh("docker", "version").returncode != 0:
        print("[SKIP] ot new-device e2e: docker is not reachable.")
        return 0
    for c in (WS6, WS3):
        if sh("docker", "inspect", c).returncode != 0:
            print(f"[SKIP] ot new-device e2e: {c} is not running (make up).")
            return 0

    if _env(WS6, "BUS_BACKEND") in ("", "memory"):
        print("[SKIP] ot new-device e2e: WS-6 has no bus backend, so its "
              "new-device signal is never republished -- the chain under test "
              "does not exist in this deployment.")
        return 0

    baseline = _env(WS6, "INVENTORY_BASELINE_SECONDS")
    if baseline != "0":
        print(f"[SKIP] ot new-device e2e: INVENTORY_BASELINE_SECONDS={baseline or 'unset (default 3600)'}. "
              f"A first sighting inside the baseline window is treated as "
              f"pre-existing inventory BY DESIGN, so no alert is expected and "
              f"waiting would prove nothing. Recreate ws6 with "
              f"INVENTORY_BASELINE_SECONDS=0 to run this.")
        return 0

    # A MAC and a TENANT unique to this run. The MAC keeps a stale alert from
    # satisfying the assertion; the fresh tenant guarantees an open baseline
    # decision made under the CURRENT env, since a tenant's baseline row is
    # written once on its first observation and never revised.
    suffix = uuid.uuid4().hex[:6]
    mac = f"02:{suffix[0:2]}:{suffix[2:4]}:{suffix[4:6]}:ab:cd"
    # Lowercase alphanumeric/hyphen only -- store.py::_validated_tenant raises
    # InvalidTenantId otherwise, and the consumer thread swallows nothing: the
    # observation is simply never stored and no notification is published.
    tenant = f"ot-e2e-{suffix}"

    obs = {"mac": mac, "ip": "10.77.0.9", "hostname": f"plc-{suffix}",
           "sector": "ot", "device_type": "plc", "tenant_id": tenant}
    produce = (
        "import sys,json;sys.path.insert(0,'/app');"
        "from shared.bus import Bus;"
        f"Bus().produce('assets.updates', key={mac!r}, payload={obs!r});"
        "print('produced')"
    )
    r = sh("docker", "exec", WS6, "python", "-c", produce)
    if r.returncode != 0 or "produced" not in r.stdout:
        print(f"[FAIL] ot new-device e2e: could not produce to assets.updates: "
              f"{(r.stderr or r.stdout).strip()[:400]}")
        return 1
    print(f"[e2e] produced assets.updates observation mac={mac} tenant={tenant}")

    print(f"[e2e] waiting up to {_SETTLE_S}s for WS-6 -> raw.events -> WS-2 -> WS-4 -> WS-3")
    deadline = time.time() + _SETTLE_S
    while time.time() < deadline:
        s = sh("docker", "exec", WS3, "python", "-c", search)
        if s.returncode == 0:
            try:
                hits = json.loads(s.stdout).get("hits", {}).get("hits", [])
            except ValueError:
                hits = []
            if hits:
                break
        time.sleep(2)
    else:
        print(f"[FAIL] ot new-device e2e: alert not found within {_SETTLE_S}s")
        return 1

    # Query the indexer for an alert from this rule mentioning THIS run's MAC.
    query = {"size": 20, "query": {"term": {"rule_id": RULE_ID}},
             "sort": [{"time": {"order": "desc", "unmapped_type": "long"}}]}
    # Real bug found while wiring this into CI (2026-08-23): this used to
    # hardcode `http://opensearch-1:9200` -- an HA-PROFILE-ONLY hostname
    # (infra/docker-compose.ha.yml's opensearch-1..3), which does not exist
    # on the plain stack this script's own docstring instructs running
    # against (`docker compose ... up -d ws6-inventory`, no HA overlay). It
    # never worked against the deployment it claimed to test; reading the
    # ws3-indexer container's own OPENSEARCH_URL (correct for either
    # profile: single node by default, comma-separated 3-node list under
    # HA -- take the first, any live node answers this query) fixes it
    # instead of hardcoding a second, drifting copy of that config.
    search = (
        "import json,os,urllib.request;"
        "url=os.environ.get('OPENSEARCH_URL','http://opensearch:9200').split(',')[0];"
        f"body=json.dumps({query!r}).encode();"
        "req=urllib.request.Request(url+'/alerts-*/_search',"
        "data=body,headers={'Content-Type':'application/json'},method='POST');"
        "print(urllib.request.urlopen(req,timeout=10).read().decode())"
    )
    s = sh("docker", "exec", WS3, "python", "-c", search)
    if s.returncode != 0:
        # Redact any basic-auth credentials in OPENSEARCH_URL before logging.
        safe_url = os.environ.get("OPENSEARCH_URL", "http://opensearch:9200")
        safe_url = re.sub(r"//[^:]+:[^@]+@", "//***:***@", safe_url)
        msg = (s.stderr or s.stdout or "").strip()[:400]
        msg = re.sub(r"https?://[^:]+:[^@]+@", "https://***:***@", msg)
        print(f"[FAIL] ot new-device e2e: alert search failed (url={safe_url}): {msg}")
        return 1
    try:
        hits = json.loads(s.stdout).get("hits", {}).get("hits", [])
    except ValueError:
        print(f"[FAIL] ot new-device e2e: unparseable search response: "
              f"{s.stdout[:300]}")
        return 1

    check(bool(hits),
          f"no alert at all from rule {RULE_ID} after a live new-device sighting "
          f"-- the WS-6 -> bus -> WS-2 -> WS-4 chain did not complete")
    blob = json.dumps(hits)
    check(mac.lower() in blob.lower(),
          f"found {len(hits)} alert(s) from this rule but none referencing this "
          f"run's MAC {mac} -- a stale alert must not be read as a fresh pass")

    if FAILS:
        print(f"\n[FAIL] OT new-device live e2e: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        return 1
    print(f"\n[OK] OT new-device live e2e PASS -- a real assets.updates "
          f"observation for {mac} (tenant {tenant}) traversed WS-6's bus "
          f"consumer -> raw.events -> WS-2 parser -> WS-4 rule and landed as an "
          f"indexed alert. First time this rule has fired from a real producer "
          f"rather than its own anti-dormancy fixture.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
