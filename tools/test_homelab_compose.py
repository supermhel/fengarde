"""Config checks for infra/docker-compose.homelab.yml (WP-2.1). No Docker needed: the two compose files are parsed as
YAML and the `${VAR:-default}` defaults are resolved by hand.

Run: python tools/test_homelab_compose.py
"""
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


class _Loader(yaml.SafeLoader):
    pass


def _tagged(loader, tag_suffix, node):
    # Compose's `!override` / `!reset` only matter to Compose; for these checks keep the value.
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node, deep=True)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    return loader.construct_scalar(node)


_Loader.add_multi_constructor("!", _tagged)


def load(name):
    return yaml.load((ROOT / "infra" / name).read_text(encoding="utf-8"), Loader=_Loader)


def resolve(text):
    """Replace ${VAR:-default} with default."""
    return re.sub(r"\$\{[A-Z0-9_]+:-([^}]*)\}", r"\1", str(text))


def to_mib(s):
    m = re.fullmatch(r"(\d+)([gGmM])", str(s).strip())
    assert m, f"unparseable size {s!r}"
    return int(m.group(1)) * (1024 if m.group(2) in "gG" else 1)


base, home = load("docker-compose.yml"), load("docker-compose.homelab.yml")
hs, bs = home["services"], base["services"]

# 1. OpenSearch heap must be at most half the container limit (JVM guidance; the rest is off-heap + page cache).
opts = next(e for e in hs["opensearch"]["environment"] if e.startswith("OPENSEARCH_JAVA_OPTS="))
heap = resolve(opts)
xms, xmx = re.findall(r"-X(?:ms|mx)(\w+)", heap)
limit = to_mib(resolve(hs["opensearch"]["mem_limit"]))
check(xms == xmx, f"Xms {xms} != Xmx {xmx}")
check(to_mib(xmx) * 2 <= limit, f"default heap {xmx} is more than half of the {limit}m OpenSearch limit")

# 2. Redis: base flags kept, maxmemory below the container limit, noeviction.
redis_cmd = hs["redis"]["command"][2]
base_cmd = bs["redis"]["command"]
base_flags = set(re.findall(r"--[a-z-]+", base_cmd))
check({"--appendonly", "--requirepass"} <= base_flags, "base redis command changed: update the homelab override and this test")
branches = [b for b in re.findall(r"exec redis-server[^;]*;", redis_cmd)]
check(len(branches) == 2, f"expected two redis-server branches (auth / no auth), got {len(branches)}")
for b in branches:
    check("--maxmemory-policy noeviction" in b, f"redis branch lacks noeviction: {b}")
    mm = re.search(r"--maxmemory (\d+)([a-z]+)", b)
    check(mm is not None and to_mib(mm.group(1) + mm.group(2)[0]) < to_mib(hs["redis"]["mem_limit"]),
          f"redis --maxmemory missing or not below mem_limit: {b}")
    for flag in base_flags - {"--requirepass"}:
        check(flag in b, f"redis override dropped base flag {flag}")
check(sum("--requirepass" in b for b in branches) == 1, "exactly the auth branch must carry --requirepass")

# 3. ISM policies attach at index creation: ws3-indexer (the only index creator) waits for the one-shot provision.
check(hs["ws3-indexer"]["depends_on"]["provision"]["condition"] == "service_completed_successfully",
      "ws3-indexer must wait for provision to complete")
check(str(bs["provision"].get("restart")) == "no", "provision must be one-shot (restart: no) or the dependency never resolves")

# 4. Every published port in the override is loopback by default.
for p in hs["ws1-collectors"]["ports"]:
    check(resolve(p).startswith("127.0.0.1:"), f"ws1 port {p} is not loopback by default")

# 5. Named volumes: only volumes the base declares, all carrying the prefix variable.
for v, spec in home["volumes"].items():
    check(v in base["volumes"], f"homelab volume {v} is not declared in the base file")
    check("${FENGARDE_HOMELAB_VOL_PREFIX:-fengarde-homelab}-" in spec["name"], f"volume {v} ignores the prefix variable")

# 6. docs/homelab.md quotes the real sum of the default memory limits.
total = sum(to_mib(resolve(s["mem_limit"])) for s in hs.values() if "mem_limit" in s and "profiles" not in s)
doc = (ROOT / "docs" / "homelab.md").read_text(encoding="utf-8")
check(f"{total / 1024:.1f} GiB" in doc, f"docs/homelab.md does not state the limit sum {total / 1024:.1f} GiB ({total} MiB)")

if FAILS:
    print("[FAIL] homelab compose:", *FAILS, sep="\n  - ")
    sys.exit(1)
print("[OK] homelab compose: heap<=limit/2, redis maxmemory+noeviction with base flags, ws3 waits for provision, "
      "loopback ports, volume prefix, doc limit sum")
