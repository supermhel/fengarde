"""Gate: every data-node `redis-server` of an HA compose file carries --min-replicas-to-write 1 and a bounded max-lag.

A replica ignores min-replicas-* while it replicates and enforces it the moment Sentinel promotes it, so a node started without
the flag silently accepts unreplicated writes after a failover (FIX 23 would hold only for the original primary).
Scans every infra/docker-compose*.yml that starts a replica (`--replicaof`): all of its `redis-server` lines must match, and it
must have 3 of them. Override files that define no redis-server (e.g. docker-compose.ws8-ha-proof.yml) are listed but pass trivially.
`--self-test` proves the check fails on a missing flag, a wrong value (10) and an unbounded/zero lag.
"""
from __future__ import annotations

import pathlib
import re
import sys

WRITE = re.compile(r"--min-replicas-to-write\s+1(?!\d)")
LAG = re.compile(r"--min-replicas-max-lag\s+(\d+)(?!\d)")
MAX_LAG_S = 10


def problems(line: str) -> list[str]:
    bad = []
    if not WRITE.search(line):
        bad.append("needs `--min-replicas-to-write 1` exactly")
    m = LAG.search(line)
    if not m or not 1 <= int(m.group(1)) <= MAX_LAG_S:
        bad.append(f"needs `--min-replicas-max-lag` between 1 and {MAX_LAG_S}")
    return bad


def node_lines(text: str) -> list[tuple[int, str]]:
    return [(n, ln) for n, ln in enumerate(text.splitlines(), 1) if "redis-server" in ln and not ln.lstrip().startswith("#")]


def self_test() -> None:
    ok = "exec redis-server --min-replicas-to-write 1 --min-replicas-max-lag 10"
    assert problems(ok) == []
    assert problems("exec redis-server --appendonly yes") != []
    assert problems(ok.replace("write 1", "write 10")) != []        # the old substring match accepted this
    assert problems(ok.replace("lag 10", "lag 3600")) != []
    assert problems(ok.replace("lag 10", "lag 0")) != []
    assert problems("exec redis-server --min-replicas-to-write 1") != []
    print("check_ha_min_replicas self-test OK")


def main() -> int:
    if "--self-test" in sys.argv:
        self_test()
        return 0
    infra = pathlib.Path(__file__).resolve().parent.parent / "infra"
    rc = 0
    for f in sorted(infra.glob("docker-compose*.yml")):
        text = f.read_text(encoding="utf-8")
        nodes = node_lines(text)
        if "--replicaof" not in text:
            print(f"skip {f.name}: starts no replica ({len(nodes)} redis-server lines)")
            continue
        errs = [f"line {n}: {p}" for n, ln in nodes for p in problems(ln)]
        if len(nodes) != 3 or errs:
            rc = 1
            print(f"FAIL {f.name}: {len(nodes)} redis-server nodes (need 3); {errs}")
        else:
            print(f"OK {f.name}: 3 data nodes all carry --min-replicas-to-write 1 and a max-lag <= {MAX_LAG_S}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
