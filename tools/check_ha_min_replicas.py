"""Gate: every data-node `redis-server` in the HA compose files carries --min-replicas-to-write 1.

A replica ignores min-replicas-* while it replicates and enforces it the moment Sentinel promotes it, so a node
started without the flag silently accepts unreplicated writes after a failover (FIX 23 would hold only for the
original primary). Text scan, no YAML dependency. `--self-test` proves the check fails on a node without the flag.
"""
from __future__ import annotations

import pathlib
import sys

FILES = ["infra/docker-compose.ha.yml", "infra/docker-compose.ws8-sentinel-proof.yml"]
NEEDED = ("--min-replicas-to-write 1", "--min-replicas-max-lag")


def missing(text: str) -> list[str]:
    bad = []
    for n, line in enumerate(text.splitlines(), 1):
        if "redis-server" in line and not line.lstrip().startswith("#"):
            bad += [f"line {n}: missing {flag}" for flag in NEEDED if flag not in line]
    return bad


def main() -> int:
    if "--self-test" in sys.argv:
        assert missing("exec redis-server --appendonly yes --replicaof x 6379") != []
        assert missing("exec redis-server --min-replicas-to-write 1 --min-replicas-max-lag 10") == []
        print("check_ha_min_replicas self-test OK")
        return 0
    root = pathlib.Path(__file__).resolve().parent.parent
    rc = 0
    for f in FILES:
        text = (root / f).read_text(encoding="utf-8")
        n = sum("redis-server" in l and not l.lstrip().startswith("#") for l in text.splitlines())
        errs = missing(text)
        if n < 3 or errs:
            rc = 1
            print(f"FAIL {f}: {n} redis-server nodes (need 3); {errs}")
        else:
            print(f"OK {f}: {n} data nodes all carry --min-replicas-to-write 1")
    return rc


if __name__ == "__main__":
    sys.exit(main())
