"""F2 (2026-10-22): the per-tenant alias map folds identity in WS-9 entity ids too.

Run: python services/ws9-resolver/test_identity_aliases.py
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from shared.identity_aliases import configure  # noqa: E402
from resolver import EntityResolver  # noqa: E402
from entity_id import compute_entity_id  # noqa: E402

FAILS: list[str] = []
MAP = "version: 1\ntenants:\n  acme:\n    default_realm: corp\n    realms:\n      - [CORP, corp.example]\n"


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _actor_ids(tenant, name, alert_id="x1"):
    r = EntityResolver(now_fn=lambda: 1_700_000_000.0)
    ups = r.resolve_alert({"alert_id": alert_id, "tenant_id": tenant, "time": 0, "actor": {"user": {"name": name}}})
    return {u["entity_id"] for u in ups if u["entity_type"] == "actor"}, ups


def run():
    os.environ.pop("FENGARDE_IDENTITY_ALIASES", None)
    configure()
    a, _ = _actor_ids("acme", "CORP\\jdoe")
    b, _ = _actor_ids("acme", "jdoe@corp.example")
    check(a != b, "no map: the two spellings are two entities (unchanged)")
    check(_actor_ids("acme", " Jdoe ")[0] == {compute_entity_id("acme", "actor", "jdoe")},
          "no map: entity id is the plain strip+casefold hash")
    fd, name = tempfile.mkstemp(suffix=".yml")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(MAP)
    try:
        os.environ["FENGARDE_IDENTITY_ALIASES"] = name
        configure()
        a, ua = _actor_ids("acme", "CORP\\jdoe")
        b, _ = _actor_ids("acme", "jdoe@corp.example", alert_id="x2")
        c, _ = _actor_ids("acme", "JDoe")
        check(len(a) == 1 and a == b == c, "map: every spelling is ONE entity for acme")
        check(a == {compute_entity_id("acme", "actor", "jdoe@corp")}, "map: the id is the hash of the folded identity")
        a2, _ = _actor_ids("acme", "CORP\\jdoe")
        check(a == a2, "map: deterministic across independent resolver instances (redelivery)")
        check(_actor_ids("globex", "CORP\\jdoe")[0] != _actor_ids("globex", "jdoe@corp.example")[0],
              "map is per tenant: globex spellings stay distinct")
        check(a != _actor_ids("globex", "CORP\\jdoe")[0], "ids stay tenant-namespaced")
        # redelivery on ONE resolver does not inflate the entity
        r = EntityResolver(now_fn=lambda: 1_700_000_000.0)
        al = {"alert_id": "r1", "tenant_id": "acme", "time": 0, "actor": {"user": {"name": "CORP\\jdoe"}}}
        for _ in range(3):
            for u in r.resolve_alert(al):
                r.apply_update(u)
        al2 = dict(al, alert_id="r2", actor={"user": {"name": "jdoe@corp.example"}})
        for u in r.resolve_alert(al2):
            r.apply_update(u)
        check(r.count() == 1, f"map: one entity after redelivery and the second spelling, got {r.count()}")
    finally:
        os.environ.pop("FENGARDE_IDENTITY_ALIASES", None)
        configure()
        os.unlink(name)


if __name__ == "__main__":
    run()
    if FAILS:
        for f in FAILS:
            print("[FAIL]", f)
        sys.exit(1)
    print("[OK] WS-9 identity aliases: one entity id per mapped identity, per tenant, deterministic")
