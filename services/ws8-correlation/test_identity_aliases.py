"""F2 (2026-10-22): the per-tenant alias map folds identity in WS-8 as well.

Two spellings of one account (``CORP\\jdoe`` / ``jdoe@corp.example``) must land on ONE actor track
(one incident that pools both tactics) and one canonical entity id for a tenant that lists the realm;
a tenant without a map, and every other tenant, keeps today's behaviour byte for byte. Ids stay
deterministic under redelivery and tenant-namespaced.

Run: python services/ws8-correlation/test_identity_aliases.py
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))

from shared.allowlist import Allowlist  # noqa: E402
from shared.identity_aliases import configure  # noqa: E402
from shared.window import DequeWindowCounter  # noqa: E402
from correlator import Correlator, canonical_entity_id  # noqa: E402

FAILS: list[str] = []
MAP = "version: 1\ntenants:\n  acme:\n    default_realm: corp\n    realms:\n      - [CORP, corp.example]\n"


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _alert(alert_id, tactic, actor, tenant):
    return {"alert_id": alert_id, "score": 10, "tenant_id": tenant, "time": 0,
            "mitre": {"tactic": tactic}, "actor": {"user": {"name": actor}}}


def _run(tenant, redeliver=False):
    c = Correlator(DequeWindowCounter(), allowlist=Allowlist([]))
    seq = [_alert("a1", "TA0001", "CORP\\jdoe", tenant), _alert("a2", "TA0002", "jdoe@corp.example", tenant)]
    out = []
    for a in seq + (seq if redeliver else []):
        out.extend(c.ingest_alert(a))
    return out


def run():
    os.environ.pop("FENGARDE_IDENTITY_ALIASES", None)
    configure()
    # absent map: two spellings = two tracks = no incident (unchanged)
    check(not _run("acme"), "no map: the two spellings stay two actors, no incident")

    fd, name = tempfile.mkstemp(suffix=".yml")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(MAP)
    try:
        os.environ["FENGARDE_IDENTITY_ALIASES"] = name
        configure()
        incs = _run("acme")
        actor_incs = [i for i in incs if i["entity_type"] == "actor"]
        check(len(actor_incs) == 1, f"map: one actor incident pooling both spellings, got {len(actor_incs)}")
        if actor_incs:
            check(actor_incs[0]["entity_value"] == "jdoe@corp",
                  f"map: the incident entity is the folded identity, got {actor_incs[0]['entity_value']!r}")
            check(set(actor_incs[0]["tactics"]) == {"TA0001", "TA0002"}, "map: both tactics pooled")
        again = [i for i in _run("acme", redeliver=True) if i["entity_type"] == "actor"]
        check(again and again[-1]["incident_id"] == actor_incs[0]["incident_id"],
              "map: incident id identical after redelivery of the same alerts")
        check(not _run("globex"), "map is per tenant: globex (no entry) is unchanged")
        # canonical entity ids
        a = canonical_entity_id("acme", "actor", "CORP\\jdoe")
        b = canonical_entity_id("acme", "actor", "JDoe@Corp.Example ")
        c = canonical_entity_id("acme", "actor", "jdoe")
        check(a and a == b == c, "map: all spellings (incl. bare via default_realm) share one entity id")
        check(a != canonical_entity_id("globex", "actor", "CORP\\jdoe"), "entity ids stay tenant-namespaced")
        check(canonical_entity_id("globex", "actor", "CORP\\jdoe") != canonical_entity_id("globex", "actor", "jdoe@corp.example"),
              "globex without a map: spellings stay distinct entities")
    finally:
        os.environ.pop("FENGARDE_IDENTITY_ALIASES", None)
        configure()
        os.unlink(name)
    # absent map: entity id is exactly the pre-F2 value
    from shared.entity_helpers import compute_entity_id
    check(canonical_entity_id("acme", "actor", " Alice ") == compute_entity_id("acme", "actor", "alice"),
          "no map: actor entity id byte-identical to strip+casefold")


if __name__ == "__main__":
    run()
    if FAILS:
        for f in FAILS:
            print("[FAIL]", f)
        sys.exit(1)
    print("[OK] WS-8 identity aliases: one track/incident/entity id per mapped identity, per tenant, "
          "deterministic under redelivery, absent map byte-identical")
