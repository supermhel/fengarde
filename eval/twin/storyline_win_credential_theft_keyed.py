"""storyline_win_credential_theft_keyed -- the KEYED TWIN of ``win_credential_theft`` (ADR-012 WP 7).

Registered by ``scenario_registry._discover`` as ``win_credential_theft_keyed``. It WRAPS ``storyline_win_credential_theft``:
the original builder runs unchanged and this module adds Sysmon-shaped process-tree keys
(``ProcessGuid`` / ``ParentProcessGuid``) and a distinct ``meta.shipper_ip`` per emitting host
(see ``keyed_kit`` for the mechanism, the independence statement and the realism limit).
The original storyline, its oracle and the frozen baseline are not touched.

NOT AN INDEPENDENT SCENARIO: it replays the original's events and rules, so the oracle records
``keyed_twin.independent_of_original: false`` / ``counts_toward_n: 0``.

PROCESS TREE MODELLED (``PROCS``: process -> parent, image; ``BIND``: step -> producing process)
    explorer.exe -> powershell.exe (the download cradle, step powershell_cradle: every script-block event is
    ONE process) -> { the dumping tool (lsass_dump, Sysmon EID 10), one sc.exe per service-install event
    (service_persistence, 7045), wevtutil.exe (log_clear, 1102) }. All on the victim workstation.
    directory_tamper (5136) is the stolen account writing LDAP on the DC: no process on the workstation is
    its producer, so it carries no process keys. The bystander administrator's wevtutil.exe on fs02 is in a
    disjoint tree.

LINKS (derived, see the oracle): powershell_cradle -> lsass_dump, -> service_persistence, -> log_clear.
NON-LINKS: powershell_cradle -> directory_tamper (different host, no producing process), log_clear ->
bystander_log_maintenance (disjoint tree, host and account).
HONESTY: none of the three child records is a Sysmon EID 1 (EID 10, 7045, 1102), so every link is
``twin_enrichment``; the parent GUID on them is what a lineage-joining collector would add.
"""
from __future__ import annotations

import sys
from pathlib import Path

TWIN = Path(__file__).resolve().parent
if str(TWIN) not in sys.path:
    sys.path.insert(0, str(TWIN))

import keyed_kit as kit  # noqa: E402
import storyline_win_credential_theft as _orig  # noqa: E402
from scenario import ScenarioDef  # noqa: E402

ORIGINAL = _orig.STORYLINE
MODULE = "storyline_win_credential_theft_keyed"

PROCS: dict = {
    "explorer": (None, "C:\\Windows\\explorer.exe"),
    "ps": ("explorer", "powershell.exe"),
    "dumper": ("ps", "dumping tool"),
    "sc#": ("ps", "C:\\Windows\\System32\\sc.exe"),
    "wevt": ("ps", "C:\\Windows\\System32\\wevtutil.exe"),
    "svchost_b": (None, "svchost.exe"),
    "wevt_b": ("svchost_b", "wevtutil.exe"),
}
BIND: dict = {
    "powershell_cradle": "ps",
    "lsass_dump": "dumper",
    "service_persistence": "sc#",
    "log_clear": "wevt",
    "bystander_log_maintenance": "wevt_b",
}
#: source types whose raw record names no host: the host that really emitted them
HOST_OVERRIDES: dict = {}
#: pairs the twin deliberately keeps UNLINKED (checked NOT to be derived links)
NON_LINKS: tuple = (
    ("powershell_cradle", "directory_tamper",
     "the 5136 write is made on the DC by the stolen account over LDAP; no process on the workstation "
     "produced it, so no process key exists to link"),
    ("log_clear", "bystander_log_maintenance",
     "a different administrator clears a different server's log; disjoint process tree, host, account and address"),
)


def build(seed: int):
    payloads, sensors, notes, baseline = ORIGINAL.build(seed)
    return (kit.key_payloads(payloads, seed=seed, procs=PROCS, bind=BIND, host_overrides=HOST_OVERRIDES),
            sensors, notes, baseline)


def _decoys(seed: int) -> list:
    return kit.key_decoys(ORIGINAL.decoy(seed), host_overrides=HOST_OVERRIDES)


STORYLINE = ScenarioDef(
    name="win_credential_theft_keyed",
    steps=ORIGINAL.steps,
    build=build,
    oracle_path=TWIN / "oracle_win_credential_theft_keyed.yaml",
    summary="KEYED TWIN of win_credential_theft (not independent): " + ORIGINAL.summary,
    decoy=_decoys,
    decoy_steps=ORIGINAL.decoy_steps,
    negatives=(),
)


def render_oracle_text() -> str:
    """The generated oracle text (``keyed_kit.py`` writes it; ``test_keyed_twins`` regenerates and compares)."""
    return kit.write_oracle(STORYLINE, ORIGINAL, module=MODULE, non_links=list(NON_LINKS),
                            host_overrides=HOST_OVERRIDES)
