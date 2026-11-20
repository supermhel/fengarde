"""storyline_ransomware_keyed -- the KEYED TWIN of ``ransomware`` (ADR-012 WP 7).

Registered by ``scenario_registry._discover`` as ``ransomware_keyed``. It WRAPS ``storyline_ransomware``:
the original builder runs unchanged and this module adds Sysmon-shaped process-tree keys
(``ProcessGuid`` / ``ParentProcessGuid``) and a distinct ``meta.shipper_ip`` per emitting host
(see ``keyed_kit`` for the mechanism, the independence statement and the realism limit).
The original storyline, its oracle and the frozen baseline are not touched.

NOT AN INDEPENDENT SCENARIO: it replays the original's events and rules, so the oracle records
``keyed_twin.independent_of_original: false`` / ``counts_toward_n: 0``.

PROCESS TREE MODELLED (``PROCS``: process -> parent, image; ``BIND``: step -> producing process)
    srv01: PSEXESVC -> cmd.exe -> vssadmin.exe (inhibit_recovery, Sysmon EID 1: the record already carries
    cmd.exe as its parent image). fs01: cmd.exe -> lckr.exe (encrypt_files, Sysmon EID 11, one process for all
    40-60 file events). The two trees are on DIFFERENT hosts (srv01 vs fs01) and share no process.

LINKS (derived): NONE. Measured finding: the original ransomware storyline has no same-host parent/child
pair between two alert-raising steps (the Windows logon/privilege/account events carry no process; the two
Sysmon steps are on different hosts), so a keyed ransomware twin can only be a no-fabrication control here.
Getting a positive link needs a new step (e.g. a Sysmon EID 1 cmd.exe -> lckr.exe on fs01), which changes
the attack shape and is an owner decision, not made in a twin.
NON-LINK: inhibit_recovery -> encrypt_files (different hosts, disjoint trees).
"""
from __future__ import annotations

import sys
from pathlib import Path

TWIN = Path(__file__).resolve().parent
if str(TWIN) not in sys.path:
    sys.path.insert(0, str(TWIN))

import keyed_kit as kit  # noqa: E402
import storyline_ransomware as _orig  # noqa: E402
from scenario import ScenarioDef  # noqa: E402

ORIGINAL = _orig.STORYLINE
MODULE = "storyline_ransomware_keyed"

PROCS: dict = {
    "psexesvc": (None, "C:\\Windows\\PSEXESVC.exe"),
    "cmd": ("psexesvc", "C:\\Windows\\System32\\cmd.exe"),
    "vss": ("cmd", "C:\\Windows\\System32\\vssadmin.exe"),
    "cmd_fs": (None, "C:\\Windows\\System32\\cmd.exe"),
    "lckr": ("cmd_fs", "C:\\Users\\Public\\lckr.exe"),
}
BIND: dict = {
    "inhibit_recovery": "vss",
    "encrypt_files": "lckr",
}
#: source types whose raw record names no host: the host that really emitted them
HOST_OVERRIDES: dict = {}
#: pairs the twin deliberately keeps UNLINKED (checked NOT to be derived links)
NON_LINKS: tuple = (
    ("inhibit_recovery", "encrypt_files",
     "vssadmin runs on srv01 and the encryptor on fs01: different hosts, disjoint process trees, no shared GUID"),
)


def build(seed: int):
    payloads, sensors, notes, baseline = ORIGINAL.build(seed)
    return (kit.key_payloads(payloads, seed=seed, procs=PROCS, bind=BIND, host_overrides=HOST_OVERRIDES),
            sensors, notes, baseline)


def _decoys(seed: int) -> list:
    return kit.key_decoys(ORIGINAL.decoy(seed), host_overrides=HOST_OVERRIDES)


STORYLINE = ScenarioDef(
    name="ransomware_keyed",
    steps=ORIGINAL.steps,
    build=build,
    oracle_path=TWIN / "oracle_ransomware_keyed.yaml",
    summary="KEYED TWIN of ransomware (not independent): " + ORIGINAL.summary,
    decoy=_decoys,
    decoy_steps=ORIGINAL.decoy_steps,
    negatives=(),
)


def render_oracle_text() -> str:
    """The generated oracle text (``keyed_kit.py`` writes it; ``test_keyed_twins`` regenerates and compares)."""
    return kit.write_oracle(STORYLINE, ORIGINAL, module=MODULE, non_links=list(NON_LINKS),
                            host_overrides=HOST_OVERRIDES)
