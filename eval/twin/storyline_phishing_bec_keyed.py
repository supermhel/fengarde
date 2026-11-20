"""storyline_phishing_bec_keyed -- the KEYED TWIN of ``phishing_bec`` (ADR-012 WP 7).

Registered by ``scenario_registry._discover`` as ``phishing_bec_keyed``. It WRAPS ``storyline_phishing_bec``:
the original builder runs unchanged and this module adds Sysmon-shaped process-tree keys
(``ProcessGuid`` / ``ParentProcessGuid``) and a distinct ``meta.shipper_ip`` per emitting host
(see ``keyed_kit`` for the mechanism, the independence statement and the realism limit).
The original storyline, its oracle and the frozen baseline are not touched.

NOT AN INDEPENDENT SCENARIO: it replays the original's events and rules, so the oracle records
``keyed_twin.independent_of_original: false`` / ``counts_toward_n: 0``.

PROCESS TREE MODELLED (``PROCS``: process -> parent, image; ``BIND``: step -> producing process)
    WINWORD.exe -> powershell.exe (user_execution, Sysmon EID 1: the record already names WINWORD as its
    parent image) -> svc.exe (c2_beacon, Sysmon EID 3, ONE process for all 20-24 beats). The CEF logins, the
    mail, mailbox-rule and database records are not process events and carry no process keys.

LINKS (derived): user_execution -> c2_beacon. The child (EID 3) natively has no parent GUID, so the link
is ``twin_enrichment``; the user_execution record itself carries a native EID 1 parent/child pair whose
parent (WINWORD) has no step of its own.
NON-LINK: user_execution -> proxy_pool_logins (an identity burst from other addresses, no process).
"""
from __future__ import annotations

import sys
from pathlib import Path

TWIN = Path(__file__).resolve().parent
if str(TWIN) not in sys.path:
    sys.path.insert(0, str(TWIN))

import keyed_kit as kit  # noqa: E402
import storyline_phishing_bec as _orig  # noqa: E402
from scenario import ScenarioDef  # noqa: E402

ORIGINAL = _orig.STORYLINE
MODULE = "storyline_phishing_bec_keyed"

PROCS: dict = {
    "winword": (None, "WINWORD.EXE"),
    "ps": ("winword", "powershell.exe"),
    "c2": ("ps", "C:\\Users\\Public\\svc.exe"),
}
BIND: dict = {
    "user_execution": "ps",
    "c2_beacon": "c2",
}
#: source types whose raw record names no host: the host that really emitted them
HOST_OVERRIDES: dict = {}
#: pairs the twin deliberately keeps UNLINKED (checked NOT to be derived links)
NON_LINKS: tuple = (
    ("user_execution", "proxy_pool_logins",
     "the credential stuffing comes from a proxy pool through the identity provider: no process on the victim host produced it"),
)


def build(seed: int):
    payloads, sensors, notes, baseline = ORIGINAL.build(seed)
    return (kit.key_payloads(payloads, seed=seed, procs=PROCS, bind=BIND, host_overrides=HOST_OVERRIDES),
            sensors, notes, baseline)


def _decoys(seed: int) -> list:
    return kit.key_decoys(ORIGINAL.decoy(seed), host_overrides=HOST_OVERRIDES)


STORYLINE = ScenarioDef(
    name="phishing_bec_keyed",
    steps=ORIGINAL.steps,
    build=build,
    oracle_path=TWIN / "oracle_phishing_bec_keyed.yaml",
    summary="KEYED TWIN of phishing_bec (not independent): " + ORIGINAL.summary,
    decoy=_decoys,
    decoy_steps=ORIGINAL.decoy_steps,
    negatives=(),
)


def render_oracle_text() -> str:
    """The generated oracle text (``keyed_kit.py`` writes it; ``test_keyed_twins`` regenerates and compares)."""
    return kit.write_oracle(STORYLINE, ORIGINAL, module=MODULE, non_links=list(NON_LINKS),
                            host_overrides=HOST_OVERRIDES)
