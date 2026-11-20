"""storyline_supply_chain_ci_keyed -- the KEYED TWIN of ``supply_chain_ci`` (ADR-012 WP 7).

Registered by ``scenario_registry._discover`` as ``supply_chain_ci_keyed``. It WRAPS ``storyline_supply_chain_ci``:
the original builder runs unchanged and this module adds Sysmon-shaped process-tree keys
(``ProcessGuid`` / ``ParentProcessGuid``) and a distinct ``meta.shipper_ip`` per emitting host
(see ``keyed_kit`` for the mechanism, the independence statement and the realism limit).
The original storyline, its oracle and the frozen baseline are not touched.

NOT AN INDEPENDENT SCENARIO: it replays the original's events and rules, so the oracle records
``keyed_twin.independent_of_original: false`` / ``counts_toward_n: 0``.

PROCESS TREE MODELLED (``PROCS``: process -> parent, image; ``BIND``: step -> producing process)
    ci-runner-03: npm -> node (malicious_dependency, Sysmon EID 1: the record already names npm as its
    parent image) -> the build agent process (ci_secret_read: the agent reads the credentials file itself)
    -> { an HTTP tool process (artifact_exfil), a shell process (pipeline_sabotage) }: tool calls that run a
    command or open a connection are children of the agent. The runaway loop session (agent_runaway) is a
    SEPARATE agent process under a different, unseen parent, and the privileged pod (k8s_audit) is produced
    by the API server.

LINKS (derived): malicious_dependency -> ci_secret_read, ci_secret_read -> artifact_exfil,
ci_secret_read -> pipeline_sabotage. The MCP records natively carry a session id, not a process GUID, so
every child here is ``twin_enrichment``. malicious_dependency raises no alert in the original (an honest gap),
so its link is NOT gradable; the two agent -> tool links are.
NON-LINKS: malicious_dependency -> artifact_exfil / pipeline_sabotage (grandchildren: no transitive link is
claimed), -> agent_runaway (a different agent process), -> privileged_runner (K8s API-server record).
"""
from __future__ import annotations

import sys
from pathlib import Path

TWIN = Path(__file__).resolve().parent
if str(TWIN) not in sys.path:
    sys.path.insert(0, str(TWIN))

import keyed_kit as kit  # noqa: E402
import storyline_supply_chain_ci as _orig  # noqa: E402
from scenario import ScenarioDef  # noqa: E402

ORIGINAL = _orig.STORYLINE
MODULE = "storyline_supply_chain_ci_keyed"

PROCS: dict = {
    "npm": (None, "/usr/bin/npm"),
    "node": ("npm", "/usr/bin/node"),
    "agent": ("node", "ci-build-agent"),
    "http_tool": ("agent", "curl"),
    "shell": ("agent", "/bin/sh"),
    "runnerd": (None, "ci-runnerd"),
    "loop_agent": ("runnerd", "ci-build-agent (loop session)"),
}
BIND: dict = {
    "malicious_dependency": "node",
    "ci_secret_read": "agent",
    "agent_runaway": "loop_agent",
    "artifact_exfil": "http_tool",
    "pipeline_sabotage": "shell",
}
#: source types whose raw record names no host: the host that really emitted them
HOST_OVERRIDES: dict = {"mcp_agent": "ci-runner-03", "k8s_audit": "k8s-apiserver"}
#: pairs the twin deliberately keeps UNLINKED (checked NOT to be derived links)
NON_LINKS: tuple = (
    ("malicious_dependency", "artifact_exfil",
     "the exfil tool is a grandchild (node -> agent -> tool): no direct parent/child key exists and no transitive link is claimed"),
    ("malicious_dependency", "pipeline_sabotage",
     "the shell is a grandchild (node -> agent -> shell): no transitive link is claimed"),
    ("malicious_dependency", "agent_runaway",
     "the runaway loop is a different agent process (own session) under an unseen parent"),
    ("malicious_dependency", "privileged_runner",
     "the privileged pod is a Kubernetes API-server audit record on another host; it names no process"),
)


def build(seed: int):
    payloads, sensors, notes, baseline = ORIGINAL.build(seed)
    return (kit.key_payloads(payloads, seed=seed, procs=PROCS, bind=BIND, host_overrides=HOST_OVERRIDES),
            sensors, notes, baseline)


def _decoys(seed: int) -> list:
    return kit.key_decoys(ORIGINAL.decoy(seed), host_overrides=HOST_OVERRIDES)


STORYLINE = ScenarioDef(
    name="supply_chain_ci_keyed",
    steps=ORIGINAL.steps,
    build=build,
    oracle_path=TWIN / "oracle_supply_chain_ci_keyed.yaml",
    summary="KEYED TWIN of supply_chain_ci (not independent): " + ORIGINAL.summary,
    decoy=_decoys,
    decoy_steps=ORIGINAL.decoy_steps,
    negatives=(),
)


def render_oracle_text() -> str:
    """The generated oracle text (``keyed_kit.py`` writes it; ``test_keyed_twins`` regenerates and compares)."""
    return kit.write_oracle(STORYLINE, ORIGINAL, module=MODULE, non_links=list(NON_LINKS),
                            host_overrides=HOST_OVERRIDES)
