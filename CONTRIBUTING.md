# Contributing to FENGARDE

Thanks for your interest in FENGARDE. This guide gets you productive fast — and the
fastest, highest-value contribution is **adding a parser**.

---

## The zero-infra inner loop

**You do NOT need Docker or OpenSearch to add a parser.** The entire inner loop is
one command that runs in seconds on plain Python:

```sh
cd services/ws2-normalization && python test_contract.py
```

That test parses every registered source's sample, validates the output against the
OCSF schema (Contract A), and runs the full bus loop on the in-memory bus — no Redis,
no OpenSearch, no containers. Write your parser, run that command, see it pass. That's
the whole loop.

The repo-wide gate is just as light:

```sh
make test          # or: ./run_all_tests.sh
```

It runs the contract validator plus every workstream's `test_contract.py` on the
memory bus / in-memory stores / stub LLM. No infrastructure required.

Want to watch the whole pipeline produce a real alert end-to-end (still no Docker)?

```sh
make e2e           # or: python tools/demo_e2e.py
```

This injects a 10-event SSH brute-force burst and asserts a real alert reaches the
index and is idempotent under replay. It's the v0.1 acceptance test — a good thing to
run before and after your change.

---

## Add a parser (the best first contribution)

19 parsers ship today (Linux SSH, Cisco ASA, Active Directory, VMware vSphere,
generic syslog, Windows Event Log, DB audit, MCP/AI-agent, OPC UA/OT, n8n, DNS query log,
Kubernetes audit, CEF, AWS CloudTrail, Sysmon, Modbus/TCP, inventory-diff OT device,
mail gateway, M365 audit). A new
source parser is a self-contained module with a clean extension point — adding one never
touches an existing parser. Good candidates still open:

- SNMP
- NetFlow *(binary format — bigger lift)*
- Proxy / web-gateway logs *(DNS query log already ships — this is the HTTP-proxy sibling)*
- Custom JSON
- S7/PROFINET *(deferred on an access gap, not a doc gap — the vocabulary needed sits behind a
  Siemens support login; see `docs/superpowers/specs/2026-07-21-s7-profinet-decision-gate.md`)*

**Step-by-step walkthrough:** [docs/adding-a-parser.md](docs/adding-a-parser.md).

In short, it's three small edits:

1. Add a new parser module under `services/ws2-normalization/parsers/`, subclassing
   `Parser` (copy `linux_ssh.py` as your template).
2. Register it in `services/ws2-normalization/parsers/__init__.py` (the `_REGISTRY` dict).
3. Add a sample + expectation so `test_contract.py` exercises it.

Then verify with `python test_contract.py`. Done.

---

## Add a detection rule

Rules are YAML (`contracts/rules/*.yml`), evaluated against the normalized OCSF
schema so one rule works across every source of that class. Copy an existing rule
(`common_bruteforce.yml` is the simplest) and adjust the `detection` selections,
`condition`, and `siem` block. Grammar (operators, allowlists, time-of-day) is
documented in [`contracts/sigma-convention.md`](contracts/sigma-convention.md).

Before opening a PR, run the two rule gates — both are part of `make test`, but
run them directly for a fast, targeted check:

```sh
python tools/validate_rules.py        # schema, condition parse, operator safety, references
python tools/check_rule_producers.py  # anti-dormancy: some parser must actually emit your fields
```

`validate_rules.py` rejects a malformed rule at contribution time with a clear
message (unknown operator, undefined selection in the `condition`, missing
allowlist, broken time window, bad UUID/score) instead of letting it silently
never fire at runtime. `check_rule_producers.py` catches the opposite trap: a
rule keyed on a `class_uid`/field no shipped parser produces (a "dormant" rule
that passes every unit test but can never match real data).

A new rule also moves generated tables and pins in the eval harness (technique matrix,
evasion-cost table and floor, producer fixture, coverage row, waivers or a storyline, rule
counts). Run the helper instead of finding them one 30-minute gate run at a time:

```sh
python tools/rule_cascade.py               # new rule files = added vs origin/main, plus uncommitted
python tools/rule_cascade.py --no-generate # report only, writes nothing
```

It runs the generators (`technique_matrix.py --write-doc`, `evasion_cost.py --seed 7
--write-doc`, and `--update-floor` only when a *stateful* rule is new; never `--allow-lower`).
The floor update goes through a guard: it runs on a scratch copy of `eval/adversarial/evasion_floor.yaml`
and is written back only if it purely *adds* rule-set keys (a bare `--update-floor` also re-baselines the
fingerprint of every other rule-set whose numbers did not get worse, so any change to an existing key is
refused and listed). Then it runs the cheap gates that fail first (`validate_rules`, `check_rule_producers`,
`check_lane_coverage`, the technique matrix, the evasion-cost gate). It prints a checklist:
`TODO` is proven missing by a gate, `CHECK` is a reminder no cheap gate can verify (oracle pins,
rule counts in README/docs/index.html/console_e2e). A generator or gate that fails (non-zero exit,
timeout) is a `TODO` and a non-zero exit. The only files it writes are the two generated blocks of
`contracts/detection-coverage.md` and new keys in `eval/adversarial/evasion_floor.yaml` (a ratchet
*output*: review that diff). It never edits an oracle, a waiver, the findings register, a fixture or the
ratchet baseline (`eval/twin/baseline_scenarios.json`): those are decisions and stay yours.

---

## Project scope — read this before filing a feature request

FENGARDE is built in versioned slices; the pipeline, AI triage, and the parsers
described elsewhere in this doc are **all shipped today**, not aspirational —
see [README.md](README.md)'s capability table for the current parser/rule
counts (they change often enough that hardcoding a number here would go stale
fast). For
current status, what's real vs. still a claim, and the forward roadmap, **read
[SSOT.md](SSOT.md) first** — it's the canonical, continuously updated index and
supersedes any version scope described in an individual spec doc under
`docs/superpowers/specs/`.

In short, for triage purposes:

- A request to **improve the pipeline, a parser, a rule, the dashboard, AI
  triage, multi-tenancy, RBAC, or the report/NIS2 generator** → all in scope,
  very welcome; these are existing, working subsystems, not future milestones.
- The five parsers listed as 🚧 Planned/Deferred in the README (SNMP, NetFlow,
  custom JSON, proxy/web-gateway, S7/PROFINET) are the current deferred/"good
  first issue" set — check there for what's actually still open before filing
  a duplicate.

See [SSOT.md](SSOT.md) §3 for the full current doc index and each doc's trust
level. The original v0.1 build plan is historical context only (it describes
the project's first slice, not its current scope) and is no longer kept in
this repo's working tree — see SSOT.md §4.

---

## CI layout

`./run_all_tests.sh` is still the whole gate, and `make test` runs all of it. CI runs the same
script as **tiers** (`GATE_TIER=<name>`; stanzas are wrapped in `tier_on` blocks, and
`tools/test_gate_tiers.py` fails if any command between the first tier block and the pass/fail summary sits in no tier, so the tiers together are the full gate):

| Job (`.github/workflows/ci.yml`) | Runs | When |
|---|---|---|
| `fast-gate` | tier `fast`: contract validator, parsers, rules, services, producer and lane-coverage guards, DCO tests, console typecheck | every PR and push |
| `eval-twin`, `eval-layers`, `eval-matrix` | tiers of the eval harness (`eval/twin`, `eval/adversarial`, `eval/detection_accuracy`), in parallel | PRs that touch an eval-affecting path |
| `eval-report` | tier `eval-report`; downloads `eval-layers`' `matrix.latest.json` | after `eval-layers` |
| `eval-gates` | ratchet check + baseline guard + scorecard check/lint; downloads every artifact above | after all four |
| `full-gate` | the unmodified `bash run_all_tests.sh` | every push to `main`, and manual runs |
| `contract-tests` | aggregator and the **required** check name: green only if every tier that should have run is green | always |

Artifacts move between jobs with `actions/upload-artifact` / `download-artifact`
(`eval/adversarial/out/`, `eval/twin/out/`, `eval/twin/report.latest.json`); they are stamped with
`eval/twin/fingerprint.py`, so a stale one fails loudly. The eval jobs run when the diff (both sides of a
rename) touches anything `eval/twin/fingerprint.py` hashes (`contracts/` data, `services/**/*.py`, `eval/`
sources, `tools/validate_contract.py`, `tools/validate_rules.py`, `tools/check_rule_producers.py`, ...), the whole
`eval/` tree, `README.md` / `SSOT.md` (linted by the scorecard), `tools/generate_scorecard.py`,
`run_all_tests.sh`, the CI workflow, or the filter itself. The list is DERIVED from the fingerprint in
`tools/ci_eval_filter.py`, and its test fails if they diverge. A PR that touches none of those (docs, console
sources, tests outside `eval/`) skips them and `contract-tests` still goes green; `main` runs the
full gate regardless. Run one tier locally with `GATE_TIER=eval-layers bash run_all_tests.sh`
(tiers `eval-report` and `eval-gates` need the earlier tiers' artifacts in the same checkout).

---

## Pull request expectations

- **Open an issue first** for anything beyond a small fix, so we can agree on the
  approach. Use the [issue templates](.github/ISSUE_TEMPLATE/) — there's a dedicated
  one for parser requests.
- **Tests pass.** `make test` (i.e. `./run_all_tests.sh`) must be green. New behavior
  needs a contract test or sample that exercises it.
- **One logical change per PR.** A new parser is one PR; don't bundle unrelated
  refactors.
- **Match the existing style.** Keep parsers isolated (one module per source), derive
  `type_uid` (never hand-set it), and keep the output validating against Contract A.
- **Honest status.** Don't claim a capability works if it's stubbed. Accuracy over
  impressiveness is a core project value — especially for a security tool.
- **License.** By contributing, you agree your contribution is licensed under the
  project's [Apache-2.0 License](LICENSE).
- **Developer Certificate of Origin (DCO).** Every commit in a PR must carry a
  `Signed-off-by:` trailer whose email matches the commit's author email
  (checked per commit by the `DCO` workflow via `tools/check_dco.py` — PR-gated
  only, never retroactive on merged history; merge commits count too, so rebase
  rather than using GitHub's "Update branch" merge). The trailer certifies the
  [Developer Certificate of Origin v1.1](https://developercertificate.org/) —
  that you have the right to submit the contribution under the project's license.
  Add it with `git commit -s`; fix your own branch with `git rebase --signoff <base>` (the sign-off must be the author's own).
- **Security.** If you found a vulnerability, do **not** open a public PR/issue —
  follow [SECURITY.md](SECURITY.md). Remember the detection engine executes rule
  files, so review any contributed rule's `condition` carefully.

---

## Code of conduct

Be respectful and constructive. We want FENGARDE to be a welcoming project for
first-time open-source contributors. The full policy is in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
