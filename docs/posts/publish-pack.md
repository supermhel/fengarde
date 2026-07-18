# Publish pack — copy-paste-ready launch material (v0.4)

Companion to [`launch-checklist.md`](launch-checklist.md) (the sequencing
authority). This file contains the actual post copy. Posting is a human
action — nothing here fires automatically. Fill `<PLACEHOLDER>` items before
posting; every factual claim below was checked against the repo at write time
(2026-07-10, re-verified 2026-07-12 after the ARGUS→FENGARDE rebrand) — re-verify
counts if the repo moves before you post.

---

## Pre-publish checklist (do not post until every box is checked)

- [x] `bash run_all_tests.sh` green on `main` (`ALL TESTS PASS`) — re-verified
      2026-07-10 at commit `081dabb`
- [x] Live-stack smoke test done, real Docker/Redis/OpenSearch/nginx, `FENGARDE_API_KEY`
      set (2026-07-10, commit `38341ce`): pipeline produces alerts end-to-end;
      report generation through the dashboard nginx proxy → ws3 lands in
      `reports-*` with `status=draft`+disclaimer; 401 with no/wrong key, 200
      with the correct one via both the proxy and direct; nginx injects the
      key server-side. This run also found and fixed two blockers the
      zero-infra gate can't see: a compose YAML break from `${REDIS_PASSWORD}`
      inside a flow-style array, and ws2 missing PyYAML for the A5 enrichment
      import (the stack would not have started at all before the fix).
- [x] GitHub repo settings: description + topics set live via `gh repo edit`
      (siem, security, ocsf, opensearch, detection-engineering, nis2,
      self-hosted, mcp, ocsf-native, blue-team, + the pre-existing ones)
- [x] Dashboard UI translated from French to v0.1-era leftover labels to
      English (PR #1, commit `081dabb`) — verified 0 French diacritics remain
- [x] README renders correctly on github.com (tables, links, quickstart) —
      browser spot-checked 2026-07-12; capability table + quickstart code block
      + `contracts/reporting.md` link all render; counts (10 parsers / 17 rules)
      match code
- [x] Dead asciinema embed removed from the README Demo section (the hosted
      cast was archived/unplayable); Demo now points to a runnable
      `bash tools/demo.sh`. Re-recording + re-embedding a fresh cast is still
      optional polish, not a blocker.
- [x] Screenshot of the dashboard with a real "Report" button + a real alert
      captured 2026-07-12 (live Docker stack, 3 real alerts, English UI,
      header now correctly reads "live data")

---

## 1. r/netsec (post FIRST — the attention play)

**Title:**
> FENGARDE: open-source SIEM now ships detection content for AI-agent/MCP tool-call logs (parser + rules, OCSF-normalized)

**Body:**

> There's a gap in open-source detection content right now: AI agents (MCP
> servers, tool-calling assistants) produce security-relevant telemetry —
> which tool was called, with what arguments, by which session — and as far
> as I can tell nobody ships open detection rules for it.
>
> I added an MCP/agent audit-log parser + a small rule pack to FENGARDE, an
> Apache-2.0 SIEM pipeline I've been building:
>
> - **Parser**: MCP tool-call JSONL → OCSF API Activity (6003). There's no
>   standard MCP log format yet, so the parser defines and documents the
>   shape it accepts (field-alias map for vendor variance).
> - **Rules**: agent accessed credential material (`.env`, `id_rsa`,
>   `.aws/credentials`, …), tool-call burst per session (runaway/hijacked
>   agent), prompt-injection phrasing in tool arguments.
> - **Honest labeling**: the credential/injection detection is documented
>   string-pattern matching, not a classifier. The rules say so in their
>   descriptions. I'd rather ship a heuristic that's honest than an "AI
>   detection" that isn't.
>
> Architecture note that might interest this sub: everything normalizes to
> OCSF before the detection layer, so the same rule engine that runs
> brute-force detection on sshd logs runs these agent rules — one grammar,
> one CI gate that proves every rule is actually satisfiable by real parser
> output (we've shipped dead rules before; there's a check for that class of
> bug now).
>
> Repo: https://github.com/supermhel/fengarde
> Write-up on the OCSF-native design: <link to docs/posts/ocsf-native.md on GitHub>
>
> Limitations, honestly: v0.4, pre-1.0. Auth is an opt-in shared key, no
> TLS, single-host. The full status table (what works vs. what's planned) is
> the first thing in the README.

---

## 2. r/selfhosted (next day)

**Title:**
> FENGARDE – a self-hosted SIEM that shows you a real alert 60 seconds after `docker compose up` (Apache-2.0, OpenSearch, local AI triage optional)

**Body:**

> I kept seeing the same complaint here: Wazuh is too heavy, ELK is a
> part-time job, and everything lighter isn't really a SIEM. So I built
> FENGARDE with a hard rule: **a stranger must get from clone to a real alert
> in the dashboard in under 10 minutes.**
>
> ```
> git clone https://github.com/supermhel/fengarde.git && cd fengarde
> make preflight   # checks vm.max_map_count, Docker RAM, free ports
> make demo        # compose up -- a real SSH brute-force alert appears
>                  # in the dashboard within ~60s, no manual step
> ```
>
> <SCREENSHOT: dashboard with the brute-force alert>
>
> What it is: log collectors → OCSF normalization → sliding-window
> correlation rules → OpenSearch → dashboard. 10 parsers (SSH, Cisco ASA,
> AD, Windows Event Log, VMware, DB audit, generic syslog, plus newer ones:
> MCP/AI-agent logs, OPC UA industrial, n8n), 17 rules, all YAML.
>
> Things this sub will care about:
> - **No Elastic license asterisk** — storage is OpenSearch (Apache-2.0).
> - **AI triage never leaves your network** — optional local Ollama;
>   without it there's a documented stub and the pipeline works fine.
> - **No call-home, no cloud dependency, air-gap-friendly** (even the
>   geo-enrichment is a local CIDR→country file, not an API).
> - **Honest README** — there's a table of what works vs. what's planned.
>   No auth by default (opt-in shared key since v0.4), no TLS, localhost
>   by design. It's pre-1.0 and says so.
>
> If you try it and the 10-minute claim fails, tell me exactly where — the
> quickstart path IS the product right now.

---

## 3. Show HN (weekday, ~9am US Eastern, after 1+2 gave signal)

**Title (pick one):**
> Show HN: FENGARDE – open-source SIEM that turns factory and IT logs into NIS2 evidence
> Show HN: FENGARDE – an OCSF-native SIEM with local AI triage (Apache-2.0)

**Body:**

> FENGARDE is an open-source SIEM pipeline: raw security logs → OCSF
> normalization → sliding-window correlation → OpenSearch → dashboard.
> Apache-2.0, no open-core feature gates in the pipeline itself.
>
> Three design decisions that make it different from "yet another ELK
> wrapper":
>
> 1. **OCSF-native, not retrofitted.** Every parser (10 today: sshd, Cisco
>    ASA, AD, Windows Event Log, VMware, DB audit, generic syslog, MCP/
>    AI-agent tool-calls, OPC UA industrial control, n8n) emits the same
>    open schema, validated in CI. One brute-force rule covers every
>    authentication source, including an OPC UA engineering session.
> 2. **OpenSearch, not Elastic.** The open-source story has no license
>    asterisk.
> 3. **AI triage that never leaves your network.** Optional local Ollama;
>    the verdict is advisory (it annotates alerts detection already raised,
>    never suppresses them) and enum-coerced, so prompt injection via log
>    content can't gate detection. No Ollama → documented stub, pipeline
>    unaffected.
>
> The newest feature is an incident-report hook: an alert becomes a draft
> incident report (markdown, one click). The open backend is a plain
> template. The regulatory version (German NIS2/DORA notification drafts
> with citations to the actual EU legal text) is the commercial layer —
> CrowdSec-style open-plumbing/paid-content split, documented in the
> contract file in the repo. Every generated report is structurally forced
> to `status: "draft"` with a disclaimer — it's not legal advice and the
> code won't let it claim otherwise.
>
> Engineering practices I'm most attached to: a CI check that proves every
> detection rule is satisfiable by real parser output (we shipped "dormant"
> rules three times before building it); a zero-infra test gate (the whole
> pipeline runs on an in-memory bus, `make e2e` proves brute-force → alert
> → idempotent replay with no Docker); and an honest status table in the
> README because a security tool that overclaims is worse than no tool.
>
> What it's NOT yet: production-hardened. Auth is an opt-in shared key
> (v0.4), no TLS, single-host, OT parser fixtures are spec-derived rather
> than captured from live PLCs. It says all of this in SECURITY.md.
>
> https://github.com/supermhel/fengarde

---

## 4. r/blueteamsec (after signal from 1–3)

**Title:**
> Detection engineering: a CI gate that catches "dormant" rules (rules no parser can ever satisfy) — and the cross-source scoping bug it can't catch

**Body:**

> Post-mortem-style write-up from building FENGARDE (open-source SIEM). Two
> detection-content bug classes we hit, one we automated away, one that
> needs review discipline:
>
> **1. Dormant rules.** A rule keyed on a field no parser emits passes
> every unit test (synthetic fixtures include the field!) and never fires
> in production. We shipped this three times. Fix: a CI check that runs
> every registered parser against real fixtures, collects the set of
> (field, value) pairs the pipeline can actually produce, and fails the
> build if any rule's selections aren't satisfiable. Not "does the field
> exist somewhere" — the specific values equality-matched on.
>
> **2. Cross-source scoping.** Once two parsers emit the same OCSF class,
> a rule keyed only on class/activity can fire on the wrong source's
> events — or worse, pool unrelated sources into one shared window counter.
> We caught three instances when the third producer of class 6003 landed.
> The satisfiability gate can't catch this (it proves a rule CAN fire, not
> that it fires on the RIGHT events). Our fix is convention + review: any
> rule sharing a class with another producer carries an explicit
> source-type selection, and the coverage doc says why.
>
> Related: a stateful-rule counting bug where events missing the group-by
> field all pooled under a literal "None" bucket — two backends (in-memory
> vs Redis) disagreed about None distinct-values, and memory-only tests
> masked it. Fail-closed on unattributable events was the fix.
>
> Code for all of it (Apache-2.0): https://github.com/supermhel/fengarde —
> `tools/check_rule_producers.py` and `contracts/detection-coverage.md`
> have the details.

---

## Comment-prep sheet (expected questions, ready answers)

**"Why not just use Wazuh/Security Onion?"**
> Different goals. Wazuh is endpoint-first and Elastic-based; Security Onion
> is network-forensics-heavy. FENGARDE is pipeline-first: OCSF normalization +
> YAML correlation rules + a 10-minute self-hosted path. If Wazuh already
> works for you, keep it. If it felt like a second job, that's the gap this
> aims at.

**"Why another schema? / What's OCSF?"**
> Not ours — OCSF is the open schema backed by AWS/Splunk/dozens of vendors.
> The bet is the same one SigNoz made on OpenTelemetry: normalize to the
> standard once, and every rule works across every source, including sources
> that don't exist yet.

**"Elasticsearch is fine, why OpenSearch?"**
> Elastic is SSPL (source-available, not OSI open source). Fine for many
> uses; not fine for an "everything open" claim. OpenSearch is Apache-2.0 —
> no asterisk. That's the whole argument.

**"Local LLM triage — what about prompt injection?"**
> Log content IS attacker-controlled, and it goes into the triage prompt, so
> injection attempts are assumed. Two structural bounds: the verdict is
> advisory (annotates alerts detection already raised — can't suppress
> anything), and output is coerced to a fixed enum with a safe default.
> Robust injection *defenses* beyond that are documented as open, not
> claimed as solved. SECURITY.md §6.

**"Is the NIS2 report feature legal advice?"**
> No, and the code enforces that it can't pretend to be: every generated
> report is structurally forced to `status: "draft"` with a mandatory
> disclaimer — a backend response claiming anything else is rejected. The
> legally-validated German mapping is gated behind compliance/legal sign-off
> that hasn't happened yet, and the docs say so.

**"What's the business model / what's paid?"**
> Open-core, CrowdSec/ET-Pro style: the pipeline, parsers, rules, and the
> generic report template are Apache-2.0 forever. The paid layer is content —
> legally-validated regulatory mappings and (later) a trained triage model —
> in a separate private repo, plugging in via a documented additive contract
> (`contracts/reporting.md`). The open pipeline is complete without it; if it
> ever hard-depends on the paid layer, that's a bug by our own definition.

**"The OT/OPC UA parser — tested on real PLCs?"**
> No — fixtures are derived from the OPC UA Part 5 spec, and the parser's
> docstring says exactly that. Validating against a real industrial stack is
> what a design partner is for. If you run OPC UA and want to try it, that's
> the most useful feedback this project could get right now.

**"No auth?! In a SIEM?"**
> Default: localhost/compose-network only, documented since v0.1. v0.4 added
> opt-in shared-key auth on the write APIs, opt-in dashboard basic-auth, and
> opt-in Redis AUTH. The bus and store ports (Redis 6379, OpenSearch 9200,
> Dashboards 5601) bind to 127.0.0.1; the service ports (dashboard 8080,
> inventory API 8000, syslog 5514) publish on all interfaces by default, so
> put them behind your own network boundary until per-host binding lands.
> Per-user identity, roles, and TLS are documented as out of scope, not
> hidden. SECURITY.md is the honest version of this answer.

**"MCP log format isn't standardized, so what does the parser parse?"**
> Correct — there's no standard yet. The parser defines and documents the
> JSON shape it accepts (tool, arguments, session, agent), tolerates common
> field-name variants, and that documented shape is itself a proposal: "log
> your agent tool-calls like this and you get detection for free."

## Engagement rules

- Reply to every top-level comment same-day (HN especially — the first 2
  hours decide the trajectory).
- Concede fast, don't defend: if someone finds a real bug, "you're right,
  fixing it, here's the issue link" beats any defense.
- Never argue the honest-status point — it's the brand. If someone says
  "this is early," the answer is "yes, and the README says exactly how
  early."
- Do not mention fengarde-sec/the paid layer unprompted anywhere except the
  Show HN body (where omitting it would look evasive when someone reads
  `contracts/reporting.md`). If asked, use the business-model answer above.
