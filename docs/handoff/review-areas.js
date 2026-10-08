export const meta = {
  name: 'review-wave12-deep-part2',
  description: 'Deep adversarial review: differential/property/fuzz tests in sandbox worktrees, every finding re-reproduced by an independent verifier',
  phases: [
    { title: 'Attack', detail: 'eight reviewers, each in its own sandbox worktree, must run experiments' },
    { title: 'Verify', detail: 'independent reproduction of each finding in a fresh sandbox' },
  ],
}

const BASE = '7205945'
const FIRST_REVIEWED = 'e18e3f2'

const COMMON = `
You are a hostile reviewer of AI-written code in the FENGARDE repo. Your sandbox is a git worktree created from main, NOT the feature branch: first run  git reset --hard ${BASE}  (verify with git log --oneline -1). It is YOUR sandbox: you may edit/create files and run anything in it to test hypotheses, but NEVER commit, push, or touch any other directory (the lead's tree and other agents' worktrees live under .claude/worktrees; stay in yours). Delete nothing outside it.
Scope: everything changed since ${FIRST_REVIEWED} (git diff ${FIRST_REVIEWED}..HEAD). Read CLAUDE.md first. Commit messages, comments, docs and test names are CLAIMS by the authors: do not trust them. A previous read-only review returned ~zero findings after 7 minutes of file listing -- that is not credible for this diff. READING IS NOT ENOUGH: your deliverable is EXPERIMENTS. For each claim of correctness in your area, design an experiment that could falsify it (differential test old-vs-new via 'git show ${FIRST_REVIEWED}:<path>' loaded as a module, property test against a trivial reference model, fuzzing, sabotage of an instrument to see whether it goes red, adversarial config files), RUN it, and report what happened. Do NOT run run_all_tests.sh (25 min) -- run single-file tests and your own scripts (keep each under ~2 min). Windows + Git Bash, repo-relative paths.
Report only real defects: wrong results, security/fail-open problems, instruments that pass vacuously, claims the code does not back, regressions of previously working behaviour. For each: file, line, severity (critical/high/medium/low), summary, failure_scenario, and 'repro' = an exact self-contained command or python snippet plus the observed output that demonstrates it (copy-pasteable, runnable from a fresh checkout of ${BASE}). No repro -> say so and mark confidence 'low'. Also return 'experiments' = list of {what, result} for EVERY experiment you ran, including those that found nothing (this is how we judge the depth of the review). At most 12 findings.
`

const OUT = {
  type: 'object',
  properties: {
    area: { type: 'string' },
    experiments: { type: 'array', items: { type: 'object', properties: { what: { type: 'string' }, result: { type: 'string' } }, required: ['what', 'result'] } },
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          file: { type: 'string' }, line: { type: 'number' }, severity: { type: 'string' },
          confidence: { type: 'string' }, summary: { type: 'string' },
          failure_scenario: { type: 'string' }, repro: { type: 'string' },
        },
        required: ['file', 'line', 'severity', 'summary', 'failure_scenario', 'repro'],
      },
    },
  },
  required: ['area', 'experiments', 'findings'],
}

const VERDICT = {
  type: 'object',
  properties: {
    verdict: { type: 'string', enum: ['CONFIRMED', 'REFUTED', 'UNCERTAIN'] },
    evidence: { type: 'string' },
    corrected_severity: { type: 'string' },
    minimal_fix: { type: 'string' },
  },
  required: ['verdict', 'evidence'],
}

const AREAS = [
  { key: 'ssh-differential', task: `services/ws2-normalization/parsers/linux_ssh.py. Load the OLD module ('git show ${FIRST_REVIEWED}:services/ws2-normalization/parsers/linux_ssh.py') and the NEW one; build a corpus of >=300 sshd lines: every sample in repo tests/fixtures/eval datasets (grep -r sshd), plus generated shapes (Failed/Accepted password|publickey|keyboard-interactive, invalid user, IPv6 and v4-mapped sources, 'Connection closed by authenticating user', 'Disconnected from', 'maximum authentication attempts', pam_unix auth failure with rhost/user, 'PAM n more authentication failures', 'sshd-session[pid]:' tags used by OpenSSH 9.8+, journald and RFC5424 prefixes, usernames with spaces/unicode/quotes/very long, CRLF/tabs, lines with two 'from <ip>'). For every line where old != new parse (activity/status/user/ip/port), classify INTENDED (forgery now blocked) vs REGRESSION (a real, legitimate line now dropped or mis-attributed). Also time the NEW regexes on adversarial 64KB lines (ReDoS) and report worst case.` },
  { key: 'window-property', task: `services/shared/window.py (DequeWindowCounter after the F1 per-key _exp change) and services/ws4-detection engine use of it. Build a trivial reference model (per key: list of (ts,member) filtered by its OWN window, no sweeping) and drive both with random interleavings of hit / hit_distinct / hit_periodic over several keys and several window sizes (60 s..3600 s), random time steps incl. equal timestamps, backwards timestamps, huge jumps, members repeated, keys reused with a CHANGED window between calls. Counts must equal the model. Also assert the internal dicts (_w,_dw,_live_members,_last,_exp) never keep a key that the model considers empty for long (memory growth: feed 1e6 distinct keys, report sizes), and compare the OLD module ('git show ${FIRST_REVIEWED}:services/shared/window.py') for any count that differs from NEW where the model agrees with OLD (regression). Check RedisWindowCounter by reading + (if a redis server is reachable on localhost:6379 or 6390, run its hit/hit_distinct against the same model; otherwise say not run).` },
  { key: 'tenant-defaultoff', task: `Default-off rule state: services/ws4-detection/{engine,main,tenants}.py, services/ws3-indexer/rules_view.py (+router/api consumers), tools/validate_rules.py, contracts/rules/ot_opcua_write_unauthorized_node.yml, contracts/tenants. Build an adversarial config matrix and check BOTH the real Detector behaviour and the rules_view 'enabled' report agree for each cell: tenant file missing / empty / malformed yaml / enabled_rules as string|dict|int|list-with-non-strings|null / disabled_rules+enabled_rules both containing the rule / tenant id with path traversal or unicode / default tenant / FENGARDE_OPT_IN_RULES with spaces, empty items, duplicates, upper-case ids, a non-existent id; opt_in_rules kwarg; cache staleness after editing a tenant file (invalidate path in main.py hot reload); companion_of of a default-off sibling; a default-off rule in plugin_rule_dirs. Any case where a default-off rule evaluates WITHOUT an explicit opt-in, where a default-ON rule silently stops evaluating, or where rules_view disagrees with the Detector, is a finding. Also check Detector.process cost: is the opt-in check done per event per rule (hot path)? measure with 20k events before/after (compare ${FIRST_REVIEWED}).` },
  { key: 'bus-differential', task: `services/shared/bus.py _MemoryBus after the wire-string _Entry change, plus services/ws8-correlation/campaigns.py. Differential-test the OLD memory bus ('git show ${FIRST_REVIEWED}:services/shared/bus.py') vs NEW with random sequences (produce/consume/ack/claim_pending/drain/depth, several consumer groups, several topics, partial acks, redelivery counts, PEL cap, block_ms) and compare delivered ids, order, payload values, delivery counts, depth(). Verify the NEW one never leaks a mutable payload between deliveries, handles non-str keys / None key / unicode / NaN / huge payloads like Redis would (read _RedisBus and compare; run real Redis if reachable on localhost:6379/6390). Check _Entry.payload re-parse cost semantics (does anything call .payload in a loop = O(n) parses?) by profiling the real consumers (ws2/ws4 runner loops) over 50k messages old vs new. For campaigns.py: property-test link_campaigns (order independence, id stability under growth, merge lineage via previous=, tenant-less incidents, duplicate incident ids, 60k incidents runtime).` },
  { key: 'harness-validity', task: `Grader and oracle instruments: eval/twin/{report,causal_order,oracle_mutate,oracle_derive,oracle_consistency,scenario_registry,storyline_phishing_bec}.py, eval/adversarial/{order_controls,scenario_matrix,layer_a}.py, oracle yamls. Try to make instruments pass VACUOUSLY: in your sandbox sabotage the product/harness (e.g. make grade_causal_order always return 1.0; make order_controls' mirror a no-op; delete an expected rule from an oracle; swap two steps; make a negative twin builder ignore its 'restored' switch; make the derived oracle read the hand oracle) and check that the corresponding test/gate goes RED. Every sabotage that stays green is a finding (the control cannot fail). Check determinism: run oracle_mutate.py / scenario_matrix.py twice and diff the outputs; check import-time side effects of storyline auto-discovery (a broken eval/twin/storyline_*.py file: does one bad file hide the others or crash silently?). Verify the SSOT/CHANGELOG numbers for these (e.g. '84 rows 0 flips', mutant counts) by recomputing.` },
  { key: 'evasion-ratchet', task: `Adversarial lane: eval/adversarial/{probe_session,evasion_search,evasion_cost,evasion_axes,rule_probes,noise_dilution,mutate_generic,technique_matrix}.py with evasion_floor.yaml, evasion_findings.yaml, evasion_tables.yaml, technique_waivers.yaml. Try to defeat the ratchets in the sandbox: hand-lower an evasion_floor value (does any check catch it?), raise a rule threshold in a rule YAML and see which gate notices (fingerprint?), edit an allowlist, delete a findings-register entry for a still-reproducing evasion, add a bogus waiver, re-date a waiver, change seed. Check FastProbe parity honestly: does verify_parity compare against an independent implementation or reuse the same code path? Break the leaky-counter negative control. For mutate_generic variants: for every variant x storyline, is there a variant that 'passes' while changing nothing (vacuous) or that changes a field the parser ignores? Verify determinism (dict order, random seeds, wall clock use).` },
  { key: 'blindrecall-tools', task: `eval/detection_accuracy/{fetch_corpora,corpus_adapters,technique_match,blind_recall}.py, corpus_manifest.json, test_blind_recall.py, tools/dns_cardinality_report.py (+test), tools/live_companion_e2e.py. Security: craft malicious manifest/dataset YAML (path traversal in file lists, absolute paths, symlinks, '..', huge files, yaml python tags - is yaml.safe_load used everywhere?), commands built for git/lfs (shell=True? unvalidated refs/urls -> argument injection like a ref starting with '-'), evtx/XML parsing (XXE/entity expansion in the XML reader used for Windows event XML), zip extraction. Correctness: funnel invariant sum(buckets)==units under multi-label scenarios and partial parses; label leakage (does any code path read engine output to decide a label/bucket?); technique_match parent()/match_level edge cases (T1110.003 vs T1110.004 siblings, ICS ids, malformed ids, lowercase). dns_cardinality_report: feed the same synthetic traffic in all formats, check the sliding-window max against a brute-force model, malformed/huge/binary input, the suggestion text for an obviously malicious parent. live_companion_e2e wait helpers: can the negatives still pass vacuously (fake search injected)?` },
  { key: 'claims-audit', task: `Docs versus code. Take every quantitative or behavioural claim added to SSOT.md, CHANGELOG.md, eval/adversarial/README.md, eval/detection_accuracy/README.md, contracts/detection-coverage.md, contracts/allowlists/*.yml headers, rule descriptions and docs/proposals/* since ${FIRST_REVIEWED} (git diff ${FIRST_REVIEWED}..HEAD -- those files) and CHECK it: recompute numbers by running the relevant tool (layer_a.py --seed 7, scenario_matrix.py, evasion_cost.py, technique_matrix.py, oracle_mutate.py --seed 7, tools/dns_cardinality_report.py on synthetic data...), grep for referenced files/functions/flags that must exist (every path, CLI flag, function name, env var, rule id mentioned), check rule ids in oracles/allowlists/waivers exist in contracts/rules, check each 'Gate: ... N stanzas' count, each 'owner decision' that is described as NOT taken really is not taken in code (e.g. causal_order_retained not in pass; headline unchanged), and every claim of 'byte-identical' (sha256 of eval/twin/baseline.json vs ${FIRST_REVIEWED}). Report each mismatch as a finding with the exact claim, the file/line, and the command that shows the truth.` },
]

const REMAINING = ['tenant-defaultoff', 'harness-validity', 'evasion-ratchet', 'blindrecall-tools', 'claims-audit']
const results = await pipeline(
  AREAS.filter(a => REMAINING.includes(a.key)),
  a => agent(`${COMMON}\nAREA: ${a.key}\n${a.task}`,
    { label: `attack:${a.key}`, phase: 'Attack', isolation: 'worktree', schema: OUT }),
  (rev, a) => rev && rev.findings && rev.findings.length
    ? parallel(rev.findings.map(f => () =>
        agent(`You are an independent VERIFIER. Sandbox: a git worktree created from main; first run  git reset --hard ${BASE}  and verify with git log --oneline -1. You may edit/run anything inside it; never commit/push/touch other directories. Do NOT run run_all_tests.sh. A reviewer claims:\nfile: ${f.file}:${f.line}\nseverity: ${f.severity} (confidence ${f.confidence || 'n/a'})\nsummary: ${f.summary}\nfailure scenario: ${f.failure_scenario}\nrepro offered:\n${f.repro}\n\nRe-run the repro yourself from scratch (fix it up if it is slightly broken) and also try to REFUTE the claim by reading the code. CONFIRMED only if you reproduced the wrong behaviour yourself; REFUTED if the code behaves correctly (say what you ran); UNCERTAIN if neither. Give exact commands + observed output, a corrected severity, and a minimal fix.`,
          { label: `verify:${a.key}:${String(f.file).split('/').pop()}:${f.line}`, phase: 'Verify', isolation: 'worktree', schema: VERDICT })
          .then(v => ({ area: a.key, finding: f, verdict: v }))))
    : [],
)

const flat = results.filter(Boolean).flat().filter(Boolean)
const confirmed = flat.filter(r => r.verdict && r.verdict.verdict === 'CONFIRMED')
log(`${flat.length} findings verified; ${confirmed.length} CONFIRMED`)
return { flat }
