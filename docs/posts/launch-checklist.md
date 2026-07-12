# Launch checklist (v0.4 Track D3)

Sequencing for the distribution push, per the v0.4 build plan
(`docs/superpowers/specs/2026-07-10-argiem-v0.4-build-plan.md`, Track D). 0
stars/forks/watchers today — this is genuinely pre-launch. Publishing itself
is a human action; nothing here fires automatically.

## Prerequisite (must be true before posting anywhere)

- [ ] `make demo` verified end-to-end on a clean machine (Track D1) — a real
      alert must appear in the dashboard within the promised ~30-60s, no
      manual step. If this breaks, every post below directs traffic at a
      broken first impression.
- [ ] README quickstart section reads correctly top-to-bottom on a fresh
      clone (Track D2 — already landed).
- [ ] `bash run_all_tests.sh` green on `main` (`ALL TESTS PASS`).

## Sequencing

1. **r/netsec** — lead with the MCP/AI-agent parser + rule pack (Track P1).
   This is the single highest-attention item: no open-source detection
   content exists yet for AI-agent telemetry, and r/netsec skews toward
   exactly the audience that cares about a new, uncontested attack surface.
   Post the [`ocsf-native.md`](ocsf-native.md) write-up as a companion —
   shows the parser isn't a one-off gimmick, it's the 9th instance of one
   documented pattern.
2. **r/selfhosted** — the quickstart is the pitch here, not the architecture.
   Lead with "10-minute `docker compose up`, see a real alert with zero
   config," link straight to the Quickstart section. This is the community
   that has generated the "Wazuh is too heavy" complaint the whole homelab
   wedge depends on — don't bury that under detection-engineering detail.
3. **Show HN** — the fullest pitch: the Mittelstand/NIS2 positioning
   (`README.md`'s headline), the three differentiators
   (OCSF-native/OpenSearch-no-asterisk/local-AI), and the three new v0.4
   write-ups linked as comments respond to specific technical questions
   (expect "why not Elastic," "why local LLM," "why yet another schema" —
   each has a dedicated post ready). Post during a weekday US-morning window
   for visibility; monitor and reply to every top-level comment same-day.
4. **r/blueteamsec** — narrower, more skeptical audience; post after the
   above have generated some initial signal/traffic, framed around the
   detection-content angle (rule packs + the anti-dormancy CI guardrail) as
   a "here's how we try to avoid shipping dead rules" engineering post, not
   a product pitch.

## What NOT to do

- Don't lead with the ARGIEM-Sec/paid layer anywhere in this round. It's
  Wave-0/RAG-stage, no design partner yet — premature to market (per
  argiem-sec's own `docs/STATUS.md` discipline: don't claim what isn't real).
- Don't claim OT/industrial fixtures are field-validated — they're
  spec-derived (documented in `opcua_audit.py`'s docstring). If asked in
  comments, say so directly; a design partner with a real OPC UA stack is
  the next validation step, not a hidden gap.
- Don't skip the prerequisite checklist above to hit a launch-day deadline.
  A broken first `docker compose up` for a new visitor is worse than a
  delayed post.
