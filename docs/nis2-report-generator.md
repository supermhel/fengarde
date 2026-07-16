# NIS2 report generator (Germany, M5)

FENGARDE can turn an alert into a deterministic, German-language (English
toggle) draft structured around the German NIS2UmsuCG's three-stage
incident-reporting obligation (§32 BSIG, implementing NIS2 Directive
(EU) 2022/2555 Article 23): a 24-hour early warning (*Erstmeldung*), a
72-hour notification (*Meldung*), and a 1-month final report
(*Abschlussbericht*).

**Read this whole page before using a generated draft for anything real.**

## What this is

- `contracts/nis2-de-schema.json` — the field schema, with citations to the
  directive and its German implementation in every field's description.
- `services/ws3-indexer/nis2_template.py` — a deterministic renderer, zero
  LLM, zero paid dependency. `POST /alerts/{id}/report?template=nis2&stage=
  <stage>&lang=<de|en>` (see `contracts/reporting.md`'s "NIS2 template
  mode" section) or the dashboard's "NIS2 (DE)" button.
- `eval/report_generator/` — ≥10 synthetic incident scenarios, sourced from
  this repo's own real rule set (`contracts/rules/*.yml`), each checked
  against a checklist (disclaimer present, status is draft, the input
  alert's facts are preserved verbatim, the scope caveat is present,
  citations are present, entity facts are never fabricated). Runs in CI
  (`run_all_tests.sh`) with zero infrastructure.
- `make nis2-demo` (`tools/demo_nis2.py`) — a privileged database GRANT on
  a banking-sector host fires `contracts/rules/bank_db_priv_esc.yml`,
  reaches the indexer as a real alert, and becomes a German NIS2 draft —
  end to end, zero infra, zero manual steps.

## What this is NOT

**Not legal advice, not a legal determination, not a filing.** Every
generated draft carries the same structural "DRAFT — not legal advice"
banner (top and bottom) that every FENGARDE report does
(`contracts/reporting.md`'s hard rules), plus an NIS2-specific caveat
explained below.

**Not a substitute for knowing your own regulatory classification.** This
is the single most important caveat, so it is stated three times — in the
schema, in every generated draft's body, and here:

> Financial entities in the EU are typically governed by **DORA**
> (Regulation (EU) 2022/2554, Article 19), a *different* incident-reporting
> regime with different timelines and (in Germany) a different competent
> authority — **BaFin, not BSI**. NIS2's Article 4 "lex specialis" clause
> excludes entities already covered by sector-specific EU legislation
> deemed "at least equivalent," and DORA is explicitly named as such.
>
> FENGARDE's internal `sector: bank | datacenter | common` tag is a
> **detection-routing label**, used to pick which correlation rules apply
> and which OpenSearch index a document lands in. It is **not** a
> regulatory classification, and this generator never treats it as one —
> it does not infer, guess, or assert which regime (NIS2, DORA, or
> something else entirely) applies to your organization. You must confirm
> that yourself before using any generated draft.

**Not a source of entity facts.** Your organization's name, its NIS2
Annex I/II classification (essential/important entity), and its actual
competent authority are never in an alert document — every such field in
the draft is rendered as an explicit `[ANALYST MUST PROVIDE]` /
`[ANALYST MUSS ANGEBEN]` placeholder, never guessed or left silently blank.

**Not a "significant incident" determination.** NIS2 Art. 23(3)'s
threshold (severe operational disruption, financial loss, or considerable
damage to others) is a judgment call for the reporting entity. A
FENGARDE alert's `score`/`level` inform that judgment but never
substitute for it — always rendered as a placeholder, never auto-derived.

**Not PDF.** Markdown only. A PDF renderer (e.g. weasyprint) is a real,
heavier dependency decision explicitly deferred to the project owner —
see the combined plan's M5 section.

**Not the `fengarde-sec` paid layer.** `contracts/reporting.md`'s frozen
seam still has an `http` backend for a legally-mapped, cited, RAG-backed
draft (DORA/NIS2/BSI/BaFin content) — that is `fengarde-sec`'s asset, a
different product. This page describes the OPEN, deterministic,
zero-paid-dependency layer only.

**Not exercised against a live regulatory submission portal.** This
generates a draft document; it does not submit anything anywhere. The
actual submission channel (BSI's Meldeportal, or your sector's competent
authority) is outside this repo's scope entirely.

## Sources

The schema's structure is derived from the directive's public text and
public secondary guidance — cited per-generated-report in the `citations`
field (CELEX `32022L2555` Article 23; §32 BSIG / NIS2UmsuCG) — never from
this generator making a legal claim on its own authority. If you find the
field structure incomplete or out of date with the current statute, that
is exactly the kind of report worth filing against this repo.
