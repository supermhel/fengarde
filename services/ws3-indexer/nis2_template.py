"""M5: NIS2 (Germany) deterministic incident-report template.

Public template layer per the combined plan's decision #1: a schema
(``contracts/nis2-de-schema.json``) plus a deterministic, German-language
(English toggle) renderer that extends the existing generic template
backend (``reporting.py``) rather than replacing it -- ``REPORT_BACKEND``
and the ``http``/``fengarde-sec`` seam are untouched; this is a second,
purely additive rendering mode selected by query parameters on the SAME
``POST/GET /alerts/{alert_id}/report`` endpoint (see ``contracts/
reporting.md``'s "NIS2 template mode" section).

Zero paid dependency, zero LLM required. Every field that isn't knowable
from the alert + triage documents is rendered as an explicit
``[ANALYST MUST PROVIDE]`` / ``[ANALYST MUSS ANGEBEN]`` placeholder, never
fabricated or guessed -- same discipline as the generic template's
"Fields an analyst must still provide" section, just structured per NIS2's
three reporting stages instead of generically.

**DRAFT -- NOT LEGAL ADVICE.** See ``contracts/nis2-de-schema.json``'s
top-level ``description`` for the full scope caveat, most importantly the
NIS2-vs-DORA distinction for financial entities (DORA, not NIS2, governs
incident reporting for EU financial entities -- FENGARDE's internal
``sector: bank`` detection-routing tag is NOT a regulatory classification
and must never be treated as one).
"""
from __future__ import annotations

import time

STAGES = ("early_warning", "notification", "final_report")
LANGUAGES = ("de", "en")

_DISCLAIMER = {
    "de": ("ENTWURF — automatisch erstellt. Keine Rechtsberatung. Vor jeder "
           "behördlichen Meldung durch eine sachkundige Person (Datenschutz-/"
           "IT-Sicherheitsbeauftragte:r, ggf. externe Rechtsberatung) prüfen."),
    "en": ("DRAFT — automatically generated. Not legal advice. Review by a "
           "qualified person before any regulatory submission."),
}

_STAGE_LABEL = {
    "de": {
        "early_warning": "Erstmeldung (24-Stunden-Frist, Art. 23 Abs. 4 lit. a NIS2 / §32 BSIG)",
        "notification": "Meldung (72-Stunden-Frist, Art. 23 Abs. 4 lit. b NIS2 / §32 BSIG)",
        "final_report": "Abschlussbericht (1-Monats-Frist, Art. 23 Abs. 4 lit. d NIS2 / §32 BSIG)",
    },
    "en": {
        "early_warning": "Early warning (24-hour deadline, NIS2 Art. 23(4)(a))",
        "notification": "Incident notification (72-hour deadline, NIS2 Art. 23(4)(b))",
        "final_report": "Final report (1-month deadline, NIS2 Art. 23(4)(d))",
    },
}

_SCOPE_CAVEAT = {
    "de": (
        "**Wichtiger Anwendungsbereich-Hinweis:** Dieser Entwurf geht davon aus, dass Ihre "
        "Organisation der NIS2-Meldepflicht (§32 BSIG) unterliegt. Finanzunternehmen "
        "unterliegen stattdessen in der Regel DORA (Verordnung (EU) 2022/2554, Art. 19) mit "
        "einem eigenen, abweichenden Melderegime (typischerweise BaFin statt BSI als "
        "zuständige Behörde). Die interne FENGARDE-Sektor-Kennzeichnung "
        "(`bank`/`datacenter`/`common`) dient nur der Erkennungs-Zuordnung und ist KEINE "
        "regulatorische Einstufung. Prüfen Sie die tatsächlich anwendbare Regelung, bevor "
        "Sie diesen Entwurf verwenden."
    ),
    "en": (
        "**Important scope note:** this draft assumes your organization is subject to "
        "NIS2's reporting obligation (§32 BSIG in Germany). Financial entities are "
        "typically governed by DORA instead (Regulation (EU) 2022/2554, Art. 19), a "
        "separate reporting regime (usually BaFin, not BSI, as the competent authority). "
        "FENGARDE's internal sector tag (`bank`/`datacenter`/`common`) is a "
        "detection-routing label only, NOT a regulatory classification. Confirm the "
        "actually applicable regime before using this draft."
    ),
}

_LABELS = {
    "de": {
        "title": "NIS2-Meldeentwurf",
        "entity_section": "## Meldende Einrichtung",
        "entity_name": "Name der Einrichtung",
        "entity_class": "Einstufung (wesentlich/wichtig nach NIS2 Anhang I/II, oder anderes Regime)",
        "entity_authority": "Zuständige Behörde",
        "incident_section": "## Vorfall",
        "incident_title": "Bezeichnung",
        "detected_at": "Erkannt am",
        "severity": "Schweregrad (FENGARDE-Regelwerk)",
        "score": "Score (FENGARDE-Regelwerk)",
        "significant": "Einstufung als „erheblicher Sicherheitsvorfall“ (Art. 23 Abs. 3 NIS2)",
        "early_warning_section": "## Angaben zur Erstmeldung",
        "suspected_malicious": "Verdacht auf rechtswidrige/böswillige Handlung?",
        "cross_border": "Möglicher grenzüberschreitender Effekt?",
        "notification_section": "## Angaben zur Meldung",
        "impact": "Erste Bewertung von Schweregrad und Auswirkung",
        "ioc": "Kompromittierungsindikatoren (Indicators of Compromise)",
        "final_section": "## Angaben zum Abschlussbericht",
        "root_cause": "Ursache / Art der Bedrohung",
        "mitigation": "Ergriffene und laufende Abhilfemaßnahmen",
        "source_section": "## Quelle: FENGARDE-Alarm",
        "alert_id": "Alarm-ID",
        "rule": "Regel",
        "triage_status": "Bearbeitungsstatus",
        "note": "Analystennotiz",
        "todo_section": "## Noch zu ergänzende Angaben",
    },
    "en": {
        "title": "NIS2 Notification Draft",
        "entity_section": "## Reporting entity",
        "entity_name": "Entity name",
        "entity_class": "Classification (essential/important under NIS2 Annex I/II, or a different regime)",
        "entity_authority": "Competent authority",
        "incident_section": "## Incident",
        "incident_title": "Title",
        "detected_at": "Detected at",
        "severity": "Severity (FENGARDE rule)",
        "score": "Score (FENGARDE rule)",
        "significant": "'Significant incident' assessment (NIS2 Art. 23(3))",
        "early_warning_section": "## Early-warning fields",
        "suspected_malicious": "Suspected unlawful/malicious act?",
        "cross_border": "Possible cross-border impact?",
        "notification_section": "## Notification fields",
        "impact": "Initial severity/impact assessment",
        "ioc": "Indicators of compromise",
        "final_section": "## Final-report fields",
        "root_cause": "Root cause / threat type",
        "mitigation": "Mitigation measures applied and ongoing",
        "source_section": "## Source: FENGARDE alert",
        "alert_id": "Alert ID",
        "rule": "Rule",
        "triage_status": "Triage status",
        "note": "Analyst note",
        "todo_section": "## Fields an analyst must still provide",
    },
}

_PLACEHOLDER = {"de": "[ANALYST MUSS ANGEBEN]", "en": "[ANALYST MUST PROVIDE]"}


def _ph(lang: str) -> str:
    return _PLACEHOLDER[lang]


def _fmt_time(epoch_ms) -> str:
    if not isinstance(epoch_ms, (int, float)) or isinstance(epoch_ms, bool):
        return "(unknown)"
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch_ms / 1000))


def _citations() -> list[dict]:
    """Public sources this draft's STRUCTURE is based on -- always the same
    two, since they're the directive/statute itself, not a per-incident
    lookup. Matches contracts/reporting.md's citations shape."""
    return [
        {"celex": "32022L2555", "article": "Article 23",
         "url": "https://eur-lex.europa.eu/eli/dir/2022/2555/oj", "retrieved_at": "2026-07"},
        {"celex": "national-implementation", "article": "§32 BSIG (NIS2UmsuCG)",
         "url": "https://www.gesetze-im-internet.de/bsig_2009/", "retrieved_at": "2026-07"},
    ]


def render_nis2_report(alert: dict, triage: dict, *, stage: str = "notification",
                        lang: str = "de") -> str:
    """Deterministic Markdown draft for one NIS2/§32 BSIG reporting stage.

    ``stage``: one of STAGES (defaults to "notification", the first stage
    with a substantive field set). ``lang``: "de" (default) or "en".
    Unknown values fall back to the defaults rather than raising -- a
    malformed query parameter must degrade gracefully, not break report
    generation."""
    if stage not in STAGES:
        stage = "notification"
    if lang not in LANGUAGES:
        lang = "de"
    L = _LABELS[lang]
    ph = _ph(lang)

    rule_title = alert.get("rule_title", "(unknown rule)")
    level = alert.get("level", "unknown")
    score = alert.get("score", "unknown")
    when = _fmt_time(alert.get("time"))
    status = triage.get("status", "new")
    note = triage.get("note") or ("(keine)" if lang == "de" else "(none)")

    lines = [
        f"# {L['title']} — {_STAGE_LABEL[lang][stage]}",
        "",
        f"_{_DISCLAIMER[lang]}_",
        "",
        _SCOPE_CAVEAT[lang],
        "",
        L["entity_section"],
        f"- {L['entity_name']}: {ph}",
        f"- {L['entity_class']}: {ph}",
        f"- {L['entity_authority']}: {ph} "
        + ("(z. B. BSI, sofern nicht sektorspezifisch anders zuständig)" if lang == "de"
           else "(e.g. BSI, unless a sector-specific authority applies)"),
        "",
        L["incident_section"],
        f"- {L['incident_title']}: {rule_title}",
        f"- {L['detected_at']}: {when}",
        f"- {L['severity']}: {level}",
        f"- {L['score']}: {score}",
        f"- {L['significant']}: {ph}",
        "",
    ]

    if stage in ("early_warning", "notification", "final_report"):
        lines += [
            L["early_warning_section"],
            f"- {L['suspected_malicious']}: {ph}",
            f"- {L['cross_border']}: {ph}",
            "",
        ]

    if stage in ("notification", "final_report"):
        lines += [
            L["notification_section"],
            f"- {L['impact']}: "
            + (f"Score {score}/100, Schweregrad {level} laut FENGARDE-Korrelation — {ph} (menschliche Bewertung erforderlich)"
               if lang == "de" else
               f"Score {score}/100, severity {level} per FENGARDE correlation — {ph} (human assessment required)"),
            f"- {L['ioc']}: {ph}",
            "",
        ]

    if stage == "final_report":
        lines += [
            L["final_section"],
            f"- {L['root_cause']}: {ph}",
            f"- {L['mitigation']}: "
            + (f"Analystennotiz: {note} — {ph} (vollständige Maßnahmenliste erforderlich)"
               if lang == "de" else
               f"Analyst note: {note} — {ph} (complete list of measures required)"),
            "",
        ]

    lines += [
        L["source_section"],
        f"- {L['alert_id']}: {alert.get('alert_id', '(unknown)')}",
        f"- {L['rule']}: {alert.get('rule_id', '(unknown)')} ({rule_title})",
        f"- {L['triage_status']}: {status}",
        f"- {L['note']}: {note}",
        "",
        L["todo_section"],
        f"- {ph}: " + ("Einstufung als erheblicher Sicherheitsvorfall bestätigen"
                        if lang == "de" else "confirm the significant-incident classification"),
        f"- {ph}: " + ("zuständige Behörde und Meldeweg bestätigen"
                        if lang == "de" else "confirm the competent authority and submission channel"),
        f"- {ph}: " + ("regulatorisches Regime bestätigen (NIS2 vs. DORA vs. anderes)"
                        if lang == "de" else "confirm the applicable regulatory regime (NIS2 vs. DORA vs. other)"),
        "",
        f"_{_DISCLAIMER[lang]}_",
    ]
    return "\n".join(lines)


def build_report(alert: dict, triage: dict, *, stage: str = "notification",
                  lang: str = "de", requested_at: float | None = None) -> dict:
    """Same response envelope as reporting.py's _template_backend (contracts/
    reporting.md's frozen schema) -- this is an additive rendering MODE of
    the same report, not a different contract."""
    if stage not in STAGES:
        stage = "notification"
    if lang not in LANGUAGES:
        lang = "de"
    requested_at = time.time() if requested_at is None else requested_at
    return {
        "report_id": f"{alert.get('alert_id')}:report",
        "alert_id": alert.get("alert_id"),
        "format": "markdown",
        "body": render_nis2_report(alert, triage, stage=stage, lang=lang),
        "status": "draft",
        "disclaimer": _DISCLAIMER[lang],
        "generated_at": int(requested_at * 1000),
        "backend": "template-nis2-de",
        "backend_degraded": False,
        "citations": _citations(),
    }
