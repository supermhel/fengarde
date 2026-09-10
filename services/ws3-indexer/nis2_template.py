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


def _warn(msg: str) -> None:
    """R3-#43: fail loudly (log) on a silent default-coercion, never raise.
    Import is lazy so the module stays import-light and logging is
    best-effort (a logging outage can't break report generation)."""
    try:
        from shared.log import get_logger  # noqa: PLC0415
        get_logger("ws3-indexer-nis2").warn(msg)
    except Exception:  # noqa: BLE001 - best-effort
        pass


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
    generation. R3-#43: such a coercion is logged loudly (it used to be
    silent, so a typo'd ?stage= silently produced the wrong regulatory
    section)."""
    if stage not in STAGES:
        _warn(f"nis2 report stage {stage!r} is not one of {STAGES}; coercing "
              "to 'notification' default")
        stage = "notification"
    if lang not in LANGUAGES:
        _warn(f"nis2 report lang {lang!r} is not one of {LANGUAGES}; coercing "
              "to 'de' default")
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
    the same report, not a different contract.

    R3-#42: contracts/nis2-de-schema.json requires `stage`/`language`/
    `entity`/`incident` in the envelope; the generator used to omit all four
    (the entity/incident facts live in the Markdown body as ANALYST place-
    holders, but were never surfaced as structured fields). They are now
    emitted: stage/language are the real, coerced values; entity/incident
    carry the same explicit placeholders the rendered body does -- nothing
    fabricated. R3-#43: an invalid stage/lang is logged loudly on coercion."""
    if stage not in STAGES:
        _warn(f"nis2 build_report stage {stage!r} is not one of {STAGES}; "
              "coercing to 'notification' default")
        stage = "notification"
    if lang not in LANGUAGES:
        _warn(f"nis2 build_report lang {lang!r} is not one of {LANGUAGES}; "
              "coercing to 'de' default")
        lang = "de"
    requested_at = time.time() if requested_at is None else requested_at
    ph = _ph(lang)
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
        # R3-#42: satisfy contracts/nis2-de-schema.json's required envelope.
        "stage": stage,
        "language": lang,
        "entity": {
            "name": ph,
            "sector_classification": ph,
            "competent_authority": ph,
        },
        "incident": {
            "title": alert.get("rule_title") or "(unknown rule)",
            "detected_at": _fmt_time(alert.get("time")),
            "severity": alert.get("level") or "unknown",
            "significant_incident_assessment": ph,
            "suspected_malicious": None,   # null = not yet determined (Art. 23(4)(a))
            "cross_border_impact": None,   # null = not yet determined (Art. 23(4)(a))
            "impact_assessment": ph,
            "indicators_of_compromise": [],
            "root_cause": ph,
            "mitigation_measures": ph,
        },
    }


# ---------------------------------------------------------------------------
# Phase 5 (2026-09-04): incident-level draft, from an evidence package.
#
# Deliberately NOT built on build_report() above or contracts/reporting.md's
# frozen alert-scoped seam -- that schema's response is hardcoded
# report_id: "{alert_id}:report" and is a real cross-repo contract
# fengarde-sec's paid backend also implements; widening it to carry N
# alerts would mean breaking or version-coordinating that consumer. This is
# a genuinely separate, additive surface (own report_id format, own caller
# in triage_api.py's route_get_incident_report -- not reachable through
# POST/GET /alerts/{id}/report). See contracts/reporting.md's own "Incident-
# level report (Phase 5)" section for the seam's documentation.
#
# to_reporting_payload() (evidence_package.py) is NOT used here either --
# it deliberately collapses a package to its primary_alert_id for the
# alert-scoped seam. This reads the package's raw blocks directly so every
# member alert (and the causal graph) survives into the narrative.
# ---------------------------------------------------------------------------

def _event_id_to_alert(alerts: list[dict]) -> dict:
    """event_id -> the alert that lists it in its own event_ids -- the join
    that lets a causal-graph edge (which carries event_id, per ADR-010) be
    attributed to the alert/rule whose evidence produced it."""
    out: dict[str, dict] = {}
    for a in alerts:
        for eid in (a.get("event_ids") or []):
            out[str(eid)] = a
    return out


def _causal_steps(alerts: list[dict], graph: dict | None) -> list[dict]:
    """The narrative's real differentiator: ordered by the causal graph's
    own edge timestamps when a graph exists, falling back to alert-arrival
    order only when it doesn't (an incident promoted before Phase 2/3, or a
    v1-only graph with no typed kinds). Every step states its `kind`
    plainly when known and leaves it unlabeled rather than inventing one --
    a causal claim the graph itself doesn't make must never appear stronger
    in the prose than it is in the data (same discipline as WS-8's own
    "never a transitive join" guarantee)."""
    if graph and graph.get("edges"):
        nodes = {n.get("entity_id"): n for n in (graph.get("nodes") or [])}
        ev2alert = _event_id_to_alert(alerts)
        steps = []
        for e in sorted(graph["edges"], key=lambda x: x.get("ts_ms") or 0):
            alert = ev2alert.get(str(e.get("event_id")))
            frm = nodes.get(e.get("from"), {})
            to = nodes.get(e.get("to"), {})
            steps.append({
                "ts_ms": e.get("ts_ms"),
                "kind": e.get("kind"),
                "from_label": frm.get("label") or frm.get("entity_value") or e.get("from"),
                "to_label": to.get("label") or to.get("entity_value") or e.get("to"),
                "rule_title": alert.get("rule_title") if alert else None,
                "level": alert.get("level") if alert else None,
                "alert_id": alert.get("alert_id") if alert else None,
            })
        return steps
    return [
        {"ts_ms": a.get("time"), "kind": None, "from_label": None, "to_label": None,
         "rule_title": a.get("rule_title"), "level": a.get("level"), "alert_id": a.get("alert_id")}
        for a in sorted(alerts, key=lambda x: x.get("time") or 0)
    ]


_INCIDENT_LABELS = {
    "de": {"timeline": "## Kausaler Ablauf", "timeline_note": (
               "Reihenfolge nach den Zeitstempeln des kausalen Graphen (WS-8); "
               "fällt auf die Reihenfolge des Alarmeingangs zurück, falls kein Graph vorliegt."),
           "evidence_section": "## Beweispaket", "evidence_verified": "Verifiziert",
           "evidence_id": "Paket-ID", "evidence_blocks": "Blöcke",
           "no_kind": "(kein typisierter Kausalzusammenhang)"},
    "en": {"timeline": "## Causal timeline", "timeline_note": (
               "Ordered by the causal graph's (WS-8) own edge timestamps; falls back to "
               "alert-arrival order when no graph exists."),
           "evidence_section": "## Evidence package", "evidence_verified": "Verified",
           "evidence_id": "Package ID", "evidence_blocks": "Blocks",
           "no_kind": "(no typed causal relationship)"},
}


def render_incident_report(pkg: dict, verified: bool, *, lang: str = "de") -> str:
    if lang not in LANGUAGES:
        _warn(f"nis2 render_incident_report lang {lang!r} is not one of {LANGUAGES}; "
              "coercing to 'de' default")
        lang = "de"
    L = _LABELS[lang]
    IL = _INCIDENT_LABELS[lang]
    ph = _ph(lang)

    blocks = pkg.get("blocks") or []
    incident: dict = next((b["content"] for b in blocks if b.get("type") == "incident"), {})
    alerts = [b["content"] for b in blocks if b.get("type") == "alert"]
    graph = next((b["content"] for b in blocks if b.get("type") == "graph"), None)
    steps = _causal_steps(alerts, graph)

    step_lines = []
    for s in steps:
        when = _fmt_time(s["ts_ms"])
        kind = f"`{s['kind']}`" if s["kind"] else IL["no_kind"]
        who = f" ({s['from_label']} → {s['to_label']})" if s.get("from_label") else ""
        rule = s["rule_title"] or ph
        level = s["level"] or "?"
        step_lines.append(f"- **{when}** — {kind}{who}: {rule} ({level})")
    timeline = "\n".join(step_lines) if step_lines else f"- {ph}"

    lines = [
        f"# {L['title']} — Incident",
        "",
        f"_{_DISCLAIMER[lang]}_",
        "",
        _SCOPE_CAVEAT[lang],
        "",
        L["entity_section"],
        f"- {L['entity_name']}: {ph}",
        f"- {L['entity_class']}: {ph}",
        f"- {L['entity_authority']}: {ph}",
        "",
        L["incident_section"],
        f"- {L['incident_title']}: {incident.get('entity_value') or ph} "
        f"({incident.get('entity_type') or ph})",
        f"- {L['detected_at']}: {_fmt_time(incident.get('first_seen'))}",
        f"- {L['severity']}: {incident.get('severity') or 'unknown'}",
        f"- {L['significant']}: {ph}",
        "",
        IL["timeline"],
        IL["timeline_note"],
        "",
        timeline,
        "",
        IL["evidence_section"],
        f"- {IL['evidence_verified']}: {'✓' if verified else '✗'}",
        f"- {IL['evidence_id']}: `{pkg.get('package_id', ph)}`",
        f"- {IL['evidence_blocks']}: {(pkg.get('chain') or {}).get('block_count', 0)}",
    ]
    return "\n".join(lines)


def build_incident_report(pkg: dict, verified: bool, *, lang: str = "de",
                          requested_at: float | None = None) -> dict:
    """The incident-level draft's own envelope -- own report_id format
    (never `{alert_id}:report`, contracts/reporting.md's frozen shape),
    own required fields. `verified` must come from a caller that has
    ALREADY run evidence_package.verify_evidence_package(pkg) -- this
    function renders what it's told, it does not re-verify (same "verify
    before serving, not after" discipline the evidence route itself
    holds, kept in the caller so this stays a pure renderer)."""
    if lang not in LANGUAGES:
        _warn(f"nis2 build_incident_report lang {lang!r} is not one of "
              f"{LANGUAGES}; coercing to 'de' default")
        lang = "de"
    requested_at = time.time() if requested_at is None else requested_at
    incident_id = pkg.get("incident_id")
    return {
        "report_id": f"{incident_id}:incident-report",
        "incident_id": incident_id,
        "format": "markdown",
        "body": render_incident_report(pkg, verified, lang=lang),
        "status": "draft",
        "disclaimer": _DISCLAIMER[lang],
        "generated_at": int(requested_at * 1000),
        "backend": "template-nis2-incident-de",
        "evidence_verified": verified,
        "evidence_package_id": pkg.get("package_id"),
        "language": lang,
        "citations": _citations(),
    }
