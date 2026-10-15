import { useState } from "react";
import { api, mitreTags, type Rule } from "../data/api";
import { Panel, Sev } from "../hmi/hmi";
import { useConsole } from "../store";
import { S } from "./settings.i18n";

/* MITRE coverage: one cell per tagged rule, grouped by tactic, heat = alerts fired by that rule
   in the selected range. Rules with no honest single-technique mapping are listed, not dropped
   (contracts/detection-coverage.md). */
export function Coverage() {
  const { t, lang, data, session, rbac, refresh } = useConsole();
  const s = S[lang];
  const isAdmin = rbac && session?.role === "admin";
  const [err, setErr] = useState("");
  const toggle = async (r: Rule) => {
    const res = await api.setRuleEnabled(r.id, r.enabled === false);
    setErr(res.ok ? "" : res.reason);
    if (res.ok) refresh();
  };
  const res = data.rules;
  const rules = res?.ok ? res.data.rules : [];
  const alerts = data.alerts?.ok ? data.alerts.data : [];
  const fired = new Map<string, number>();
  for (const a of alerts) if (a.rule_id) fired.set(a.rule_id, (fired.get(a.rule_id) || 0) + 1);
  const max = Math.max(1, ...fired.values());

  const byTactic = new Map<string, Rule[]>();
  const untagged: Rule[] = [];
  for (const r of rules) {
    const { tactics } = mitreTags(r.mitre);
    if (!tactics.length) { untagged.push(r); continue; }
    for (const tac of tactics) byTactic.set(tac, [...(byTactic.get(tac) || []), r]);
  }
  const tactics = [...byTactic.keys()].sort();
  const heat = (n: number) => (n === 0 ? "" : n / max > 0.66 ? " h3" : n / max > 0.33 ? " h2" : " h1");
  const firing = rules.filter((r) => fired.get(r.id)).length;

  return (
    <>
      <h1 className="view-title">{t.coverage}<small>{firing} / {rules.length} {t.rulesFired}</small></h1>
      {res && !res.ok ? <p className="empty"><b>{t.unreachable}.</b> {res.reason}</p> : rules.length === 0 ? <p className="empty">{t.noRules}</p> : (
        <div className="grid">
          <Panel title={t.coverageMap} aside={`${tactics.length} ${t.tactics_.toLowerCase()}`}>
            <div className="grid" style={{ gap: 12 }}>
              {tactics.map((tac) => (
                <div key={tac}>
                  <div className="note" style={{ margin: "0 0 5px", fontWeight: 600, color: "var(--ink-2)" }}>{tac} · {byTactic.get(tac)!.length}</div>
                  <div className="strip">
                    {byTactic.get(tac)!.map((r) => {
                      const n = fired.get(r.id) || 0;
                      return (
                        <div key={r.id} className={`tac${heat(n)}`} title={r.title}>
                          <b>{mitreTags(r.mitre).techniques[0] || r.id}</b>
                          <span className="muted">{n} {t.fired} · {r.title.length > 34 ? r.title.slice(0, 33) + "…" : r.title}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
            {untagged.length > 0 && (
              <p className="note" style={{ marginTop: 14 }}><b>{t.untagged} ({untagged.length}):</b> {untagged.map((r) => r.title).join(" · ")}</p>
            )}
          </Panel>
          <Panel title={t.allRules} aside={`${rules.length} ${t.rules}`}>
            {isAdmin && <p className="note">{s.ruleSwitchHint}</p>}
            {err && <p className="err" role="alert">{err}</p>}
            <div className="table-wrap">
              <table className="data">
                <thead><tr><th>{t.rule}</th><th>{t.sector}</th><th>{t.level}</th><th className="num">{t.weight}</th><th>{t.stateful}</th><th>{t.enabled}</th><th className="num">{t.fired}</th>{isAdmin && <th>{s.ruleSwitch}</th>}</tr></thead>
                <tbody>
                  {[...rules].sort((a, b) => (fired.get(b.id) || 0) - (fired.get(a.id) || 0) || a.title.localeCompare(b.title)).map((r) => (
                    <tr key={r.id}>
                      <td>{r.title}<div className="note mono" style={{ margin: 0 }}>{r.id}</div></td>
                      <td>{r.sector || "—"}</td>
                      <td><Sev level={r.level} /></td>
                      <td className="num">{r.score_weight ?? "—"}</td>
                      <td>{r.stateful ? t.yes : t.no}</td>
                      <td><span className={`pill ${r.enabled === false ? "off" : "ok"}`}>{r.enabled === false ? t.no : t.yes}</span>{r.opt_in ? <span className="tag" style={{ marginLeft: 6 }}>{t.optIn}</span> : null}</td>
                      <td className="num">{fired.get(r.id) || 0}</td>
                      {isAdmin && <td><button className="btn" onClick={() => toggle(r)}>{r.enabled === false ? s.on : s.off}</button></td>}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
        </div>
      )}
    </>
  );
}
