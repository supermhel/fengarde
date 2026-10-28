import { useEffect, useState } from "react";
import { currentScenario, resetReplay, replayState, setScenario, startReplay, type ScenarioId } from "./adapter";
import { useConsole } from "../store";

const S = {
  en: {
    chip: "Demo", reset: "Reset", replaying: "Replaying", scenario: "Scenario",
    lab: {
      sub: "recorded lab data", replay: "Replay the attack", again: "Replay again", pick: "SSH brute force + DNS volume (recorded)",
      chipTitle: "Recorded from a local lab run. Timestamps are shifted to now, changes are not saved, and the delay between pipeline stages is approximate.",
    },
    "ai-ot": {
      sub: "synthetic input, real pipeline output", replay: "Replay the AI-to-OT chain", again: "Replay again", pick: "AI agent to OT (synthetic input, real pipeline)",
      chipTitle: "Synthetic AI-to-OT chain (the evaluation twin's raw records, seed 7). Every alert, incident, graph, evidence package and report was produced by the real WS-2/4/5/8/9/3 code run in-process, not recorded from a live stack. The 60 s between steps is replayed 12x faster, evidence blocks keep the original times. The AI verdicts come from the stub backend (no model). Timestamps are shifted to now, changes are not saved, and the delay between pipeline stages is approximate.",
    },
  },
  de: {
    chip: "Demo", reset: "Zurücksetzen", replaying: "Spielt ab", scenario: "Szenario",
    lab: {
      sub: "aufgezeichnete Labordaten", replay: "Angriff abspielen", again: "Erneut abspielen", pick: "SSH-Brute-Force + DNS-Volumen (aufgezeichnet)",
      chipTitle: "Aufzeichnung eines lokalen Laborlaufs. Zeitstempel sind auf jetzt verschoben, Änderungen werden nicht gespeichert, die Verzögerung zwischen den Stufen ist angenähert.",
    },
    "ai-ot": {
      sub: "synthetische Eingabe, echte Pipeline-Ausgabe", replay: "KI-zu-OT-Kette abspielen", again: "Erneut abspielen", pick: "KI-Agent zu OT (synthetische Eingabe, echte Pipeline)",
      chipTitle: "Synthetische KI-zu-OT-Kette (Rohdaten des Evaluations-Twins, Seed 7). Jeder Alarm, Vorfall, Graph, jedes Beweispaket und jeder Bericht wurde vom echten Code von WS-2/4/5/8/9/3 im selben Prozess erzeugt, nicht an einem Live-Stack aufgezeichnet. Die 60 s zwischen den Schritten laufen 12-fach schneller, die Beweisblöcke behalten die Originalzeiten. Die KI-Urteile stammen vom Stub-Backend (kein Modell). Zeitstempel sind auf jetzt verschoben, Änderungen werden nicht gespeichert, die Verzögerung zwischen den Stufen ist angenähert.",
    },
  },
};

/* Sits in the top bar of the demo build only. The page that embeds the demo can also start the replay
   (postMessage, same origin), and the adapter reports alarms back to it. */
export default function DemoBar() {
  const { lang } = useConsole();
  const [st, setSt] = useState(replayState());
  const [sc, setSc] = useState<ScenarioId>(currentScenario());
  useEffect(() => { const id = setInterval(() => { setSt(replayState()); setSc(currentScenario()); }, 400); return () => clearInterval(id); }, []);
  const s = S[lang];
  const t = s[sc];
  const mmss = (ms: number) => `${Math.floor(ms / 60000)}:${String(Math.floor(ms / 1000) % 60).padStart(2, "0")}`;
  const pick = (id: ScenarioId) => { setScenario(id); setSc(id); setSt(replayState()); };
  return (
    <span className="demo-bar">
      <span className="chip demo" title={t.chipTitle}><b>{s.chip}</b> · {t.sub}</span>
      <select aria-label={s.scenario} value={sc} onChange={(e) => pick(e.target.value as ScenarioId)}>
        <option value="lab">{s.lab.pick}</option>
        <option value="ai-ot">{s["ai-ot"].pick}</option>
      </select>
      <button className="btn primary" disabled={st.phase === "replaying"} onClick={() => startReplay()}>
        {st.phase === "replaying" ? `${s.replaying} ${mmss(st.elapsedMs)}` : st.phase === "done" ? t.again : t.replay}
      </button>
      {st.phase !== "idle" && <button className="btn" onClick={() => resetReplay()}>{s.reset}</button>}
    </span>
  );
}
