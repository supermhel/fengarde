import { useEffect, useState } from "react";
import { resetReplay, replayState, startReplay } from "./adapter";
import { useConsole } from "../store";

const S = {
  en: {
    chip: "Demo", chipTitle: "Recorded from a local lab run. Timestamps are shifted to now, changes are not saved, and the delay between pipeline stages is approximate.",
    sub: "recorded lab data", replay: "Replay the attack", replaying: "Replaying", again: "Replay again", reset: "Reset",
  },
  de: {
    chip: "Demo", chipTitle: "Aufzeichnung eines lokalen Laborlaufs. Zeitstempel sind auf jetzt verschoben, Änderungen werden nicht gespeichert, die Verzögerung zwischen den Stufen ist angenähert.",
    sub: "aufgezeichnete Labordaten", replay: "Angriff abspielen", replaying: "Spielt ab", again: "Erneut abspielen", reset: "Zurücksetzen",
  },
};

/* Sits in the top bar of the demo build only. The page that embeds the demo can also start the replay
   (postMessage, same origin), and the adapter reports alarms back to it. */
export default function DemoBar() {
  const { lang } = useConsole();
  const s = S[lang];
  const [st, setSt] = useState(replayState());
  useEffect(() => { const id = setInterval(() => setSt(replayState()), 400); return () => clearInterval(id); }, []);
  const mmss = (ms: number) => `${Math.floor(ms / 60000)}:${String(Math.floor(ms / 1000) % 60).padStart(2, "0")}`;
  return (
    <span className="demo-bar">
      <span className="chip demo" title={s.chipTitle}><b>{s.chip}</b> · {s.sub}</span>
      <button className="btn primary" disabled={st.phase === "replaying"} onClick={() => startReplay()}>
        {st.phase === "replaying" ? `${s.replaying} ${mmss(st.elapsedMs)}` : st.phase === "done" ? s.again : s.replay}
      </button>
      {st.phase !== "idle" && <button className="btn" onClick={() => resetReplay()}>{s.reset}</button>}
    </span>
  );
}
