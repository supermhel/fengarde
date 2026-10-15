import { useEffect, useState, type FormEvent } from "react";
import { api, type Session } from "../data/api";
import { AlarmShape, Icon, Panel, Shield } from "../hmi/hmi";
import { dicts, initialLang, type Lang } from "../lib/i18n";
import { L } from "./login.i18n";

const store = (k: string, v: string) => { try { localStorage.setItem(k, v); } catch { /* storage blocked */ } };

/* Plain http is fine on the machine itself; anywhere else a password would cross the network in clear text. */
const isLocal = (h: string) => h === "localhost" || h === "127.0.0.1" || h === "[::1]" || h.endsWith(".localhost");

/* The door is the console in its idle state: same rail, top bar and banner as the app, so signing in changes
   the content and not the world. Everything shown is a fact about this install or this connection. */
export function Login({ onIn, error, down }: { onIn: (s: Session) => void; error?: string; down?: boolean }) {
  const [lang, setLangState] = useState<Lang>(initialLang);
  const [theme, setTheme] = useState<string>(() => { try { return localStorage.getItem("fg.theme") || "light"; } catch { return "light"; } });
  const [err, setErr] = useState<{ kind: "bad" | "many" | "down" | "other"; text?: string } | null>(error ? { kind: "other", text: error } : null);
  const [busy, setBusy] = useState(false);
  const [reveal, setReveal] = useState(false);
  const t = dicts[lang];
  const l = L[lang];
  const insecure = location.protocol === "http:" && !isLocal(location.hostname);

  useEffect(() => { document.documentElement.dataset.theme = theme; store("fg.theme", theme); }, [theme]);
  useEffect(() => { document.documentElement.lang = lang; }, [lang]);
  const setLang = (x: Lang) => { setLangState(x); store("fg.lang", x); };

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    setBusy(true); setErr(null);
    const r = await api.login(String(f.get("username") || ""), String(f.get("password") || ""), String(f.get("code") || "").replace(/\s+/g, ""));
    setBusy(false);
    if (r.ok) onIn(r.data);
    else setErr(r.status === 429 ? { kind: "many" } : r.status === 0 || r.status >= 500 ? { kind: "down" } : r.status === 401 ? { kind: "bad" } : { kind: "other", text: r.reason });
  }

  const notes: { key: string; label: string; text: string }[] = [];
  if (down) notes.push({ key: "down", label: l.downBanner, text: l.downText });
  if (insecure) notes.push({ key: "tls", label: l.insecure, text: l.insecureText });

  return (
    <div className="shell">
      <span className="brand"><Shield /> FENGARDE</span>
      <header className="top">
        <span className={`chip ${down ? "down" : "ok"}`}><span className="dot" />{down ? l.down : l.reachable}</span>
        <span className="spacer" />
        <span className="seg" role="group" aria-label={l.lang}>
          <button type="button" aria-pressed={lang === "de"} onClick={() => setLang("de")}>DE</button>
          <button type="button" aria-pressed={lang === "en"} onClick={() => setLang("en")}>EN</button>
        </span>
        <button type="button" className="ctl icon-btn" onClick={() => setTheme((x) => (x === "light" ? "dark" : "light"))} aria-label={l.theme} aria-pressed={theme === "dark"}>
          <Icon name={theme === "dark" ? "moon" : "sun"} size={16} />
        </button>
      </header>

      <div className={`banner ${notes.length ? "active" : "quiet"}`} role="status">
        {notes.length === 0 ? (
          <>
            <span className="label">{l.required}</span>
            <span className="items"><span className="muted">{l.required2}</span></span>
          </>
        ) : notes.map((n) => (
          <span key={n.key} className="label" style={{ textTransform: "none", letterSpacing: 0, font: "inherit", gap: 10 }}>
            <AlarmShape level="high" /><b>{n.label}.</b> {n.text}
          </span>
        ))}
      </div>

      <nav className="nav" aria-label="Views">
        <span className="group">{l.access}</span>
        <a href="./" aria-current="page"><Icon name="account" />{t.signIn}</a>
      </nav>

      <main>
        <h1 className="view-title">{t.signIn}<small>{l.signingInTo} <span className="mono">{location.host}</span></small></h1>
        <div className="login-grid">
          <Panel title={l.account} aside={<span className={`pill ${insecure ? "warn" : "ok"}`}>{insecure ? l.plain : location.protocol === "https:" ? l.tls : l.localConn}</span>}>
            <form className="signin" onSubmit={submit} aria-label={t.signIn}>
              <label htmlFor="u">{t.username}</label>
              <input id="u" name="username" autoComplete="username" required autoFocus spellCheck={false} autoCapitalize="none" />
              <label htmlFor="p">{t.password}</label>
              <div className="pw">
                <input id="p" name="password" type={reveal ? "text" : "password"} autoComplete="current-password" required />
                <button type="button" className="pw-toggle" onClick={() => setReveal((x) => !x)} aria-label={reveal ? l.hide : l.show} aria-pressed={reveal}>
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
                    <path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z" /><circle cx="12" cy="12" r="3" />
                    {reveal && <path d="M4 4l16 16" />}
                  </svg>
                </button>
              </div>
              <label htmlFor="c">{l.code}</label>
              <input id="c" name="code" className="mono" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9 ]*" maxLength={10} aria-describedby="c-hint" />
              <p id="c-hint" className="hint">{l.codeHint}</p>
              <p className="err" role="alert">{err && (err.kind === "many" ? t.tooMany : err.kind === "down" ? `${t.unreachable}.` : err.kind === "bad" ? l.bad : err.text || t.signInFailed)}</p>
              <button className="btn primary" disabled={busy}>{busy ? "…" : t.signIn}</button>
              <p className="hint" style={{ marginTop: 14 }}>{l.guard}</p>
            </form>
          </Panel>

          <Panel title={l.roles}>
            <dl className="roles">
              {l.roleRows.map(([role, text]) => (
                <div key={role}><dt className="mono">{role}</dt><dd>{text}</dd></div>
              ))}
            </dl>
          </Panel>
        </div>
      </main>
    </div>
  );
}
