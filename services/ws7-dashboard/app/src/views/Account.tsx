import { useState, type FormEvent } from "react";
import { api } from "../data/api";
import { useConsole } from "../store";

/* Opt-in TOTP enrolment (POST /auth/mfa/enable + /verify, password re-auth on both). The secret
   is shown as text for manual entry: that is all a QR code encodes, and it needs no library. */
export function Account() {
  const { t, session, rbac } = useConsole();
  const [password, setPassword] = useState("");
  const [secret, setSecret] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [err, setErr] = useState("");
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);

  if (!rbac || !session) return (<><h1 className="view-title">{t.account}</h1><section className="panel"><p className="empty">{t.rbacOff}</p></section></>);

  async function enable(e: FormEvent) {
    e.preventDefault(); setBusy(true); setErr("");
    const r = await api.mfaEnable(password);
    setBusy(false);
    if (!r.ok) return setErr(r.status === 429 ? t.tooMany : r.reason);
    setSecret(new URL(r.data.otpauth_uri).searchParams.get("secret") || r.data.otpauth_uri);
  }
  async function verify(e: FormEvent) {
    e.preventDefault(); setBusy(true); setErr("");
    const r = await api.mfaVerify(password, code.trim());
    setBusy(false);
    if (!r.ok) return setErr(r.status === 429 ? t.tooMany : r.reason);
    setDone(true); setPassword(""); setSecret(null);
  }

  return (
    <>
      <h1 className="view-title">{t.account}</h1>
      <div className="grid g2" style={{ alignItems: "start" }}>
        <section className="panel">
          <h2>{t.signedInAs}</h2>
          <dl className="kv">
            <dt>{t.username}</dt><dd><b>{session.username}</b></dd>
            <dt>{t.role}</dt><dd>{session.role}</dd>
            <dt>{t.tenant}</dt><dd>{session.tenant_id || "default"}</dd>
          </dl>
        </section>
        <section className="panel">
          <h2>{t.mfa}</h2>
          {done ? <p className="ok-text" role="status">{t.mfaOn}</p> : secret === null ? (
            <form onSubmit={enable}>
              <p className="hint">{t.mfaIntro}</p>
              <input className="ctl" style={{ width: "100%", padding: 9 }} type="password" autoComplete="current-password" aria-label={t.password} placeholder={t.password} value={password} onChange={(e) => setPassword(e.target.value)} required />
              <div className="actions"><button className="btn primary" disabled={busy}>{t.mfaGenerate}</button></div>
            </form>
          ) : (
            <form onSubmit={verify}>
              <p className="hint">{t.mfaAdd}</p>
              <dl className="kv"><dt>{t.secret}</dt><dd className="mono" style={{ wordBreak: "break-all" }}>{secret}</dd></dl>
              <input className="ctl" style={{ width: "100%", padding: 9 }} inputMode="numeric" autoComplete="one-time-code" aria-label={t.mfaCode} placeholder={t.mfaCode} value={code} onChange={(e) => setCode(e.target.value)} required />
              <div className="actions"><button className="btn primary" disabled={busy}>{t.mfaVerify}</button></div>
            </form>
          )}
          <p className="err" role="alert">{err}</p>
        </section>
      </div>
    </>
  );
}
