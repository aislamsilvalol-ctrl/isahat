import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { api, type AuthConfig } from "../api/client";
import { useI18n } from "../i18n";

/**
 * Start-audit form. The authorisation checklist is not cosmetic: the bridge
 * rejects any scan whose payload does not carry confirmed=true, and the UI
 * only sends it after the user ticks every item.
 */
export default function NewScan(): JSX.Element {
  const { t } = useI18n();
  const navigate = useNavigate();
  const [target, setTarget] = useState("");
  const [profile, setProfile] = useState("safe");
  const [scanType, setScanType] = useState("web");
  const [authJson, setAuthJson] = useState("");
  const [rateLimitCheck, setRateLimitCheck] = useState(false);
  const [checks, setChecks] = useState({ own: false, scope: false, safe: false });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const allChecked = checks.own && checks.scope && checks.safe;

  async function onSubmit(event: FormEvent): Promise<void> {
    event.preventDefault();
    setError(null);

    let auth: AuthConfig | undefined;
    if (authJson.trim()) {
      try {
        auth = JSON.parse(authJson) as AuthConfig;
      } catch {
        setError(t.newScan.authInvalid);
        return;
      }
    }

    setBusy(true);
    try {
      const accepted = await api.startScan({
        target: target.trim(),
        profile,
        scan_type: scanType,
        auth,
        rate_limit_check: rateLimitCheck,
        confirmed: true, // allChecked is enforced before submit is possible
      });
      navigate(`/scans/${accepted.scan_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setBusy(false);
    }
  }

  return (
    <div style={{ maxWidth: 580 }}>
      <h1>{t.newScan.title}</h1>
      <p className="page-sub">{t.newScan.subtitle}</p>

      <form onSubmit={onSubmit} className="card">
        <label htmlFor="target">{t.newScan.target}</label>
        <input
          id="target"
          placeholder={t.newScan.targetPlaceholder}
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          required
          type="url"
        />

        <label htmlFor="profile">{t.newScan.profile}</label>
        <select id="profile" value={profile} onChange={(e) => setProfile(e.target.value)}>
          <option value="safe">{t.newScan.profileSafe}</option>
          <option value="standard">{t.newScan.profileStandard}</option>
        </select>

        <label htmlFor="scanType">{t.newScan.scanType}</label>
        <select id="scanType" value={scanType} onChange={(e) => setScanType(e.target.value)}>
          <option value="web">{t.newScan.typeWeb}</option>
          <option value="api">{t.newScan.typeApi}</option>
        </select>

        <label htmlFor="auth">{t.newScan.auth}</label>
        <textarea
          id="auth"
          rows={3}
          placeholder={t.newScan.authPlaceholder}
          value={authJson}
          onChange={(e) => setAuthJson(e.target.value)}
        />

        <label
          className="row-between"
          style={{ marginTop: 18, cursor: "pointer" }}
          htmlFor="rl"
        >
          <span>
            {t.newScan.rateLimit}{" "}
            <span className="muted">({t.newScan.rateLimitHint})</span>
          </span>
          <input
            id="rl"
            type="checkbox"
            checked={rateLimitCheck}
            onChange={(e) => setRateLimitCheck(e.target.checked)}
          />
        </label>

        <div className="auth-banner">
          <strong>{t.newScan.authzTitle}</strong> {t.newScan.authzBody}
          <label>
            <input
              type="checkbox"
              checked={checks.own}
              onChange={(e) => setChecks({ ...checks, own: e.target.checked })}
            />
            {t.newScan.checkOwn}
          </label>
          <label>
            <input
              type="checkbox"
              checked={checks.scope}
              onChange={(e) => setChecks({ ...checks, scope: e.target.checked })}
            />
            {t.newScan.checkScope}
          </label>
          <label>
            <input
              type="checkbox"
              checked={checks.safe}
              onChange={(e) => setChecks({ ...checks, safe: e.target.checked })}
            />
            {t.newScan.checkSafe}
          </label>
        </div>

        {error && <p className="error-text">{error}</p>}

        <div style={{ marginTop: 22 }}>
          <button type="submit" disabled={!allChecked || busy || !target.trim()}>
            {busy ? t.newScan.submitting : t.newScan.submit}
          </button>
        </div>
      </form>
    </div>
  );
}
