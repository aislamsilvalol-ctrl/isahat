import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { api, type AuthConfig } from "../api/client";

/**
 * Start-audit form. The authorisation checklist is not cosmetic: the bridge
 * rejects any scan whose payload does not carry confirmed=true, and the UI
 * only sends it after the user ticks every item.
 */
export default function NewScan(): JSX.Element {
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
        setError("Auth JSON is invalid — expected an object with headers/cookies.");
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
    <div style={{ maxWidth: 560 }}>
      <h1>New audit</h1>
      <p className="page-sub">Same engine as the CLI — no GUI-only behaviour.</p>

      <form onSubmit={onSubmit} className="card">
        <label htmlFor="target">Target URL</label>
        <input
          id="target"
          placeholder="https://staging.example.com"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          required
          type="url"
        />

        <label htmlFor="profile">Profile</label>
        <select id="profile" value={profile} onChange={(e) => setProfile(e.target.value)}>
          <option value="safe">safe — non-destructive checks only</option>
          <option value="standard">standard — safe + controlled active checks</option>
        </select>

        <label htmlFor="scanType">Target type</label>
        <select id="scanType" value={scanType} onChange={(e) => setScanType(e.target.value)}>
          <option value="web">web application</option>
          <option value="api">API</option>
        </select>

        <label htmlFor="auth">Auth (optional JSON — headers/cookies, never persisted)</label>
        <textarea
          id="auth"
          rows={3}
          placeholder='{"headers": {"Authorization": "Bearer …"}}'
          value={authJson}
          onChange={(e) => setAuthJson(e.target.value)}
        />

        <label className="row-between" style={{ marginTop: 16 }}>
          <span>
            Controlled rate-limit probe{" "}
            <span className="muted">(small request burst, auto-stops on 429)</span>
          </span>
          <input
            type="checkbox"
            style={{ width: "auto" }}
            checked={rateLimitCheck}
            onChange={(e) => setRateLimitCheck(e.target.checked)}
          />
        </label>

        <div className="auth-banner">
          <strong>Authorisation required.</strong> IsaHat may only be used against
          systems you own or are explicitly authorised to test. Confirm:
          <label style={{ marginTop: 10 }}>
            <input
              type="checkbox"
              style={{ width: "auto", marginRight: 8 }}
              checked={checks.own}
              onChange={(e) => setChecks({ ...checks, own: e.target.checked })}
            />
            I own this system or hold written authorisation to test it.
          </label>
          <label>
            <input
              type="checkbox"
              style={{ width: "auto", marginRight: 8 }}
              checked={checks.scope}
              onChange={(e) => setChecks({ ...checks, scope: e.target.checked })}
            />
            The target and all hosts it links to are inside my authorised scope.
          </label>
          <label>
            <input
              type="checkbox"
              style={{ width: "auto", marginRight: 8 }}
              checked={checks.safe}
              onChange={(e) => setChecks({ ...checks, safe: e.target.checked })}
            />
            I understand IsaHat runs non-destructive checks only and will not
            alter data.
          </label>
        </div>

        {error && <p className="error-text">{error}</p>}

        <div style={{ marginTop: 20 }}>
          <button type="submit" disabled={!allChecked || busy || !target.trim()}>
            {busy ? "Starting…" : "Start audit"}
          </button>
        </div>
      </form>
    </div>
  );
}
