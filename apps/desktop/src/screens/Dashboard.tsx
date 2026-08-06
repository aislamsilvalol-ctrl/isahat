import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, type ScanRow, type Severity } from "../api/client";
import { useI18n } from "../i18n";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

interface CheckpointRow {
  scan_id: string;
  target: string;
  stage: string;
  saved_at: string;
  running: boolean;
}

export function SeverityBadge({ value }: { value: Severity }): JSX.Element {
  return <span className={`badge ${value}`}>{value}</span>;
}

function InterruptedAudits({
  checkpoints,
  onResume,
}: {
  checkpoints: CheckpointRow[];
  onResume: (scanId: string) => void;
}): JSX.Element {
  const { t } = useI18n();
  const [busyId, setBusyId] = useState<string | null>(null);

  if (checkpoints.length === 0) return <></>;

  return (
    <div className="card" style={{ marginBottom: 18 }}>
      <h3 style={{ margin: "0 0 4px", fontSize: 14, fontWeight: 650 }}>
        {t.dashboard.resumeTitle}
      </h3>
      <p className="muted" style={{ margin: "0 0 12px", fontSize: 12.5 }}>
        {t.dashboard.resumeSubtitle}
      </p>
      {checkpoints.map((cp) => (
        <div key={cp.scan_id} className="row-between checkpoint-row">
          <div>
            <span className="mono">{cp.target}</span>{" "}
            <span className="muted">
              · {t.dashboard.resumeStage} <span className="mono">{cp.stage}</span> ·{" "}
              {t.dashboard.resumeSaved}{" "}
              {cp.saved_at ? new Date(cp.saved_at).toLocaleString() : ""}
            </span>
          </div>
          {cp.running ? (
            <Link className="button secondary" to={`/scans/${cp.scan_id}`}>
              <span className="spinner" /> {t.dashboard.running}
            </Link>
          ) : (
            <button
              disabled={busyId === cp.scan_id}
              onClick={() => {
                setBusyId(cp.scan_id);
                onResume(cp.scan_id);
              }}
            >
              {busyId === cp.scan_id ? t.dashboard.resuming : `▶ ${t.dashboard.resume}`}
            </button>
          )}
        </div>
      ))}
    </div>
  );
}

export default function Dashboard(): JSX.Element {
  const { t } = useI18n();
  const navigate = useNavigate();
  const [scans, setScans] = useState<ScanRow[] | null>(null);
  const [checkpoints, setCheckpoints] = useState<CheckpointRow[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const load = (): void => {
      api
        .listScans()
        .then((rows) => alive && setScans(rows))
        .catch((err: Error) => alive && setError(err.message));
      api
        .listCheckpoints()
        .then((rows) => alive && setCheckpoints(rows))
        .catch(() => undefined); // checkpoints are best-effort
    };
    load();
    const timer = setInterval(load, 5000); // live-ish: running scans update
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, []);

  async function onResume(scanId: string): Promise<void> {
    try {
      await api.resumeScan(scanId);
      navigate(`/scans/${scanId}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  const totals = (scans ?? []).reduce(
    (acc, row) => {
      for (const sev of SEVERITIES) acc[sev] += row.by_severity[sev] ?? 0;
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>,
  );

  return (
    <div>
      <div className="row-between">
        <div>
          <h1>{t.dashboard.title}</h1>
          <p className="page-sub">{t.dashboard.subtitle}</p>
        </div>
        <Link className="button" to="/new">
          ＋ {t.dashboard.newAudit}
        </Link>
      </div>

      <div className="stat-grid">
        {SEVERITIES.map((sev) => (
          <div
            className="stat"
            key={sev}
            style={{ ["--stat-color" as string]: `var(--${sev})` }}
          >
            <div className="num" style={{ color: `var(--${sev})` }}>
              {totals[sev]}
            </div>
            <div className="label">{sev}</div>
          </div>
        ))}
      </div>

      {error && <p className="error-text">{error}</p>}

      <InterruptedAudits checkpoints={checkpoints} onResume={onResume} />

      {scans === null && !error && (
        <p className="muted">
          <span className="spinner" /> {t.dashboard.loading}
        </p>
      )}

      {scans !== null && scans.length === 0 && (
        <div className="card empty-state">
          <div className="empty-icon">⛨</div>
          <h3>{t.dashboard.emptyTitle}</h3>
          <p className="muted" style={{ maxWidth: 420, margin: "0 auto 18px" }}>
            {t.dashboard.emptyBody}
          </p>
          <Link className="button" to="/new">
            {t.dashboard.emptyCta}
          </Link>
        </div>
      )}

      {scans !== null && scans.length > 0 && (
        <div className="card" style={{ padding: "8px 20px" }}>
          <table>
            <thead>
              <tr>
                <th>{t.dashboard.colTarget}</th>
                <th>{t.dashboard.colStarted}</th>
                <th>{t.dashboard.colFindings}</th>
                <th>{t.dashboard.colSeverities}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {scans.map((row) => (
                <tr key={row.id}>
                  <td className="mono">{row.target}</td>
                  <td className="muted">
                    {new Date(row.started_at).toLocaleString()}
                    {row.running && (
                      <span>
                        {" "}
                        <span className="spinner" /> {t.dashboard.running}
                      </span>
                    )}
                  </td>
                  <td style={{ fontWeight: 600 }}>{row.findings_total}</td>
                  <td>
                    {SEVERITIES.filter((s) => (row.by_severity[s] ?? 0) > 0).map(
                      (s) => (
                        <span key={s} style={{ marginRight: 8 }}>
                          <SeverityBadge value={s} />{" "}
                          <span className="muted">{row.by_severity[s]}</span>
                        </span>
                      ),
                    )}
                  </td>
                  <td style={{ textAlign: "right" }}>
                    <Link to={`/scans/${row.id}`}>{t.dashboard.open} →</Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
