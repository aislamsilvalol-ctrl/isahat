import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type ScanRow, type Severity } from "../api/client";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export function SeverityBadge({ value }: { value: Severity }): JSX.Element {
  return <span className={`badge ${value}`}>{value}</span>;
}

export default function Dashboard(): JSX.Element {
  const [scans, setScans] = useState<ScanRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const load = (): void => {
      api
        .listScans()
        .then((rows) => alive && setScans(rows))
        .catch((err: Error) => alive && setError(err.message));
    };
    load();
    const timer = setInterval(load, 5000); // live-ish: running scans update
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, []);

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
          <h1>Security posture</h1>
          <p className="page-sub">Every audit of every authorised target.</p>
        </div>
        <Link className="button" to="/new">
          New audit
        </Link>
      </div>

      <div className="stat-grid">
        {SEVERITIES.map((sev) => (
          <div className="stat" key={sev}>
            <div className="num" style={{ color: `var(--${sev})` }}>
              {totals[sev]}
            </div>
            <div className="label">{sev}</div>
          </div>
        ))}
      </div>

      {error && <p className="error-text">{error}</p>}
      {scans === null && !error && (
        <p className="muted">
          <span className="spinner" /> Loading history…
        </p>
      )}

      {scans !== null && scans.length === 0 && (
        <div className="card">
          <p className="muted">
            No audits yet. Start one — remember, only targets you own or are
            explicitly authorised to test.
          </p>
        </div>
      )}

      {scans !== null && scans.length > 0 && (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>Target</th>
                <th>Started</th>
                <th>Findings</th>
                <th>Severities</th>
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
                        <span className="spinner" /> running
                      </span>
                    )}
                  </td>
                  <td>{row.findings_total}</td>
                  <td>
                    {SEVERITIES.filter((s) => (row.by_severity[s] ?? 0) > 0).map(
                      (s) => (
                        <span key={s} style={{ marginRight: 6 }}>
                          <SeverityBadge value={s} /> {row.by_severity[s]}
                        </span>
                      ),
                    )}
                  </td>
                  <td>
                    <Link to={`/scans/${row.id}`}>Open</Link>
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
