import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type CompareResult, type ScanRow } from "../api/client";

/**
 * Compare two audits of the same target: what appeared, what was fixed.
 * This is the "did the correction work?" answer in product form.
 */
export default function Compare(): JSX.Element {
  const [scans, setScans] = useState<ScanRow[]>([]);
  const [base, setBase] = useState("");
  const [head, setHead] = useState("");
  const [result, setResult] = useState<CompareResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api
      .listScans()
      .then((rows) => setScans(rows.filter((r) => !r.running)))
      .catch((err: Error) => setError(err.message));
  }, []);

  async function run(): Promise<void> {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await api.compare(base, head));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ maxWidth: 760 }}>
      <h1>Compare audits</h1>
      <p className="page-sub">
        Pick an older (base) and a newer (head) audit to track correction progress.
      </p>

      <div className="card">
        <label htmlFor="base">Base (older)</label>
        <select id="base" value={base} onChange={(e) => setBase(e.target.value)}>
          <option value="">—</option>
          {scans.map((row) => (
            <option key={row.id} value={row.id}>
              {row.target} · {new Date(row.started_at).toLocaleString()} ·{" "}
              {row.findings_total} findings
            </option>
          ))}
        </select>

        <label htmlFor="head">Head (newer)</label>
        <select id="head" value={head} onChange={(e) => setHead(e.target.value)}>
          <option value="">—</option>
          {scans.map((row) => (
            <option key={row.id} value={row.id}>
              {row.target} · {new Date(row.started_at).toLocaleString()} ·{" "}
              {row.findings_total} findings
            </option>
          ))}
        </select>

        {error && <p className="error-text">{error}</p>}

        <div style={{ marginTop: 18 }}>
          <button disabled={!base || !head || base === head || busy} onClick={() => void run()}>
            {busy ? "Comparing…" : "Compare"}
          </button>
        </div>
      </div>

      {result && (
        <div className="card" style={{ marginTop: 16 }}>
          <div className="stat-grid">
            <div className="stat">
              <div className="num" style={{ color: "var(--critical)" }}>
                {result.new.length}
              </div>
              <div className="label">new</div>
            </div>
            <div className="stat">
              <div className="num" style={{ color: "var(--low)" }}>
                {result.resolved.length}
              </div>
              <div className="label">resolved</div>
            </div>
            <div className="stat">
              <div className="num">{result.unchanged.length}</div>
              <div className="label">unchanged</div>
            </div>
          </div>
          <p className="muted">
            Open the head audit to act on what remains:{" "}
            <Link to={`/scans/${result.head}`}>view head audit</Link>
          </p>
        </div>
      )}
    </div>
  );
}
