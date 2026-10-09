import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type CompareResult, type ScanRow } from "../api/client";
import { useI18n } from "../i18n";

/**
 * Compare two audits of the same target: what appeared, what was fixed.
 * This is the "did the correction work?" answer in product form.
 */
export default function Compare(): JSX.Element {
  const { t } = useI18n();
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

  const rowLabel = (row: ScanRow): string =>
    `${row.target} · ${new Date(row.started_at).toLocaleString()} · ${row.findings_total}`;

  return (
    <div style={{ maxWidth: 720 }}>
      <h1>{t.compare.title}</h1>
      <p className="page-sub">{t.compare.subtitle}</p>

      <div className="card">
        <label htmlFor="base">{t.compare.base}</label>
        <select id="base" value={base} onChange={(e) => setBase(e.target.value)}>
          <option value="">{t.compare.select}</option>
          {scans.map((row) => (
            <option key={row.id} value={row.id}>
              {rowLabel(row)}
            </option>
          ))}
        </select>

        <label htmlFor="head">{t.compare.head}</label>
        <select id="head" value={head} onChange={(e) => setHead(e.target.value)}>
          <option value="">{t.compare.select}</option>
          {scans.map((row) => (
            <option key={row.id} value={row.id}>
              {rowLabel(row)}
            </option>
          ))}
        </select>

        {error && <p className="error-text">{error}</p>}

        <div style={{ marginTop: 20 }}>
          <button
            disabled={!base || !head || base === head || busy}
            onClick={() => void run()}
          >
            {busy ? t.compare.running : t.compare.run}
          </button>
        </div>
      </div>

      {result && (
        <div className="card" style={{ marginTop: 16 }}>
          <div className="stat-grid" style={{ marginBottom: 12 }}>
            <div
              className="stat"
              style={{ ["--stat-color" as string]: "var(--critical)" }}
            >
              <div className="num" style={{ color: "var(--critical)" }}>
                {result.new.length}
              </div>
              <div className="label">{t.compare.new}</div>
            </div>
            <div
              className="stat"
              style={{ ["--stat-color" as string]: "var(--low)" }}
            >
              <div className="num" style={{ color: "var(--low)" }}>
                {result.resolved.length}
              </div>
              <div className="label">{t.compare.resolved}</div>
            </div>
            <div className="stat">
              <div className="num">{result.unchanged.length}</div>
              <div className="label">{t.compare.unchanged}</div>
            </div>
          </div>
          {/* Scan markdown is untrusted text. Keep it in a pre, never HTML. */}
          <pre className="compare-report">{result.markdown}</pre>
          <p className="muted">
            {t.compare.openHead}{" "}
            <Link to={`/scans/${result.head}`}>{t.compare.viewHead}</Link>
          </p>
        </div>
      )}
    </div>
  );
}
