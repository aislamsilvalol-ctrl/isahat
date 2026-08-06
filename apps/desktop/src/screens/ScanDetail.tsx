import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  api,
  type Finding,
  type FindingState,
  type ScanEvent,
  type ScanResult,
  type Severity,
} from "../api/client";
import { useI18n } from "../i18n";
import { SeverityBadge } from "./Dashboard";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const SEV_COLOR: Record<Severity, string> = {
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
  low: "var(--low)",
  info: "var(--info)",
};

function FindingCard({
  scanId,
  finding,
  onAnnotated,
}: {
  scanId: string;
  finding: Finding;
  onAnnotated: () => void;
}): JSX.Element {
  const { t } = useI18n();
  const [open, setOpen] = useState(false);
  const [tab, setTab] = useState<"evidence" | "remediation">("remediation");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function mark(state: FindingState): Promise<void> {
    setBusy(true);
    setError(null);
    try {
      await api.annotate(scanId, finding.id, state);
      onAnnotated();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  const rem = t.scan.remediation;

  return (
    <div
      className="card finding"
      style={{ ["--sev-color" as string]: SEV_COLOR[finding.severity] }}
    >
      <div className="finding-head" onClick={() => setOpen(!open)}>
        <div className="row-between">
          <div>
            <SeverityBadge value={finding.severity} />{" "}
            <span className={`badge state-${finding.state}`}>
              {t.state[finding.state]}
            </span>{" "}
            <strong>{finding.title}</strong>
          </div>
          <span className="muted">{open ? `▲ ${t.scan.hide}` : `▼ ${t.scan.show}`}</span>
        </div>
        <div className="muted" style={{ marginTop: 7 }}>
          <span className="mono">
            {finding.method} {finding.endpoint}
          </span>
          {finding.parameter && (
            <span>
              {" "}
              · {t.scan.param} <span className="mono">{finding.parameter}</span>
            </span>
          )}{" "}
          · {finding.category}
          {finding.cwe && <span> · {finding.cwe}</span>} · {t.scan.confidence}:{" "}
          {finding.confidence}
        </div>
      </div>

      {open && (
        <>
          <div className="tabs">
            <button
              className={tab === "remediation" ? "on" : ""}
              onClick={() => setTab("remediation")}
            >
              {t.scan.tabs.remediation}
            </button>
            <button
              className={tab === "evidence" ? "on" : ""}
              onClick={() => setTab("evidence")}
            >
              {t.scan.tabs.evidence}
            </button>
          </div>

          {tab === "remediation" && (
            <div className="remediation">
              <div className="rem-section">
                <div className="rem-title">{rem.impact}</div>
                {finding.impact}
                {finding.likelihood && finding.likelihood !== "unknown" && (
                  <div className="muted" style={{ marginTop: 4 }}>
                    {rem.likelihood}: {finding.likelihood}
                    {finding.exploitation &&
                      finding.exploitation !== "n/a" &&
                      ` · ${rem.exploitation}: ${finding.exploitation}`}
                  </div>
                )}
              </div>

              <div className="rem-section">
                <div className="rem-title">{rem.recommendation}</div>
                {finding.recommendation}
              </div>

              <div className="rem-section">
                <div className="rem-title">{rem.example}</div>
                {finding.remediation_example ? (
                  <pre>
                    <code>{finding.remediation_example}</code>
                  </pre>
                ) : (
                  <span className="muted">{rem.noExample}</span>
                )}
              </div>

              {(finding.false_positive_hints?.length ?? 0) > 0 && (
                <div className="rem-section">
                  <div className="rem-title">{rem.fpHints}</div>
                  <ul style={{ margin: "4px 0 0", paddingLeft: 18 }}>
                    {finding.false_positive_hints!.map((hint) => (
                      <li key={hint} className="muted">
                        {hint}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {finding.references.length > 0 && (
                <div className="rem-section">
                  <div className="rem-title">{rem.references}</div>
                  {finding.references.map((ref) => (
                    <div key={ref}>
                      <a href={ref} target="_blank" rel="noreferrer">
                        {ref}
                      </a>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {tab === "evidence" && (
            <div className="evidence">
              <div className="rem-section">
                <div className="rem-title">{t.scan.evidenceSummary}</div>
                {finding.evidence.summary}
              </div>
              {finding.evidence.request && (
                <div className="rem-section">
                  <div className="rem-title">{t.scan.evidenceRequest}</div>
                  <pre>{finding.evidence.request}</pre>
                </div>
              )}
              {finding.evidence.response && (
                <div className="rem-section">
                  <div className="rem-title">{t.scan.evidenceResponse}</div>
                  <pre>{finding.evidence.response}</pre>
                </div>
              )}
            </div>
          )}
        </>
      )}

      {error && <p className="error-text">{error}</p>}

      <div className="finding-actions">
        <button
          className="secondary"
          disabled={busy || finding.state === "fixed"}
          onClick={() => void mark("fixed")}
        >
          ✓ {t.scan.markFixed}
        </button>
        <button
          className="secondary"
          disabled={busy || finding.state === "false_positive"}
          onClick={() => void mark("false_positive")}
        >
          {t.scan.markFp}
        </button>
        <button
          className="secondary"
          disabled={busy || finding.state === "accepted_risk"}
          onClick={() => void mark("accepted_risk")}
        >
          {t.scan.markRisk}
        </button>
        <button
          className="ghost"
          disabled={busy || finding.state === "open"}
          onClick={() => void mark("open")}
        >
          {t.scan.reopen}
        </button>
      </div>
    </div>
  );
}

export default function ScanDetail(): JSX.Element {
  const { t } = useI18n();
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [running, setRunning] = useState(false);
  const [runError, setRunError] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [filter, setFilter] = useState<Severity | null>(null);
  const logRef = useRef<HTMLDivElement | null>(null);

  const refreshScan = useCallback((): void => {
    if (!id) return;
    api
      .getScan(id)
      .then(setScan)
      .catch((err: Error) => setLoadError(err.message));
  }, [id]);

  // Track the scan lifecycle: status polling while running (works for scans
  // started in other sessions too), plus the SSE stream for the event log.
  useEffect(() => {
    if (!id) return;
    let alive = true;
    let source: EventSource | null = null;

    const poll = setInterval(() => {
      api
        .getStatus(id)
        .then((status) => {
          if (!alive) return;
          setEvents(status.events);
          const isRunning = status.status === "running";
          setRunning(isRunning);
          if (status.status === "error") setRunError(status.detail);
          if (!isRunning) {
            refreshScan();
            clearInterval(poll);
            source?.close();
          }
        })
        .catch(() => {
          if (alive) refreshScan(); // finished scans have no live job
        });
    }, 1200);

    source = new EventSource(api.eventsUrl(id));
    source.onmessage = (msg: MessageEvent<string>) => {
      try {
        const event = JSON.parse(msg.data) as ScanEvent;
        if (!alive) return;
        setEvents((prev) => [...prev.slice(-200), event]);
        // The server ends the stream after a terminal event; without this the
        // browser would auto-reconnect and replay the buffer.
        if (event.stage === "done" || event.stage === "error") {
          source?.close();
        }
      } catch {
        // malformed event — ignore
      }
    };

    return () => {
      alive = false;
      clearInterval(poll);
      source?.close();
    };
  }, [id, refreshScan]);

  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight });
  }, [events]);

  if (loadError && !scan) {
    return (
      <div>
        <h1>{t.scan.failed}</h1>
        <p className="error-text">{loadError}</p>
        <Link to="/">{t.scan.back}</Link>
      </div>
    );
  }

  const findings = (scan?.findings ?? [])
    .filter((f) => filter === null || f.severity === filter)
    .sort(
      (a, b) =>
        SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity),
    );

  const durationSeconds =
    scan?.finished_at != null
      ? (new Date(scan.finished_at).getTime() -
          new Date(scan.started_at).getTime()) /
        1000
      : null;

  return (
    <div>
      <div className="row-between">
        <div>
          <h1 className="mono" style={{ fontSize: 16, letterSpacing: 0 }}>
            {scan?.target ?? id}
          </h1>
          <p className="page-sub">
            {scan ? (
              <>
                {scan.stats.findings_total} {t.scan.findings} ·{" "}
                {scan.stats.endpoints_discovered} {t.scan.endpoints} ·{" "}
                {scan.stats.requests_made} {t.scan.requests}
                {durationSeconds !== null && ` · ${durationSeconds.toFixed(1)}s`}
                {scan.authenticated && ` · ${t.scan.authenticated}`}
              </>
            ) : (
              t.scan.connecting
            )}
          </p>
        </div>
        {scan && (
          <div style={{ display: "flex", gap: 8 }}>
            {(["html", "markdown", "json"] as const).map((fmt) => (
              <a
                key={fmt}
                className="button secondary"
                href={api.reportUrl(scan.id, fmt)}
                download
              >
                ↓ {fmt}
              </a>
            ))}
          </div>
        )}
      </div>

      {runError && (
        <div className="card">
          <p className="error-text">
            {t.scan.failed}: {runError}
          </p>
        </div>
      )}

      {running && (
        <div className="card">
          <div className="row-between" style={{ marginBottom: 12 }}>
            <strong>
              <span className="spinner" /> {t.scan.runningTitle}
            </strong>
          </div>
          <div className="event-log" ref={logRef}>
            {events.map((event, i) => (
              <div key={i}>
                <span className="stage">[{event.stage}]</span>
                {event.message}
              </div>
            ))}
          </div>
        </div>
      )}

      {scan && scan.technologies.length > 0 && (
        <div className="card">
          <strong>{t.scan.stack}:</strong>{" "}
          {scan.technologies
            .map((tech) => (tech.version ? `${tech.name} ${tech.version}` : tech.name))
            .join(" · ")}
        </div>
      )}

      {scan && (
        <>
          <div className="filter-row">
            <button
              className={`filter-chip ${filter === null ? "on" : ""}`}
              onClick={() => setFilter(null)}
            >
              {t.scan.filterAll} ({scan.findings.length})
            </button>
            {SEVERITIES.map((sev) => {
              const count = scan.findings.filter((f) => f.severity === sev).length;
              if (count === 0) return null;
              return (
                <button
                  key={sev}
                  className={`filter-chip ${filter === sev ? "on" : ""}`}
                  onClick={() => setFilter(sev)}
                >
                  {sev} ({count})
                </button>
              );
            })}
          </div>

          {findings.length === 0 && (
            <div className="card">
              <p className="muted">
                {scan.findings.length === 0
                  ? t.scan.noFindings
                  : t.scan.noFindingsAtSeverity}
              </p>
            </div>
          )}
          {findings.map((finding) => (
            <FindingCard
              key={finding.id}
              scanId={scan.id}
              finding={finding}
              onAnnotated={refreshScan}
            />
          ))}
        </>
      )}
    </div>
  );
}
