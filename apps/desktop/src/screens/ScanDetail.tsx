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
import { SeverityBadge } from "./Dashboard";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const STATE_LABELS: Record<FindingState, string> = {
  open: "open",
  false_positive: "false positive",
  fixed: "fixed",
  accepted_risk: "accepted risk",
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
  const [open, setOpen] = useState(false);
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

  return (
    <div className="card">
      <div className="row-between">
        <div>
          <SeverityBadge value={finding.severity} />{" "}
          <span className={`badge state-${finding.state}`}>
            {STATE_LABELS[finding.state]}
          </span>{" "}
          <strong>{finding.title}</strong>
        </div>
        <button className="secondary" onClick={() => setOpen(!open)}>
          {open ? "Hide" : "Evidence"}
        </button>
      </div>
      <div className="muted" style={{ marginTop: 6 }}>
        <span className="mono">
          {finding.method} {finding.endpoint}
        </span>
        {finding.parameter && <span> · param {finding.parameter}</span>} ·{" "}
        {finding.category}
        {finding.cwe && <span> · {finding.cwe}</span>} · confidence:{" "}
        {finding.confidence}
      </div>

      {open && (
        <div className="evidence">
          <div>{finding.evidence.summary}</div>
          {finding.evidence.request && <pre>{finding.evidence.request}</pre>}
          {finding.evidence.response && <pre>{finding.evidence.response}</pre>}
          <div style={{ marginTop: 8 }}>
            <strong>Impact.</strong> {finding.impact}
            <br />
            <strong>Recommendation.</strong> {finding.recommendation}
          </div>
          {finding.references.length > 0 && (
            <div className="muted" style={{ marginTop: 6 }}>
              {finding.references.map((ref) => (
                <div key={ref}>{ref}</div>
              ))}
            </div>
          )}
        </div>
      )}

      {error && <p className="error-text">{error}</p>}

      <div className="finding-actions">
        <button
          className="secondary"
          disabled={busy || finding.state === "fixed"}
          onClick={() => void mark("fixed")}
        >
          Mark fixed
        </button>
        <button
          className="secondary"
          disabled={busy || finding.state === "false_positive"}
          onClick={() => void mark("false_positive")}
        >
          False positive
        </button>
        <button
          className="secondary"
          disabled={busy || finding.state === "accepted_risk"}
          onClick={() => void mark("accepted_risk")}
        >
          Accept risk
        </button>
        <button
          className="secondary"
          disabled={busy || finding.state === "open"}
          onClick={() => void mark("open")}
        >
          Reopen
        </button>
      </div>
    </div>
  );
}

export default function ScanDetail(): JSX.Element {
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
        <h1>Audit</h1>
        <p className="error-text">{loadError}</p>
        <Link to="/">Back to dashboard</Link>
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
          <h1 className="mono" style={{ fontSize: 17 }}>
            {scan?.target ?? id}
          </h1>
          <p className="page-sub">
            {scan ? (
              <>
                {scan.stats.findings_total} findings ·{" "}
                {scan.stats.endpoints_discovered} endpoints ·{" "}
                {scan.stats.requests_made} requests
                {durationSeconds !== null && ` · ${durationSeconds.toFixed(1)}s`}
                {scan.authenticated && " · authenticated"}
              </>
            ) : (
              "Connecting…"
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
                {fmt}
              </a>
            ))}
          </div>
        )}
      </div>

      {runError && (
        <div className="card">
          <p className="error-text">Scan failed: {runError}</p>
        </div>
      )}

      {running && (
        <div className="card">
          <div className="row-between" style={{ marginBottom: 10 }}>
            <strong>
              <span className="spinner" /> Audit running
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
          <strong>Detected stack:</strong>{" "}
          {scan.technologies
            .map((t) => (t.version ? `${t.name} ${t.version}` : t.name))
            .join(" · ")}
        </div>
      )}

      {scan && (
        <>
          <div className="filter-row" style={{ marginTop: 18 }}>
            <button
              className={`filter-chip ${filter === null ? "on" : ""}`}
              onClick={() => setFilter(null)}
            >
              all ({scan.findings.length})
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
                  ? "No findings — the checks that ran found nothing to report."
                  : "No findings at this severity."}
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
