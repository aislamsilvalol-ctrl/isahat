/**
 * Typed client for the local IsaHat bridge (`isahat serve`).
 *
 * The UI never touches the Python core directly — everything goes through this
 * client, which mirrors the CLI's capabilities 1:1 (shared-engine guarantee).
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "possible" | "probable" | "high" | "confirmed" | "false_positive";
export type FindingState = "open" | "false_positive" | "fixed" | "accepted_risk";

export interface Evidence {
  summary: string;
  request?: string | null;
  response?: string | null;
  location?: string | null;
}

export interface Finding {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  confidence: Confidence;
  state: FindingState;
  endpoint: string;
  method: string;
  parameter?: string | null;
  evidence: Evidence;
  impact: string;
  likelihood?: string;
  exploitation?: string;
  recommendation: string;
  remediation_example?: string | null;
  references: string[];
  false_positive_hints?: string[];
  cwe?: string | null;
  owasp?: string | null;
  detected_at: string;
}

export interface Endpoint {
  url: string;
  status: number;
  content_type?: string | null;
  title?: string | null;
}

export interface Technology {
  name: string;
  version?: string | null;
  category: string;
}

export interface ScanStats {
  endpoints_discovered: number;
  forms_discovered: number;
  apis_discovered: number;
  requests_made: number;
  findings_total: number;
  by_severity: Record<string, number>;
  by_confidence: Record<string, number>;
}

export interface ScanResult {
  id: string;
  target: string;
  profile: string;
  scan_type: string;
  authenticated: boolean;
  started_at: string;
  finished_at?: string | null;
  stats: ScanStats;
  endpoints: Endpoint[];
  technologies: Technology[];
  findings: Finding[];
}

export interface ScanRow {
  id: string;
  target: string;
  profile: string;
  started_at: string;
  finished_at?: string | null;
  findings_total: number;
  by_severity: Record<Severity, number>;
  running: boolean;
}

export interface ScanEvent {
  stage: string;
  message: string;
}

export interface ScanStatus {
  scan_id: string;
  status: "running" | "done" | "error";
  detail: string;
  events: ScanEvent[];
}

export interface CompareResult {
  base: string;
  head: string;
  new: string[];
  resolved: string[];
  unchanged: string[];
  markdown: string;
}

export interface AuthConfig {
  headers?: Record<string, string>;
  cookies?: Record<string, string>;
}

// Inside the Tauri webview there is no dev proxy, so we call the bridge
// directly; in the browser dev server, /api is proxied by Vite. The bridge
// only ever listens on loopback.
const isTauri = typeof window !== "undefined" && "__TAURI__" in window;
const BASE =
  import.meta.env?.VITE_BRIDGE_URL ?? (isTauri ? "http://127.0.0.1:8741" : "/api");

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const body = (await response.json()) as { detail?: string };
      if (body.detail) detail = body.detail;
    } catch {
      // keep the HTTP status as the message
    }
    throw new Error(detail);
  }
  return (await response.json()) as T;
}

export const api = {
  health: () => request<{ status: string; version: string }>("/health"),

  listScans: () => request<ScanRow[]>("/scans"),

  getScan: (id: string) => request<ScanResult>(`/scans/${id}`),

  getStatus: (id: string) => request<ScanStatus>(`/scans/${id}/status`),

  startScan: (payload: {
    target: string;
    profile: string;
    scan_type: string;
    auth?: AuthConfig;
    rate_limit_check: boolean;
    confirmed: boolean;
  }) =>
    request<{ scan_id: string; target: string }>("/scans", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  annotate: (scanId: string, findingId: string, state: FindingState, comment?: string) =>
    request<{ status: string }>(`/scans/${scanId}/findings/${findingId}/annotation`, {
      method: "POST",
      body: JSON.stringify({ state, comment: comment ?? null }),
    }),

  compare: (base: string, head: string) =>
    request<CompareResult>(`/compare?base=${encodeURIComponent(base)}&head=${encodeURIComponent(head)}`),

  listCheckpoints: () =>
    request<
      {
        scan_id: string;
        target: string;
        stage: string;
        saved_at: string;
        running: boolean;
      }[]
    >("/checkpoints"),

  resumeScan: (scanId: string) =>
    request<{ scan_id: string; target: string }>(
      `/scans/${encodeURIComponent(scanId)}/resume`,
      { method: "POST" },
    ),

  reportUrl: (scanId: string, fmt: string) =>
    `${BASE}/scans/${encodeURIComponent(scanId)}/report?fmt=${encodeURIComponent(fmt)}`,

  /** Server-sent events stream of scan progress; caller must close it. */
  eventsUrl: (scanId: string) => `${BASE}/scans/${encodeURIComponent(scanId)}/events`,
};
