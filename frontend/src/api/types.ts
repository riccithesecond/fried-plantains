/** Typed API response interfaces — mirrors backend Pydantic models exactly. */

export interface ITokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

export interface IColumnMeta {
  name: string;
  type: string;
}

export interface IQueryResponse {
  columns: IColumnMeta[];
  rows: unknown[][];
  count: number;
  duration_ms: number;
  render_hint: string | null;
}

export interface IDetectionRule {
  id: string;
  name: string;
  description: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  language: "kql" | "spl" | "sql";
  query: string;
  tags: string[];
  mde_portable: boolean;
  enabled: boolean;
  created_at: string;
  updated_at: string;
  author: string;
  false_positive_notes: string;
}

export interface IDetectionRuleCreate {
  name: string;
  description: string;
  severity: string;
  language: string;
  query: string;
  tags: string[];
  mde_portable: boolean;
  enabled: boolean;
  author: string;
  false_positive_notes: string;
}

export interface IDetectionTestResult {
  rule_id: string;
  match_count: number;
  sample_rows: Record<string, unknown>[];
  duration_ms: number;
}

export interface IAlert {
  alert_id: string;
  rule_id: string;
  rule_name: string;
  severity: string;
  triggered_at: string;
  event_count: number;
  sample_event_ids: string[];
  status: "open" | "investigating" | "closed";
  notes: string;
}

export interface IIngestResponse {
  table: string | string[];
  events_ingested: number;
  partition_path: string | null;
  duration_ms: number;
  message?: string;
}

export interface IApiError {
  detail: string;
}
