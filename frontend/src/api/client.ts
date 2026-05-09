/**
 * client.ts — Typed API client for all backend communication.
 *
 * Security design:
 *   - Access token stored in module memory (not localStorage) — XSS cannot steal it
 *   - Refresh token is an httpOnly cookie — JS has no access to it
 *   - On 401: auto-retry with refreshed access token once, then redirect to login
 *   - No raw fetch() calls anywhere else in the codebase — all API calls go through here
 */

import axios, { AxiosInstance, AxiosRequestConfig } from "axios";
import type {
  IAlert,
  IDetectionRule,
  IDetectionRuleCreate,
  IDetectionTestResult,
  IIngestResponse,
  IQueryResponse,
  ITokenResponse,
} from "./types";

const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "/api/v1";

// Module-level token storage — survives re-renders but is lost on page refresh.
// This is intentional: fresh page load requires re-authentication.
// The httpOnly refresh cookie handles silent renewal via /auth/refresh.
let _accessToken: string | null = null;
let _isRefreshing = false;
let _refreshSubscribers: Array<(token: string) => void> = [];

function setAccessToken(token: string): void {
  _accessToken = token;
}

function clearAccessToken(): void {
  _accessToken = null;
}

export function getAccessToken(): string | null {
  return _accessToken;
}

const api: AxiosInstance = axios.create({
  baseURL: BASE_URL,
  withCredentials: true, // Required for httpOnly refresh cookie
});

// Attach access token to every request
api.interceptors.request.use((config) => {
  if (_accessToken) {
    config.headers.Authorization = `Bearer ${_accessToken}`;
  }
  return config;
});

// On 401: attempt silent token refresh, retry original request once
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config as AxiosRequestConfig & {
      _retry?: boolean;
    };

    if (error.response?.status === 401 && !originalRequest._retry) {
      if (_isRefreshing) {
        // Queue the retry until refresh completes
        return new Promise((resolve) => {
          _refreshSubscribers.push((token: string) => {
            originalRequest.headers = {
              ...originalRequest.headers,
              Authorization: `Bearer ${token}`,
            };
            resolve(api(originalRequest));
          });
        });
      }

      originalRequest._retry = true;
      _isRefreshing = true;

      try {
        const resp = await axios.post<ITokenResponse>(
          `${BASE_URL}/auth/refresh`,
          {},
          { withCredentials: true }
        );
        const newToken = resp.data.access_token;
        setAccessToken(newToken);
        _refreshSubscribers.forEach((cb) => cb(newToken));
        _refreshSubscribers = [];
        originalRequest.headers = {
          ...originalRequest.headers,
          Authorization: `Bearer ${newToken}`,
        };
        return api(originalRequest);
      } catch {
        clearAccessToken();
        _refreshSubscribers = [];
        // Redirect to login on refresh failure
        window.location.href = "/login";
        return Promise.reject(error);
      } finally {
        _isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

export async function login(username: string, password: string): Promise<ITokenResponse> {
  const form = new URLSearchParams();
  form.append("username", username);
  form.append("password", password);
  const resp = await api.post<ITokenResponse>("/auth/token", form, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
  });
  setAccessToken(resp.data.access_token);
  return resp.data;
}

export async function logout(): Promise<void> {
  await api.post("/auth/logout");
  clearAccessToken();
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------

export async function executeQuery(
  query: string,
  language: "kql" | "spl" | "sql",
  limit = 1000
): Promise<IQueryResponse> {
  const resp = await api.post<IQueryResponse>("/query/execute", {
    query,
    language,
    limit,
  });
  return resp.data;
}

// ---------------------------------------------------------------------------
// Ingest
// ---------------------------------------------------------------------------

export async function uploadLogs(
  file: File,
  table?: string
): Promise<IIngestResponse> {
  const form = new FormData();
  form.append("file", file);
  if (table) form.append("table", table);
  const resp = await api.post<IIngestResponse>("/ingest/upload", form);
  return resp.data;
}

// ---------------------------------------------------------------------------
// Detections
// ---------------------------------------------------------------------------

export async function listDetections(
  page = 1,
  pageSize = 50
): Promise<IDetectionRule[]> {
  const resp = await api.get<IDetectionRule[]>("/detections/", {
    params: { page, page_size: pageSize },
  });
  return resp.data;
}

export async function getDetection(id: string): Promise<IDetectionRule> {
  const resp = await api.get<IDetectionRule>(`/detections/${id}`);
  return resp.data;
}

export async function createDetection(
  rule: IDetectionRuleCreate
): Promise<IDetectionRule> {
  const resp = await api.post<IDetectionRule>("/detections/", rule);
  return resp.data;
}

export async function updateDetection(
  id: string,
  rule: IDetectionRuleCreate
): Promise<IDetectionRule> {
  const resp = await api.put<IDetectionRule>(`/detections/${id}`, rule);
  return resp.data;
}

export async function patchDetection(
  id: string,
  patch: { enabled?: boolean; false_positive_notes?: string; severity?: string }
): Promise<IDetectionRule> {
  const resp = await api.patch<IDetectionRule>(`/detections/${id}`, patch);
  return resp.data;
}

export async function deleteDetection(id: string): Promise<void> {
  await api.delete(`/detections/${id}`);
}

export async function testDetection(
  id: string
): Promise<IDetectionTestResult> {
  const resp = await api.post<IDetectionTestResult>(`/detections/${id}/test`);
  return resp.data;
}

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------

export async function listAlerts(params?: {
  severity?: string[];
  status?: string;
  page?: number;
  page_size?: number;
}): Promise<IAlert[]> {
  const resp = await api.get<IAlert[]>("/alerts/", { params });
  return resp.data;
}

export async function getAlert(id: string): Promise<IAlert> {
  const resp = await api.get<IAlert>(`/alerts/${id}`);
  return resp.data;
}

export async function patchAlert(
  id: string,
  patch: { status?: string; notes?: string }
): Promise<IAlert> {
  const resp = await api.patch<IAlert>(`/alerts/${id}`, patch);
  return resp.data;
}
