/**
 * Alerts.tsx — Alert feed and triage workflow.
 *
 * Sorted by triggered_at descending. Status transitions: open → investigating → closed.
 * Auto-refreshes every 60 seconds. Optimistic updates for status changes.
 */

import { useEffect, useRef, useState } from "react";
import { listAlerts, patchAlert } from "../api/client";
import type { IAlert } from "../api/types";
import AlertBadge from "../components/AlertBadge";
import SeverityPill from "../components/SeverityPill";

export default function Alerts() {
  const [alerts, setAlerts] = useState<IAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string[]>([]);
  const [statusFilter, setStatusFilter] = useState("");
  const [notes, setNotes] = useState<Record<string, string>>({});
  const refreshRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const load = async () => {
    try {
      const data = await listAlerts({
        severity: severityFilter.length ? severityFilter : undefined,
        status: statusFilter || undefined,
      });
      setAlerts(data);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    refreshRef.current = setInterval(load, 60_000);
    return () => { if (refreshRef.current) clearInterval(refreshRef.current); };
  }, [severityFilter, statusFilter]);

  const handleStatusChange = async (alert: IAlert, newStatus: string) => {
    // Optimistic update
    setAlerts((prev) =>
      prev.map((a) => (a.alert_id === alert.alert_id ? { ...a, status: newStatus as IAlert["status"] } : a))
    );
    await patchAlert(alert.alert_id, { status: newStatus, notes: notes[alert.alert_id] });
  };

  const handleNoteSave = async (alert: IAlert) => {
    await patchAlert(alert.alert_id, { notes: notes[alert.alert_id] });
  };

  const SEVERITIES = ["critical", "high", "medium", "low", "info"];
  const STATUS_OPTIONS = ["open", "investigating", "closed"];

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold">Alerts</h1>
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          Auto-refresh: 60s
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-4 flex-wrap">
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">Severity:</span>
          {SEVERITIES.map((s) => (
            <button
              key={s}
              onClick={() =>
                setSeverityFilter((prev) =>
                  prev.includes(s) ? prev.filter((x) => x !== s) : [...prev, s]
                )
              }
              className={`px-2 py-1 rounded text-xs transition-colors ${
                severityFilter.includes(s)
                  ? "bg-primary text-primary-foreground"
                  : "bg-muted text-muted-foreground hover:text-foreground"
              }`}
            >
              {s}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">Status:</span>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-input border border-border rounded px-2 py-1 text-xs text-foreground"
          >
            <option value="">All</option>
            {STATUS_OPTIONS.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Alert list */}
      {loading ? (
        <div className="text-sm text-muted-foreground">Loading alerts...</div>
      ) : alerts.length === 0 ? (
        <div className="text-sm text-muted-foreground border border-border rounded p-6 text-center">
          No alerts match your filters.
        </div>
      ) : (
        <div className="space-y-2">
          {alerts.map((alert) => (
            <div key={alert.alert_id} className="bg-card border border-border rounded-lg">
              {/* Alert header */}
              <div
                className="flex items-center gap-3 p-4 cursor-pointer hover:bg-muted/20 transition-colors"
                onClick={() => setExpandedId(expandedId === alert.alert_id ? null : alert.alert_id)}
              >
                <SeverityPill severity={alert.severity} />
                <div className="flex-1">
                  <div className="text-sm font-medium">{alert.rule_name}</div>
                  <div className="text-xs text-muted-foreground">
                    {alert.rule_id} · {alert.event_count} events ·{" "}
                    {new Date(alert.triggered_at).toLocaleString()}
                  </div>
                </div>
                <AlertBadge status={alert.status} />
              </div>

              {/* Expanded detail */}
              {expandedId === alert.alert_id && (
                <div className="border-t border-border p-4 space-y-3">
                  <div className="text-xs text-muted-foreground">
                    Sample event IDs: {alert.sample_event_ids.slice(0, 3).join(", ")}
                    {alert.sample_event_ids.length > 3 && ` +${alert.sample_event_ids.length - 3} more`}
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="text-xs text-muted-foreground">Status:</span>
                    <select
                      value={alert.status}
                      onChange={(e) => handleStatusChange(alert, e.target.value)}
                      className="bg-input border border-border rounded px-2 py-1 text-xs text-foreground"
                    >
                      {STATUS_OPTIONS.map((s) => (
                        <option key={s} value={s}>{s}</option>
                      ))}
                    </select>
                  </div>

                  <div className="space-y-1">
                    <label className="text-xs text-muted-foreground">Analyst notes</label>
                    <textarea
                      value={notes[alert.alert_id] ?? alert.notes}
                      onChange={(e) =>
                        setNotes((prev) => ({ ...prev, [alert.alert_id]: e.target.value }))
                      }
                      rows={3}
                      className="w-full bg-input border border-border rounded px-3 py-2 text-sm resize-none"
                      placeholder="Add investigation notes..."
                    />
                    <button
                      onClick={() => handleNoteSave(alert)}
                      className="text-xs text-primary hover:text-primary/80 transition-colors"
                    >
                      Save notes
                    </button>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
