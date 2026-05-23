/**
 * Dashboard.tsx — Overview of platform health and detection activity.
 *
 * Four metric cards + event volume chart (Recharts) + alert severity chart.
 * Event volume is queried live from the data lake via SQL — three parallel
 * queries, one per table, merged into a single 24-hour time series.
 */

import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { executeQuery, listAlerts, listDetections } from "../api/client";
import type { IAlert, IDetectionRule } from "../api/types";
import AlertBadge from "../components/AlertBadge";
import SeverityPill from "../components/SeverityPill";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface IMetricCardProps {
  label: string;
  value: string | number;
  sub?: string;
}

interface IVolumePoint {
  hour: string;
  DeviceProcessEvents: number;
  DeviceNetworkEvents: number;
  DeviceLogonEvents: number;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const VOLUME_TABLES = [
  "DeviceProcessEvents",
  "DeviceNetworkEvents",
  "DeviceLogonEvents",
] as const;

type TVolumeTable = (typeof VOLUME_TABLES)[number];

function buildVolumeQuery(table: string): string {
  return (
    `SELECT date_trunc('hour', Timestamp) AS hour, COUNT(*) AS event_count ` +
    `FROM ${table} ` +
    `WHERE Timestamp > NOW() - INTERVAL 24 HOUR ` +
    `GROUP BY 1 ORDER BY 1 ASC`
  );
}

/** Build an empty 24-slot hour map — all tables zeroed. */
function emptyHourMap(): Record<string, IVolumePoint> {
  const map: Record<string, IVolumePoint> = {};
  for (let h = 0; h < 24; h++) {
    const key = `${String(h).padStart(2, "0")}:00`;
    map[key] = {
      hour: key,
      DeviceProcessEvents: 0,
      DeviceNetworkEvents: 0,
      DeviceLogonEvents: 0,
    };
  }
  return map;
}

// ---------------------------------------------------------------------------
// Components
// ---------------------------------------------------------------------------

function MetricCard({ label, value, sub }: IMetricCardProps) {
  return (
    <div className="bg-card border border-border rounded-lg p-4">
      <div className="text-xs text-muted-foreground mb-1">{label}</div>
      <div className="text-2xl font-bold">{value}</div>
      {sub && <div className="text-xs text-muted-foreground mt-1">{sub}</div>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

export default function Dashboard() {
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState<IAlert[]>([]);
  const [rules, setRules] = useState<IDetectionRule[]>([]);
  const [volumeData, setVolumeData] = useState<IVolumePoint[]>([]);
  const [totalEventCount, setTotalEventCount] = useState(0);
  const [topSource, setTopSource] = useState<string>("—");
  const [loading, setLoading] = useState(true);
  const [volumeLoading, setVolumeLoading] = useState(true);

  useEffect(() => {
    // Load alerts + rules immediately
    Promise.all([listAlerts(), listDetections()])
      .then(([a, r]) => {
        setAlerts(a);
        setRules(r);
      })
      .finally(() => setLoading(false));

    // Load volume data in parallel — errors are caught per-table so a missing
    // table (no parquet yet) degrades gracefully to a zero line.
    setVolumeLoading(true);
    Promise.all(
      VOLUME_TABLES.map((t) =>
        executeQuery(buildVolumeQuery(t), "sql", 24).catch(() => null)
      )
    )
      .then((results) => {
        const hourMap = emptyHourMap();
        let total = 0;
        const tableTotals: Record<TVolumeTable, number> = {
          DeviceProcessEvents: 0,
          DeviceNetworkEvents: 0,
          DeviceLogonEvents: 0,
        };

        results.forEach((result, i) => {
          if (!result) return;
          const table = VOLUME_TABLES[i];
          for (const row of result.rows) {
            const [rawHour, count] = row as [string, number];
            if (!rawHour) continue;
            const d = new Date(rawHour);
            const key = `${String(d.getUTCHours()).padStart(2, "0")}:00`;
            if (hourMap[key]) {
              hourMap[key][table] = count;
              total += count;
              tableTotals[table] += count;
            }
          }
        });

        setVolumeData(Object.values(hourMap));
        setTotalEventCount(total);

        // Top source = table with most events in the last 24h
        const top = (Object.entries(tableTotals) as [TVolumeTable, number][])
          .sort(([, a], [, b]) => b - a)[0];
        if (top && top[1] > 0) setTopSource(top[0]);
      })
      .finally(() => setVolumeLoading(false));
  }, []);

  const openAlerts = alerts.filter((a) => a.status === "open").length;
  const activeRules = rules.filter((r) => r.enabled).length;

  const severityData = ["critical", "high", "medium", "low", "info"].map(
    (s) => ({
      severity: s.charAt(0).toUpperCase() + s.slice(1),
      count: alerts.filter((a) => a.severity === s).length,
    })
  );

  const recent = alerts.slice(0, 10);

  if (loading) {
    return (
      <div className="p-6 text-muted-foreground text-sm">
        Loading dashboard...
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-xl font-bold">Dashboard</h1>

      {/* Metric cards */}
      <div className="grid grid-cols-4 gap-4">
        <MetricCard
          label="Events (24h)"
          value={totalEventCount.toLocaleString()}
          sub={volumeLoading ? "loading…" : undefined}
        />
        <MetricCard
          label="Open Alerts"
          value={openAlerts}
          sub={`${alerts.length} total`}
        />
        <MetricCard
          label="Active Rules"
          value={activeRules}
          sub={`${rules.length} total`}
        />
        <MetricCard label="Top Source" value={topSource} />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-3 gap-4">
        {/* Event volume area chart — 2/3 width */}
        <div className="col-span-2 bg-card border border-border rounded-lg p-4">
          <div className="text-sm font-medium mb-3">
            Event Volume (24h)
            {volumeLoading && (
              <span className="ml-2 text-xs text-muted-foreground font-normal">
                loading…
              </span>
            )}
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={volumeData}>
              <CartesianGrid
                strokeDasharray="3 3"
                stroke="hsl(var(--border))"
              />
              <XAxis
                dataKey="hour"
                tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }}
                interval={3}
              />
              <YAxis
                tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: "hsl(var(--card))",
                  border: "1px solid hsl(var(--border))",
                  fontSize: 12,
                }}
              />
              <Area
                type="monotone"
                dataKey="DeviceProcessEvents"
                stackId="1"
                stroke="#3b82f6"
                fill="#3b82f6"
                fillOpacity={0.4}
              />
              <Area
                type="monotone"
                dataKey="DeviceNetworkEvents"
                stackId="1"
                stroke="#10b981"
                fill="#10b981"
                fillOpacity={0.4}
              />
              <Area
                type="monotone"
                dataKey="DeviceLogonEvents"
                stackId="1"
                stroke="#f59e0b"
                fill="#f59e0b"
                fillOpacity={0.4}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Alert severity bar chart — 1/3 width */}
        <div className="bg-card border border-border rounded-lg p-4">
          <div className="text-sm font-medium mb-3">Alerts by Severity</div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={severityData} layout="vertical">
              <CartesianGrid
                strokeDasharray="3 3"
                stroke="hsl(var(--border))"
              />
              <XAxis
                type="number"
                tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }}
              />
              <YAxis
                type="category"
                dataKey="severity"
                tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }}
                width={60}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: "hsl(var(--card))",
                  border: "1px solid hsl(var(--border))",
                  fontSize: 12,
                }}
              />
              <Bar dataKey="count" fill="#3b82f6" radius={[0, 2, 2, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Recent alerts */}
      <div className="bg-card border border-border rounded-lg">
        <div className="px-4 py-3 border-b border-border text-sm font-medium">
          Recent Alerts
        </div>
        {recent.length === 0 ? (
          <div className="p-6 text-center text-sm text-muted-foreground">
            No alerts yet.
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-muted-foreground text-left">
                <th className="px-4 py-2">Rule</th>
                <th className="px-4 py-2">Severity</th>
                <th className="px-4 py-2">Status</th>
                <th className="px-4 py-2">Triggered</th>
                <th className="px-4 py-2">Events</th>
              </tr>
            </thead>
            <tbody>
              {recent.map((alert) => (
                <tr
                  key={alert.alert_id}
                  className="border-b border-border hover:bg-muted/20 cursor-pointer transition-colors"
                  onClick={() => navigate("/alerts")}
                >
                  <td className="px-4 py-2">{alert.rule_name}</td>
                  <td className="px-4 py-2">
                    <SeverityPill severity={alert.severity} />
                  </td>
                  <td className="px-4 py-2">
                    <AlertBadge status={alert.status} />
                  </td>
                  <td className="px-4 py-2 text-muted-foreground text-xs">
                    {new Date(alert.triggered_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-2">{alert.event_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
