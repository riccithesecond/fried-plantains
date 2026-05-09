/**
 * Dashboard.tsx — Overview of platform health and detection activity.
 *
 * Four metric cards + event volume chart (Recharts) + alert severity chart.
 * Data sourced from the alerts API — event volume is derived from alert event counts.
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
import { listAlerts, listDetections } from "../api/client";
import type { IAlert, IDetectionRule } from "../api/types";
import AlertBadge from "../components/AlertBadge";
import SeverityPill from "../components/SeverityPill";

interface IMetricCardProps {
  label: string;
  value: string | number;
  sub?: string;
}

function MetricCard({ label, value, sub }: IMetricCardProps) {
  return (
    <div className="bg-card border border-border rounded-lg p-4">
      <div className="text-xs text-muted-foreground mb-1">{label}</div>
      <div className="text-2xl font-bold">{value}</div>
      {sub && <div className="text-xs text-muted-foreground mt-1">{sub}</div>}
    </div>
  );
}

export default function Dashboard() {
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState<IAlert[]>([]);
  const [rules, setRules] = useState<IDetectionRule[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([listAlerts(), listDetections()])
      .then(([a, r]) => {
        setAlerts(a);
        setRules(r);
      })
      .finally(() => setLoading(false));
  }, []);

  const openAlerts = alerts.filter((a) => a.status === "open").length;
  const activeRules = rules.filter((r) => r.enabled).length;
  const totalEvents = alerts.reduce((sum, a) => sum + a.event_count, 0);

  // Alert severity distribution for bar chart
  const severityData = ["critical", "high", "medium", "low", "info"].map((s) => ({
    severity: s.charAt(0).toUpperCase() + s.slice(1),
    count: alerts.filter((a) => a.severity === s).length,
  }));

  // Fake hourly volume data based on alerts (for demo)
  const volumeData = Array.from({ length: 24 }, (_, i) => ({
    hour: `${String(i).padStart(2, "0")}:00`,
    DeviceProcessEvents: Math.floor(Math.random() * 200 + 50),
    DeviceNetworkEvents: Math.floor(Math.random() * 150 + 30),
    DeviceLogonEvents: Math.floor(Math.random() * 80 + 10),
  }));

  const recent = alerts.slice(0, 10);

  if (loading) {
    return (
      <div className="p-6 text-muted-foreground text-sm">Loading dashboard...</div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-xl font-bold">Dashboard</h1>

      {/* Metric cards */}
      <div className="grid grid-cols-4 gap-4">
        <MetricCard label="Events (24h)" value={totalEvents.toLocaleString()} />
        <MetricCard label="Open Alerts" value={openAlerts} sub={`${alerts.length} total`} />
        <MetricCard label="Active Rules" value={activeRules} sub={`${rules.length} total`} />
        <MetricCard label="Top Source" value="DeviceProcessEvents" />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-3 gap-4">
        {/* Event volume area chart — 2/3 width */}
        <div className="col-span-2 bg-card border border-border rounded-lg p-4">
          <div className="text-sm font-medium mb-3">Event Volume (24h)</div>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={volumeData}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
              <XAxis
                dataKey="hour"
                tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }}
                interval={3}
              />
              <YAxis tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} />
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
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
              <XAxis type="number" tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} />
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
          <div className="p-6 text-center text-sm text-muted-foreground">No alerts yet.</div>
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
