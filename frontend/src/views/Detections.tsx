/**
 * Detections.tsx — Detection rule CRUD interface.
 *
 * Slide-out Sheet for create/edit. Monaco editor for the query field —
 * language matches the rule's declared language. Test button executes
 * the rule against the last 24h of stored data inline.
 */

import { useEffect, useState } from "react";
import {
  createDetection,
  deleteDetection,
  listDetections,
  patchDetection,
  testDetection,
  updateDetection,
} from "../api/client";
import type { IDetectionRule, IDetectionRuleCreate, IDetectionTestResult } from "../api/types";
import QueryEditor from "../components/QueryEditor";
import type { TQueryLanguage } from "../components/QueryEditor";
import SeverityPill from "../components/SeverityPill";

const EMPTY_RULE: IDetectionRuleCreate = {
  name: "",
  description: "",
  severity: "medium",
  language: "kql",
  query: `DeviceProcessEvents\n| where Timestamp > ago(1h)\n| limit 10`,
  tags: [],
  mde_portable: false,
  enabled: true,
  author: "fried-plantains",
  false_positive_notes: "",
};

export default function Detections() {
  const [rules, setRules] = useState<IDetectionRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [sheetOpen, setSheetOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<IDetectionRuleCreate>(EMPTY_RULE);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<IDetectionTestResult | null>(null);
  const [testingId, setTestingId] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      const data = await listDetections();
      setRules(data);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const openCreate = () => {
    setEditingId(null);
    setForm(EMPTY_RULE);
    setSaveError(null);
    setTestResult(null);
    setSheetOpen(true);
  };

  const openEdit = (rule: IDetectionRule) => {
    setEditingId(rule.id);
    setForm({
      name: rule.name,
      description: rule.description,
      severity: rule.severity,
      language: rule.language,
      query: rule.query,
      tags: rule.tags,
      mde_portable: rule.mde_portable,
      enabled: rule.enabled,
      author: rule.author,
      false_positive_notes: rule.false_positive_notes,
    });
    setSaveError(null);
    setTestResult(null);
    setSheetOpen(true);
  };

  const handleSave = async () => {
    setSaveError(null);
    try {
      if (editingId) {
        await updateDetection(editingId, form);
      } else {
        await createDetection(form);
      }
      setSheetOpen(false);
      await load();
    } catch (err: unknown) {
      const detail =
        (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
        "Save failed.";
      setSaveError(detail);
    }
  };

  const handleToggle = async (rule: IDetectionRule) => {
    await patchDetection(rule.id, { enabled: !rule.enabled });
    await load();
  };

  const handleDelete = async (id: string) => {
    if (!confirm(`Archive rule ${id}?`)) return;
    await deleteDetection(id);
    await load();
  };

  const handleTest = async (id: string) => {
    setTestingId(id);
    setTestResult(null);
    try {
      const result = await testDetection(id);
      setTestResult(result);
    } catch {
      setTestResult({ rule_id: id, match_count: -1, sample_rows: [], duration_ms: 0 });
    } finally {
      setTestingId(null);
    }
  };

  const LANG_BADGE: Record<string, string> = {
    kql: "bg-blue-900/60 text-blue-300",
    spl: "bg-green-900/60 text-green-300",
    sql: "bg-purple-900/60 text-purple-300",
  };

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-bold">Detection Rules</h1>
        <button
          onClick={openCreate}
          className="bg-primary text-primary-foreground px-4 py-2 rounded text-sm font-medium hover:bg-primary/90 transition-colors"
        >
          + New Rule
        </button>
      </div>

      {loading ? (
        <div className="text-muted-foreground text-sm">Loading rules...</div>
      ) : (
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-muted-foreground text-left">
              <th className="pb-2 pr-4">ID</th>
              <th className="pb-2 pr-4">Name</th>
              <th className="pb-2 pr-4">Lang</th>
              <th className="pb-2 pr-4">Severity</th>
              <th className="pb-2 pr-4">Enabled</th>
              <th className="pb-2">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {rules.map((rule) => (
              <tr key={rule.id} className="hover:bg-muted/30 transition-colors">
                <td className="py-3 pr-4 font-mono text-xs text-muted-foreground">{rule.id}</td>
                <td className="py-3 pr-4">
                  <div>{rule.name}</div>
                  {rule.mde_portable && (
                    <span className="text-xs text-primary">MDE portable</span>
                  )}
                </td>
                <td className="py-3 pr-4">
                  <span className={`px-2 py-0.5 rounded text-xs font-medium ${LANG_BADGE[rule.language] ?? ""}`}>
                    {rule.language.toUpperCase()}
                  </span>
                </td>
                <td className="py-3 pr-4">
                  <SeverityPill severity={rule.severity} />
                </td>
                <td className="py-3 pr-4">
                  <button
                    onClick={() => handleToggle(rule)}
                    className={`w-10 h-5 rounded-full transition-colors ${
                      rule.enabled ? "bg-primary" : "bg-muted"
                    }`}
                  >
                    <span className={`block w-4 h-4 rounded-full bg-white mx-0.5 transition-transform ${
                      rule.enabled ? "translate-x-5" : "translate-x-0"
                    }`} />
                  </button>
                </td>
                <td className="py-3">
                  <div className="flex gap-2">
                    <button
                      onClick={() => handleTest(rule.id)}
                      disabled={testingId === rule.id}
                      className="text-xs text-muted-foreground hover:text-foreground transition-colors"
                    >
                      {testingId === rule.id ? "Testing..." : "Test"}
                    </button>
                    <button
                      onClick={() => openEdit(rule)}
                      className="text-xs text-muted-foreground hover:text-foreground transition-colors"
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => handleDelete(rule.id)}
                      className="text-xs text-destructive hover:text-destructive/80 transition-colors"
                    >
                      Archive
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {/* Test result */}
      {testResult && (
        <div className="mt-4 p-4 bg-card border border-border rounded-lg">
          <div className="text-sm font-medium mb-2">
            Rule {testResult.rule_id} test result — {testResult.match_count === -1 ? "Error" : `${testResult.match_count} matches`}
          </div>
          {testResult.sample_rows.length > 0 && (
            <pre className="text-xs text-muted-foreground overflow-auto max-h-40">
              {JSON.stringify(testResult.sample_rows[0], null, 2)}
            </pre>
          )}
        </div>
      )}

      {/* Create/Edit Sheet */}
      {sheetOpen && (
        <div className="fixed inset-0 z-50 flex justify-end">
          <div className="absolute inset-0 bg-black/60" onClick={() => setSheetOpen(false)} />
          <div className="relative w-full max-w-2xl bg-card border-l border-border overflow-y-auto p-6 space-y-4">
            <h2 className="text-lg font-bold">{editingId ? `Edit ${editingId}` : "New Detection Rule"}</h2>

            <div className="space-y-1">
              <label className="text-xs text-muted-foreground">Name</label>
              <input
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                className="w-full bg-input border border-border rounded px-3 py-2 text-sm"
              />
            </div>

            <div className="space-y-1">
              <label className="text-xs text-muted-foreground">Description</label>
              <textarea
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                rows={3}
                className="w-full bg-input border border-border rounded px-3 py-2 text-sm resize-none"
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1">
                <label className="text-xs text-muted-foreground">Severity</label>
                <select
                  value={form.severity}
                  onChange={(e) => setForm({ ...form, severity: e.target.value })}
                  className="w-full bg-input border border-border rounded px-3 py-2 text-sm"
                >
                  {["info", "low", "medium", "high", "critical"].map((s) => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </select>
              </div>

              <div className="space-y-1">
                <label className="text-xs text-muted-foreground">Language</label>
                <select
                  value={form.language}
                  onChange={(e) => setForm({ ...form, language: e.target.value })}
                  className="w-full bg-input border border-border rounded px-3 py-2 text-sm"
                >
                  {["kql", "spl", "sql"].map((l) => (
                    <option key={l} value={l}>{l.toUpperCase()}</option>
                  ))}
                </select>
              </div>
            </div>

            <div className="space-y-1">
              <label className="text-xs text-muted-foreground">Query</label>
              <div className="border border-border rounded overflow-hidden">
                <QueryEditor
                  language={form.language as TQueryLanguage}
                  value={form.query}
                  onChange={(v) => setForm({ ...form, query: v })}
                  height="200px"
                />
              </div>
            </div>

            <div className="space-y-1">
              <label className="text-xs text-muted-foreground">MITRE tags (comma-separated)</label>
              <input
                value={form.tags.join(", ")}
                onChange={(e) => setForm({ ...form, tags: e.target.value.split(",").map((t) => t.trim()).filter(Boolean) })}
                className="w-full bg-input border border-border rounded px-3 py-2 text-sm"
                placeholder="T1059.001, execution"
              />
            </div>

            <div className="flex items-center gap-3">
              <input
                type="checkbox"
                id="mde_portable"
                checked={form.mde_portable}
                onChange={(e) => setForm({ ...form, mde_portable: e.target.checked })}
              />
              <label htmlFor="mde_portable" className="text-sm">MDE portable (runs unchanged in real Sentinel/MDE)</label>
            </div>

            <div className="space-y-1">
              <label className="text-xs text-muted-foreground">False positive notes</label>
              <textarea
                value={form.false_positive_notes}
                onChange={(e) => setForm({ ...form, false_positive_notes: e.target.value })}
                rows={3}
                className="w-full bg-input border border-border rounded px-3 py-2 text-sm resize-none"
              />
            </div>

            {saveError && (
              <div className="bg-destructive/20 border border-destructive/50 rounded p-3 text-sm text-destructive-foreground">
                {saveError}
              </div>
            )}

            <div className="flex gap-3">
              <button
                onClick={handleSave}
                className="bg-primary text-primary-foreground px-4 py-2 rounded text-sm font-medium hover:bg-primary/90 transition-colors"
              >
                Save
              </button>
              <button
                onClick={() => setSheetOpen(false)}
                className="bg-muted text-foreground px-4 py-2 rounded text-sm hover:bg-muted/80 transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
