/**
 * Workbench.tsx — Interactive query workbench.
 *
 * Monaco Editor + AG Grid result table. Queries are sent to backend for
 * transpilation and execution — Monaco is display-only, no local execution.
 *
 * Features:
 *   - Language selector (KQL | SPL | SQL)
 *   - Ctrl+Enter keyboard shortcut to execute
 *   - Line highlighting on transpiler errors with line/column context
 *   - CSV export of results
 */

import DOMPurify from "dompurify";
import { Download, Play } from "lucide-react";
import { useRef, useState } from "react";
import { executeQuery } from "../api/client";
import type { IColumnMeta } from "../api/types";
import LogTable from "../components/LogTable";
import QueryEditor, {
  IQueryEditorRef,
  TQueryLanguage,
} from "../components/QueryEditor";

const DEFAULT_QUERIES: Record<TQueryLanguage, string> = {
  kql: `DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName =~ "powershell.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp desc
| limit 100`,
  spl: `index=process | stats count by DeviceName | sort -count | head 20`,
  sql: `SELECT DeviceName, COUNT(*) as event_count
FROM DeviceProcessEvents
GROUP BY DeviceName
ORDER BY event_count DESC
LIMIT 20`,
};

export default function Workbench() {
  const [language, setLanguage] = useState<TQueryLanguage>("kql");
  const [query, setQuery] = useState(DEFAULT_QUERIES.kql);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [columns, setColumns] = useState<IColumnMeta[]>([]);
  const [rows, setRows] = useState<unknown[][]>([]);
  const [rowCount, setRowCount] = useState<number | null>(null);
  const [durationMs, setDurationMs] = useState<number | null>(null);
  const editorRef = useRef<IQueryEditorRef>(null);

  const handleRun = async () => {
    setError(null);
    setLoading(true);
    try {
      const result = await executeQuery(query, language, 1000);
      setColumns(result.columns);
      setRows(result.rows);
      setRowCount(result.count);
      setDurationMs(result.duration_ms);
    } catch (err: unknown) {
      const detail =
        (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
        "Query execution failed.";
      setError(detail);
      // Highlight error line if backend provides location
      const lineMatch = detail.match(/line (\d+)/i);
      if (lineMatch && editorRef.current) {
        editorRef.current.highlightLine(parseInt(lineMatch[1], 10));
      }
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.ctrlKey && e.key === "Enter") {
      handleRun();
    }
  };

  const handleLanguageChange = (lang: TQueryLanguage) => {
    setLanguage(lang);
    setQuery(DEFAULT_QUERIES[lang]);
    setColumns([]);
    setRows([]);
    setError(null);
  };

  const handleExportCsv = () => {
    if (!columns.length || !rows.length) return;
    const header = columns.map((c) => c.name).join(",");
    const csvRows = rows.map((row) =>
      row.map((v) => `"${String(v ?? "").replace(/"/g, '""')}"`).join(",")
    );
    const csv = [header, ...csvRows].join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `query_results_${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="p-6 space-y-4" onKeyDown={handleKeyDown}>
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold">Query Workbench</h1>
        <div className="flex items-center gap-2">
          {/* Language selector */}
          {(["kql", "spl", "sql"] as TQueryLanguage[]).map((lang) => (
            <button
              key={lang}
              onClick={() => handleLanguageChange(lang)}
              className={`px-3 py-1.5 rounded text-xs font-medium uppercase transition-colors ${
                language === lang
                  ? "bg-primary text-primary-foreground"
                  : "bg-muted text-muted-foreground hover:text-foreground"
              }`}
            >
              {lang}
            </button>
          ))}
        </div>
      </div>

      {/* Editor */}
      <div className="border border-border rounded-lg overflow-hidden">
        <QueryEditor
          ref={editorRef}
          language={language}
          value={query}
          onChange={setQuery}
          height="40vh"
        />
      </div>

      {/* Controls */}
      <div className="flex items-center gap-3">
        <button
          onClick={handleRun}
          disabled={loading}
          className="flex items-center gap-2 bg-primary text-primary-foreground px-4 py-2 rounded text-sm font-medium hover:bg-primary/90 disabled:opacity-50 transition-colors"
        >
          <Play size={14} />
          {loading ? "Running..." : "Run (Ctrl+Enter)"}
        </button>

        {durationMs !== null && (
          <span className="text-xs text-muted-foreground">
            {rowCount} rows · {durationMs}ms
          </span>
        )}

        {rows.length > 0 && (
          <button
            onClick={handleExportCsv}
            className="flex items-center gap-2 text-xs text-muted-foreground hover:text-foreground transition-colors ml-auto"
          >
            <Download size={14} />
            Export CSV
          </button>
        )}
      </div>

      {/* Error */}
      {error && (
        <div
          className="bg-destructive/20 border border-destructive/50 rounded p-3 text-sm text-destructive-foreground"
          dangerouslySetInnerHTML={{
            __html: DOMPurify.sanitize(error),
          }}
        />
      )}

      {/* Results */}
      {rowCount === 0 && !loading && !error && (
        <div className="text-sm text-muted-foreground border border-border rounded p-6 text-center">
          Query returned 0 rows.
        </div>
      )}

      {columns.length > 0 && (
        <div>
          <div className="text-xs text-muted-foreground mb-2">
            {rowCount} rows · {columns.length} columns
          </div>
          <LogTable columns={columns} rows={rows} loading={loading} />
        </div>
      )}
    </div>
  );
}
