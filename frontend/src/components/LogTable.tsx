/**
 * LogTable.tsx — AG Grid wrapper for displaying query results.
 *
 * Uses virtual row model for performance with large result sets.
 * Type-aware cell renderers: timestamps as ISO 8601, booleans as checkmarks,
 * JSON columns with an expandable panel.
 */

import "ag-grid-community/styles/ag-grid.css";
import "ag-grid-community/styles/ag-theme-alpine.css";
import { AgGridReact } from "ag-grid-react";
import type { ColDef } from "ag-grid-community";
import { useMemo, useState } from "react";
import type { IColumnMeta } from "../api/types";

interface ILogTableProps {
  columns: IColumnMeta[];
  rows: unknown[][];
  loading: boolean;
}

function formatCellValue(value: unknown, type: string): string {
  if (value === null || value === undefined) return "";
  if (type === "boolean") return value ? "✓" : "✗";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

export default function LogTable({ columns, rows, loading }: ILogTableProps) {
  const [expandedJson, setExpandedJson] = useState<string | null>(null);

  const colDefs: ColDef[] = useMemo(
    () =>
      columns.map((col) => ({
        field: col.name,
        headerName: col.name,
        sortable: true,
        filter: true,
        resizable: true,
        minWidth: 100,
        flex: 1,
        valueFormatter: (params) => formatCellValue(params.value, col.type),
        cellRenderer:
          col.type === "unknown" || col.name === "AdditionalFields"
            ? (params: { value: unknown }) => {
                const str =
                  typeof params.value === "string"
                    ? params.value
                    : JSON.stringify(params.value);
                return (
                  <button
                    className="text-primary text-xs underline"
                    onClick={() => setExpandedJson(str)}
                  >
                    view
                  </button>
                );
              }
            : undefined,
      })),
    [columns]
  );

  const rowData = useMemo(
    () =>
      rows.map((row) => {
        const obj: Record<string, unknown> = {};
        columns.forEach((col, i) => {
          obj[col.name] = row[i];
        });
        return obj;
      }),
    [rows, columns]
  );

  if (loading) {
    return (
      <div className="flex items-center justify-center h-40 text-muted-foreground">
        <div className="animate-pulse">Executing query...</div>
      </div>
    );
  }

  if (columns.length === 0) {
    return null;
  }

  return (
    <div className="flex flex-col gap-2">
      <div
        className="ag-theme-alpine-dark w-full"
        style={{ height: "400px" }}
      >
        <AgGridReact
          columnDefs={colDefs}
          rowData={rowData}
          defaultColDef={{
            sortable: true,
            filter: true,
            resizable: true,
          }}
          animateRows={false}
          rowSelection="single"
        />
      </div>

      {/* JSON expansion panel */}
      {expandedJson && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-card border border-border rounded-lg p-4 max-w-2xl w-full max-h-[80vh] overflow-auto">
            <div className="flex justify-between items-center mb-2">
              <span className="text-sm font-medium">Field value</span>
              <button
                onClick={() => setExpandedJson(null)}
                className="text-muted-foreground hover:text-foreground"
              >
                ✕
              </button>
            </div>
            <pre className="text-xs text-foreground overflow-auto">
              {(() => {
                try {
                  return JSON.stringify(JSON.parse(expandedJson), null, 2);
                } catch {
                  return expandedJson;
                }
              })()}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
