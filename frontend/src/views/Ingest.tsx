/**
 * Ingest.tsx — Drag-and-drop log file upload.
 *
 * Security: all filenames rendered to the DOM are sanitized with DOMPurify
 * before display. File content never touches the DOM — it goes to the API.
 */

import DOMPurify from "dompurify";
import { Upload } from "lucide-react";
import { useRef, useState } from "react";
import { uploadLogs } from "../api/client";
import type { IIngestResponse } from "../api/types";

const MDE_TABLES = [
  "DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents",
  "DeviceRegistryEvents", "DeviceLogonEvents", "DeviceEvents",
  "DeviceAlertEvents", "IdentityLogonEvents", "CloudAppEvents",
];

export default function Ingest() {
  const [dragging, setDragging] = useState(false);
  const [selectedTable, setSelectedTable] = useState("");
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState<IIngestResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) setSelectedFile(file);
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) setSelectedFile(file);
  };

  const handleUpload = async () => {
    if (!selectedFile) return;
    setUploading(true);
    setError(null);
    setResult(null);
    setProgress(30);

    try {
      const data = await uploadLogs(selectedFile, selectedTable || undefined);
      setProgress(100);
      setResult(data);
    } catch (err: unknown) {
      const detail =
        (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
        "Upload failed.";
      setError(detail);
    } finally {
      setUploading(false);
    }
  };

  const detectFormat = (file: File): string => {
    const name = file.name.toLowerCase();
    if (name.endsWith(".gz")) return "gzip";
    if (name.endsWith(".csv")) return "CSV";
    if (name.endsWith(".ndjson")) return "NDJSON";
    if (name.endsWith(".json")) return "JSON";
    return "Unknown";
  };

  return (
    <div className="p-6 space-y-6 max-w-2xl">
      <h1 className="text-xl font-bold">Log Ingest</h1>

      {/* Table selector */}
      <div className="space-y-1">
        <label className="text-sm text-muted-foreground">
          Target MDE table (optional — auto-detected if omitted)
        </label>
        <select
          value={selectedTable}
          onChange={(e) => setSelectedTable(e.target.value)}
          className="w-full bg-input border border-border rounded px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
        >
          <option value="">Auto-detect</option>
          {MDE_TABLES.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
      </div>

      {/* Drop zone */}
      <div
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        onClick={() => inputRef.current?.click()}
        className={`border-2 border-dashed rounded-lg p-10 text-center cursor-pointer transition-colors ${
          dragging
            ? "border-primary bg-primary/10"
            : "border-border hover:border-primary/50"
        }`}
      >
        <Upload size={32} className="mx-auto mb-3 text-muted-foreground" />
        <p className="text-sm text-muted-foreground">
          Drag and drop a log file here, or click to browse
        </p>
        <p className="text-xs text-muted-foreground mt-1">
          JSON · NDJSON · CSV · gzip — max 500MB
        </p>
        <input
          ref={inputRef}
          type="file"
          className="hidden"
          accept=".json,.ndjson,.csv,.gz,.log"
          onChange={handleFileSelect}
        />
      </div>

      {/* Selected file info */}
      {selectedFile && (
        <div className="bg-card border border-border rounded p-4 space-y-2">
          <div className="flex justify-between text-sm">
            <span
              className="font-medium"
              dangerouslySetInnerHTML={{
                __html: DOMPurify.sanitize(selectedFile.name),
              }}
            />
            <span className="text-muted-foreground">
              {detectFormat(selectedFile)}
            </span>
          </div>
          <div className="text-xs text-muted-foreground">
            {(selectedFile.size / 1024 / 1024).toFixed(2)} MB
          </div>
          <button
            onClick={handleUpload}
            disabled={uploading}
            className="w-full bg-primary text-primary-foreground py-2 rounded text-sm font-medium hover:bg-primary/90 disabled:opacity-50 transition-colors"
          >
            {uploading ? `Uploading... ${progress}%` : "Upload and ingest"}
          </button>
        </div>
      )}

      {/* Progress bar */}
      {uploading && (
        <div className="w-full bg-muted rounded-full h-1.5">
          <div
            className="bg-primary h-1.5 rounded-full transition-all duration-500"
            style={{ width: `${progress}%` }}
          />
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="bg-destructive/20 border border-destructive/50 rounded p-3 text-sm text-destructive-foreground">
          {error}
        </div>
      )}

      {/* Result */}
      {result && (
        <div className="bg-card border border-border rounded p-4 space-y-2">
          <div className="text-sm font-medium text-green-400">
            Ingest complete
          </div>
          <div className="grid grid-cols-2 gap-2 text-sm">
            <span className="text-muted-foreground">Table</span>
            <span>{Array.isArray(result.table) ? result.table.join(", ") : result.table}</span>
            <span className="text-muted-foreground">Events ingested</span>
            <span>{result.events_ingested.toLocaleString()}</span>
            <span className="text-muted-foreground">Duration</span>
            <span>{result.duration_ms}ms</span>
            {result.partition_path && (
              <>
                <span className="text-muted-foreground">Partition</span>
                <span className="text-xs font-mono break-all">{result.partition_path}</span>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
