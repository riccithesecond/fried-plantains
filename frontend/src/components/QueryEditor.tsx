/**
 * QueryEditor.tsx — Monaco Editor wrapper with full KQL Monarch grammar.
 *
 * Queries are NEVER executed client-side. The editor is display-only —
 * Run sends the query to the backend for transpilation and execution.
 * Monaco's eval() / executeScript() paths are never invoked.
 *
 * KQL grammar features:
 *   - Teal:   MDE table names (DeviceProcessEvents, etc.)
 *   - Blue:   Pipeline operators (where, project, summarize, etc.)
 *   - Yellow: Functions (ago, bin, count, toupper, etc.)
 *   - Purple: String operators (contains, startswith, has, matches, etc.)
 *   - Orange: String literals
 *   - Green:  // line comments
 *   - White:  Identifiers (column names, variables)
 *
 * Context-aware autocomplete: after a table name, columns for that table
 * are offered. Pipe position offers pipeline operators. Global offers tables.
 */

import Editor, { OnMount } from "@monaco-editor/react";
import type * as Monaco from "monaco-editor";
import { forwardRef, useEffect, useImperativeHandle, useRef } from "react";

export type TQueryLanguage = "kql" | "spl" | "sql";

interface IQueryEditorProps {
  language: TQueryLanguage;
  value: string;
  onChange: (value: string) => void;
  height?: string;
  readOnly?: boolean;
}

export interface IQueryEditorRef {
  highlightLine: (lineNumber: number) => void;
}

// ---------------------------------------------------------------------------
// KQL token constants — typed for Monaco Monarch state machine
// ---------------------------------------------------------------------------

const KQL_TABLE_NAMES: readonly string[] = [
  "DeviceProcessEvents",
  "DeviceNetworkEvents",
  "DeviceFileEvents",
  "DeviceRegistryEvents",
  "DeviceLogonEvents",
  "DeviceEvents",
  "DeviceAlertEvents",
  "IdentityLogonEvents",
  "CloudAppEvents",
];

// Pipeline stage operators
const KQL_PIPELINE_OPERATORS: readonly string[] = [
  "where",
  "project",
  "project-away",
  "extend",
  "summarize",
  "order",
  "sort",
  "top",
  "limit",
  "take",
  "distinct",
  "join",
  "union",
  "let",
  "render",
  "mv-expand",
];

// Functions — highlighted in yellow
const KQL_FUNCTIONS: readonly string[] = [
  "ago",
  "bin",
  "count",
  "dcount",
  "sum",
  "avg",
  "min",
  "max",
  "toupper",
  "tolower",
  "tostring",
  "toint",
  "tolong",
  "strcat",
  "split",
  "parse_json",
  "has_any",
  "isempty",
  "isnotempty",
  "now",
  "datetime",
  "format_datetime",
  "startofday",
  "startofweek",
  "startofmonth",
];

// String/predicate operators — highlighted in purple
const KQL_OPERATORS: readonly string[] = [
  "contains",
  "startswith",
  "endswith",
  "has",
  "matches",
  "regex",
  "in",
  "between",
  "and",
  "or",
  "not",
  "by",
  "asc",
  "desc",
  "kind",
  "on",
  "inner",
  "leftouter",
  "leftanti",
  "true",
  "false",
  "null",
];

// Join kind values
const KQL_JOIN_KINDS: readonly string[] = [
  "inner",
  "leftouter",
  "leftanti",
  "rightouter",
  "fullouter",
  "leftsemi",
  "rightsemi",
  "innerunique",
];

// ---------------------------------------------------------------------------
// Per-table column completions for context-aware autocomplete
// ---------------------------------------------------------------------------

type TMdeTableColumns = Record<string, readonly string[]>;

const MDE_TABLE_COLUMNS: TMdeTableColumns = {
  DeviceProcessEvents: [
    "Timestamp", "DeviceId", "DeviceName", "ActionType", "FileName",
    "FolderPath", "SHA256", "MD5", "ProcessId", "ProcessCommandLine",
    "AccountDomain", "AccountName", "AccountSid", "LogonId",
    "InitiatingProcessId", "InitiatingProcessFileName",
    "InitiatingProcessCommandLine", "InitiatingProcessParentFileName",
    "InitiatingProcessAccountName", "InitiatingProcessSHA256", "ReportId",
  ],
  DeviceNetworkEvents: [
    "Timestamp", "DeviceId", "DeviceName", "ActionType",
    "RemoteIP", "RemotePort", "RemoteUrl", "LocalIP", "LocalPort",
    "Protocol", "InitiatingProcessFileName", "InitiatingProcessCommandLine",
    "InitiatingProcessAccountName", "InitiatingProcessId",
    "InitiatingProcessSHA256", "ReportId",
  ],
  DeviceFileEvents: [
    "Timestamp", "DeviceId", "DeviceName", "ActionType",
    "FileName", "FolderPath", "SHA256", "MD5", "FileSize",
    "InitiatingProcessFileName", "InitiatingProcessCommandLine",
    "InitiatingProcessAccountName", "InitiatingProcessId",
    "InitiatingProcessSHA256", "ReportId",
  ],
  DeviceRegistryEvents: [
    "Timestamp", "DeviceId", "DeviceName", "ActionType",
    "RegistryKey", "RegistryValueName", "RegistryValueData",
    "InitiatingProcessFileName", "InitiatingProcessCommandLine",
    "InitiatingProcessAccountName", "InitiatingProcessId", "ReportId",
  ],
  DeviceLogonEvents: [
    "Timestamp", "DeviceId", "DeviceName", "ActionType",
    "AccountDomain", "AccountName", "AccountSid",
    "LogonType", "LogonTypeName", "IsLocalAdmin",
    "FailureReason", "RemoteIP", "RemoteDeviceName", "ReportId",
  ],
  DeviceEvents: [
    "Timestamp", "DeviceId", "DeviceName", "ActionType",
    "FileName", "FolderPath", "SHA256", "ProcessCommandLine", "AccountName",
    "AdditionalFields", "InitiatingProcessFileName",
    "InitiatingProcessCommandLine", "InitiatingProcessAccountName",
    "InitiatingProcessId", "ReportId",
  ],
  DeviceAlertEvents: [
    "Timestamp", "DeviceId", "DeviceName", "AlertId", "Title", "Severity",
    "ServiceSource", "DetectionSource", "AttackTechniques", "ReportId",
  ],
  IdentityLogonEvents: [
    "Timestamp", "AccountUpn", "AccountObjectId", "AccountDisplayName",
    "AccountDomain", "DeviceName", "IPAddress", "Port",
    "DestinationDeviceName", "DestinationIPAddress", "DestinationPort",
    "Protocol", "FailureReason", "LogonType", "ActionType",
    "Application", "ReportId",
  ],
  CloudAppEvents: [
    "Timestamp", "Application", "ActionType", "AccountObjectId",
    "AccountDisplayName", "AccountDomain", "IPAddress",
    "CountryCode", "City", "ISP", "DeviceType", "OSPlatform",
    "AdditionalFields", "ReportId",
  ],
};

// ---------------------------------------------------------------------------
// Custom kql-dark theme
// ---------------------------------------------------------------------------

const KQL_THEME_RULES: Monaco.editor.ITokenThemeRule[] = [
  // Table names — teal
  { token: "type.identifier.kql", foreground: "4EC9B0", fontStyle: "bold" },
  // Pipeline operators — blue
  { token: "keyword.kql", foreground: "569CD6", fontStyle: "bold" },
  // Functions — yellow
  { token: "support.function.kql", foreground: "DCDCAA" },
  // String/predicate operators — purple
  { token: "keyword.operator.kql", foreground: "C586C0" },
  // String literals — orange
  { token: "string.kql", foreground: "CE9178" },
  // Numbers — light green
  { token: "number.kql", foreground: "B5CEA8" },
  // Comments — dark green
  { token: "comment.kql", foreground: "6A9955", fontStyle: "italic" },
  // Operators (=, !=, =~, |, etc.) — grey-white
  { token: "operator.kql", foreground: "D4D4D4" },
  // Identifiers / column names — white
  { token: "identifier.kql", foreground: "9CDCFE" },
  // Delimiters
  { token: "delimiter.kql", foreground: "D4D4D4" },
];

// ---------------------------------------------------------------------------
// Monarch grammar definition
// ---------------------------------------------------------------------------

function buildKqlMonarchLanguage(monaco: typeof Monaco): Monaco.languages.IMonarchLanguage {
  return {
    tables: KQL_TABLE_NAMES as string[],
    pipelineOps: KQL_PIPELINE_OPERATORS as string[],
    functions: KQL_FUNCTIONS as string[],
    operators: KQL_OPERATORS as string[],

    tokenizer: {
      root: [
        // Line comments
        [/\/\/.*$/, "comment.kql"],

        // Numbers (plain and with duration suffix: 7d, 1h, 30m, 60s, 500ms)
        [/\d+(\.\d+)?(ms|[dhms])\b/, "number.kql"],
        [/\d+(\.\d+)?/, "number.kql"],

        // Strings — double and single quoted
        [/"([^"\\]|\\.)*$/, "string.invalid.kql"],
        [/"/, "string.kql", "@string_double"],
        [/'([^'\\]|\\.)*$/, "string.invalid.kql"],
        [/'/, "string.kql", "@string_single"],

        // Pipe operator — structural delimiter
        [/\|/, "operator.kql"],

        // Operators: =~, !=~, !~, !=, ==, =, <, <=, >, >=, !
        [/=~|!=~|!~|!=|==|=|<=|>=|<|>|!/, "operator.kql"],

        // Delimiters
        [/[(),.;[\]]/, "delimiter.kql"],

        // Identifiers and keywords — match with word boundary
        [
          /[A-Za-z_][\w-]*/,
          {
            cases: {
              "@tables": "type.identifier.kql",
              "@pipelineOps": "keyword.kql",
              "@functions": "support.function.kql",
              "@operators": "keyword.operator.kql",
              "@default": "identifier.kql",
            },
          },
        ],

        // Whitespace
        [/\s+/, "white"],
      ],

      string_double: [
        [/[^\\"]+/, "string.kql"],
        [/\\./, "string.escape.kql"],
        [/"/, "string.kql", "@pop"],
      ],

      string_single: [
        [/[^\\']+/, "string.kql"],
        [/\\./, "string.escape.kql"],
        [/'/, "string.kql", "@pop"],
      ],
    },
  };
}

// ---------------------------------------------------------------------------
// Context-aware completion provider
// ---------------------------------------------------------------------------

function createKqlCompletionProvider(
  monaco: typeof Monaco
): Monaco.languages.CompletionItemProvider {
  return {
    provideCompletionItems(
      model: Monaco.editor.ITextModel,
      position: Monaco.Position
    ): Monaco.languages.CompletionList {
      const textUntilCursor = model.getValueInRange({
        startLineNumber: 1,
        startColumn: 1,
        endLineNumber: position.lineNumber,
        endColumn: position.column,
      });

      const word = model.getWordUntilPosition(position);
      const range: Monaco.IRange = {
        startLineNumber: position.lineNumber,
        endLineNumber: position.lineNumber,
        startColumn: word.startColumn,
        endColumn: word.endColumn,
      };

      const suggestions: Monaco.languages.CompletionItem[] = [];

      // Detect if we're after a pipe — offer pipeline operators
      const afterPipe = /\|\s*\w*$/.test(textUntilCursor);
      if (afterPipe) {
        KQL_PIPELINE_OPERATORS.forEach((op) => {
          suggestions.push({
            label: op,
            kind: monaco.languages.CompletionItemKind.Keyword,
            insertText: op,
            detail: "pipeline operator",
            range,
          });
        });
      }

      // Detect which table is in scope — offer its columns
      const tableMatch = textUntilCursor.match(
        /\b(DeviceProcessEvents|DeviceNetworkEvents|DeviceFileEvents|DeviceRegistryEvents|DeviceLogonEvents|DeviceEvents|DeviceAlertEvents|IdentityLogonEvents|CloudAppEvents)\b/
      );
      if (tableMatch) {
        const tableName = tableMatch[1];
        const cols = MDE_TABLE_COLUMNS[tableName] ?? [];
        cols.forEach((col) => {
          suggestions.push({
            label: col,
            kind: monaco.languages.CompletionItemKind.Field,
            insertText: col,
            detail: `${tableName} column`,
            range,
          });
        });
      }

      // Always offer table names (at start of query or after let =)
      KQL_TABLE_NAMES.forEach((t) => {
        suggestions.push({
          label: t,
          kind: monaco.languages.CompletionItemKind.Class,
          insertText: t,
          detail: "MDE table",
          range,
        });
      });

      // Functions
      KQL_FUNCTIONS.forEach((fn) => {
        suggestions.push({
          label: fn,
          kind: monaco.languages.CompletionItemKind.Function,
          insertText: `${fn}(`,
          detail: "KQL function",
          range,
        });
      });

      return { suggestions };
    },
  };
}

// ---------------------------------------------------------------------------
// Language registration — idempotent via guard flag
// ---------------------------------------------------------------------------

let kqlRegistered = false;

function registerKqlLanguage(monaco: typeof Monaco): void {
  if (kqlRegistered) return;
  kqlRegistered = true;

  monaco.languages.register({ id: "kql" });

  monaco.languages.setMonarchTokensProvider("kql", buildKqlMonarchLanguage(monaco));

  monaco.editor.defineTheme("kql-dark", {
    base: "vs-dark",
    inherit: true,
    rules: KQL_THEME_RULES,
    colors: {
      "editor.background": "#1E1E1E",
      "editor.foreground": "#D4D4D4",
      "editorLineNumber.foreground": "#858585",
      "editor.selectionBackground": "#264F78",
      "editor.inactiveSelectionBackground": "#3A3D41",
    },
  });

  monaco.languages.registerCompletionItemProvider("kql", createKqlCompletionProvider(monaco));
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

const QueryEditor = forwardRef<IQueryEditorRef, IQueryEditorProps>(
  ({ language, value, onChange, height = "40vh", readOnly = false }, ref) => {
    const editorRef = useRef<Monaco.editor.IStandaloneCodeEditor | null>(null);
    const monacoRef = useRef<typeof Monaco | null>(null);

    useImperativeHandle(ref, () => ({
      highlightLine: (lineNumber: number) => {
        const editor = editorRef.current;
        if (!editor || !monacoRef.current) return;
        const monaco = monacoRef.current;
        editor.deltaDecorations([], [
          {
            range: new monaco.Range(lineNumber, 1, lineNumber, 1),
            options: {
              isWholeLine: true,
              className: "bg-destructive/30",
              glyphMarginClassName: "bg-destructive",
            },
          },
        ]);
        editor.revealLine(lineNumber);
      },
    }));

    const handleEditorMount: OnMount = (editor, monaco) => {
      editorRef.current = editor;
      monacoRef.current = monaco;

      if (language === "kql") {
        registerKqlLanguage(monaco);
        monaco.editor.setTheme("kql-dark");
      }
    };

    // Switch language without remounting — preserves cursor and undo history
    useEffect(() => {
      const editor = editorRef.current;
      const monaco = monacoRef.current;
      if (!editor || !monaco) return;

      const model = editor.getModel();
      if (!model) return;

      if (language === "kql") {
        registerKqlLanguage(monaco);
        monaco.editor.setModelLanguage(model, "kql");
        monaco.editor.setTheme("kql-dark");
      } else if (language === "spl") {
        monaco.editor.setModelLanguage(model, "plaintext");
        monaco.editor.setTheme("vs-dark");
      } else {
        monaco.editor.setModelLanguage(model, "sql");
        monaco.editor.setTheme("vs-dark");
      }
    }, [language]);

    const monacoLanguage =
      language === "kql" ? "kql" : language === "sql" ? "sql" : "plaintext";

    return (
      <Editor
        height={height}
        language={monacoLanguage}
        value={value}
        theme={language === "kql" ? "kql-dark" : "vs-dark"}
        options={{
          minimap: { enabled: false },
          lineNumbers: "on",
          wordWrap: "on",
          readOnly,
          fontSize: 13,
          fontFamily: "'Cascadia Code', 'JetBrains Mono', Consolas, monospace",
          scrollBeyondLastLine: false,
          automaticLayout: true,
          suggestOnTriggerCharacters: true,
          quickSuggestions: { other: true, comments: false, strings: false },
        }}
        onChange={(v) => onChange(v ?? "")}
        onMount={handleEditorMount}
      />
    );
  }
);

QueryEditor.displayName = "QueryEditor";
export default QueryEditor;
