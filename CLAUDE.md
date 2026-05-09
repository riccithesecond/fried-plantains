# fried-plantains — CLAUDE.md

## Project identity

fried-plantains is a custom-built SIEM and threat hunting platform designed as a learning
platform and portfolio builder. It runs on an Intel NUC using DuckDB and Parquet as the
query engine and core storage layer.

Designed to emulate major data lake and analytics platforms such as Microsoft Sentinel /
Microsoft Defender for Endpoint (KQL + MDE table schema), Splunk Enterprise Security (SPL),
and direct SQL analytics — at homelab scale. Parquet files can be processed and ingested
into ClickHouse, Snowflake, and Databricks without changing the detection logic. Only the
execution engine scales.

This project demonstrates detection engineering competency: log ingestion, normalization,
multi-language query support, MDE-compatible detection rule authoring, and alert triage —
all in a self-hosted, portable architecture. KQL detections written here must be valid and
portable to real Microsoft Sentinel and MDE environments.

---

## Stack (locked — do not suggest alternatives)

| Layer | Technology |
|---|---|
| Frontend framework | React + Vite |
| UI components | shadcn/ui + Tailwind CSS |
| Data tables | AG Grid (Community) |
| Charts | Recharts |
| Query editor | Monaco Editor |
| Backend | FastAPI (Python) |
| Query engine | DuckDB |
| Storage format | Apache Parquet (hive-style partitioning) |
| Detection rules | YAML schema |
| Auth | JWT (short expiry + refresh tokens) |
| Testing | pytest (backend), Vitest (frontend) |

---

## Repository structure

```
fried-plantains/
├── backend/
│   ├── main.py                  # FastAPI app entrypoint
│   ├── api/
│   │   ├── auth.py              # JWT auth endpoints
│   │   ├── ingest.py            # Log upload and normalization
│   │   ├── query.py             # Query execution endpoint
│   │   ├── detections.py        # Detection rule CRUD
│   │   └── alerts.py            # Alert retrieval and triage
│   ├── engine/
│   │   ├── duckdb_pool.py       # Serialized DuckDB connection pool
│   │   ├── kql_transpiler.py    # KQL → DuckDB SQL transpiler (MDE schema)
│   │   ├── spl_transpiler.py    # Splunk SPL → DuckDB SQL transpiler
│   │   ├── sql_transpiler.py    # SQL passthrough validator + executor
│   │   ├── query_router.py      # Routes query by language to correct transpiler
│   │   └── detection_runner.py  # Scheduled detection execution loop
│   ├── ingest/
│   │   ├── validator.py         # MIME + magic byte validation
│   │   ├── normalizer.py        # Log normalization to MDE-aligned table schemas
│   │   └── writer.py            # Atomic Parquet write (temp → rename)
│   ├── models/
│   │   ├── detection.py         # Detection rule Pydantic model
│   │   ├── alert.py             # Alert Pydantic model
│   │   └── user.py              # User Pydantic model
│   ├── parsers/                 # Per-source normalization schemas
│   │   ├── base_parser.py
│   │   ├── windows_event.py     # Windows Security/System/Application events
│   │   ├── cloudtrail.py        # AWS CloudTrail
│   │   ├── syslog.py            # RFC 5424 syslog
│   │   └── defender.py          # MDE raw JSON export format
│   ├── schema/
│   │   └── mde_tables.py        # Canonical MDE table definitions (source of truth)
│   └── tests/
│       ├── test_ingest.py
│       ├── test_kql_transpiler.py
│       ├── test_spl_transpiler.py
│       ├── test_sql_transpiler.py
│       ├── test_detections.py
│       └── test_auth.py
├── frontend/
│   ├── src/
│   │   ├── main.tsx
│   │   ├── App.tsx
│   │   ├── api/
│   │   │   └── client.ts        # Typed API client — no raw fetch() elsewhere
│   │   ├── views/
│   │   │   ├── Dashboard.tsx    # Event volume, alert trend, top sources
│   │   │   ├── Workbench.tsx    # Monaco editor + result table
│   │   │   ├── Detections.tsx   # Detection rule CRUD UI
│   │   │   ├── Alerts.tsx       # Alert feed and triage
│   │   │   ├── Ingest.tsx       # Drag-drop log upload
│   │   │   └── Settings.tsx
│   │   └── components/
│   │       ├── LogTable.tsx     # AG Grid wrapper
│   │       ├── AlertBadge.tsx
│   │       ├── QueryEditor.tsx  # Monaco wrapper with language switching
│   │       └── SeverityPill.tsx
│   └── vite.config.ts
├── storage/
│   └── {MdeTableName}/{year}/{month}/{day}/data.parquet
├── detections/
│   └── rules/                   # YAML detection rule files
├── scripts/
│   └── generate_logs.py         # AI-assisted synthetic log + attack scenario generator
├── .env.example
├── .gitignore                   # Must include .env, storage/, *.parquet
└── CLAUDE.md
```

---

## Query language support

fried-plantains supports three query languages in strict priority order. All queries are
sent to the backend, parsed, validated, and transpiled to DuckDB SQL before execution.
Never execute raw query strings against DuckDB without going through the transpiler and
validator.

### Supported languages — in priority order

| Priority | Language | Origin | Role in fried-plantains |
|---|---|---|---|
| 1 | KQL | Microsoft Sentinel / MDE / Azure Data Explorer | Primary. Must be MDE-schema-accurate and portable. |
| 2 | SPL | Splunk Enterprise / Splunk ES | Secondary. Core search commands. |
| 3 | SQL | ANSI SQL | Tertiary. Direct power-user access to DuckDB. |

### Future language additions (do not implement in MVP)

CQL (CrowdStrike Falcon Query Language), Sigma (rule format), YARA-L (Chronicle).
When these are added, they follow the same transpiler pattern established by KQL/SPL/SQL.

### Language abstraction rules

- The Monaco Editor supports language switching via a dropdown — never hardcode KQL
- Each language registers its own Monaco grammar and keyword completions
- `query_router.py` is the single dispatch point — add new languages there only
- Transpiler output is logged at DEBUG level (internal only, never exposed to the user)
- On parse failure: return a structured error with line/column info — never a raw exception
- Query timeouts are enforced at the DuckDB layer — default 30s, configurable via env
- Every transpiler exposes a `COVERAGE` dict documenting supported vs planned operators —
  this is a portfolio artifact showing engineering honesty and roadmap thinking

---

## KQL — MDE table schema (primary language, highest fidelity requirement)

KQL in fried-plantains must replicate Microsoft Defender for Endpoint's Advanced Hunting
table schema as closely as possible. Detections written here must be valid and portable to
real MDE/Sentinel environments with no or minimal modification.

### MDE tables to implement (defined in `backend/schema/mde_tables.py`)

Each table is a DuckDB view over the normalized Parquet storage layer.
Column names, types, and semantics must match MDE exactly.

#### DeviceProcessEvents
```
Timestamp                        TIMESTAMP
DeviceId                         STRING
DeviceName                       STRING
ActionType                       STRING      -- ProcessCreated, ProcessInjected
FileName                         STRING      -- Process image filename
FolderPath                       STRING
SHA256                           STRING
MD5                              STRING
ProcessId                        INT
ProcessCommandLine                STRING
AccountDomain                    STRING
AccountName                      STRING
AccountSid                       STRING
LogonId                          STRING
InitiatingProcessId              INT
InitiatingProcessFileName        STRING
InitiatingProcessCommandLine     STRING
InitiatingProcessParentFileName  STRING
InitiatingProcessAccountName     STRING
InitiatingProcessSHA256          STRING
ReportId                         STRING
```

#### DeviceNetworkEvents
```
Timestamp                        TIMESTAMP
DeviceId                         STRING
DeviceName                       STRING
ActionType                       STRING      -- ConnectionSuccess, ConnectionFailed, InboundConnectionAccepted
RemoteIP                         STRING
RemotePort                       INT
RemoteUrl                        STRING
LocalIP                          STRING
LocalPort                        INT
Protocol                         STRING
InitiatingProcessFileName        STRING
InitiatingProcessCommandLine     STRING
InitiatingProcessAccountName     STRING
InitiatingProcessId              INT
InitiatingProcessSHA256          STRING
ReportId                         STRING
```

#### DeviceFileEvents
```
Timestamp                        TIMESTAMP
DeviceId                         STRING
DeviceName                       STRING
ActionType                       STRING      -- FileCreated, FileModified, FileDeleted, FileRenamed
FileName                         STRING
FolderPath                       STRING
SHA256                           STRING
MD5                              STRING
FileSize                         BIGINT
InitiatingProcessFileName        STRING
InitiatingProcessCommandLine     STRING
InitiatingProcessAccountName     STRING
InitiatingProcessId              INT
InitiatingProcessSHA256          STRING
ReportId                         STRING
```

#### DeviceRegistryEvents
```
Timestamp                        TIMESTAMP
DeviceId                         STRING
DeviceName                       STRING
ActionType                       STRING      -- RegistryKeyCreated, RegistryValueSet, RegistryKeyDeleted
RegistryKey                      STRING
RegistryValueName                STRING
RegistryValueData                STRING
InitiatingProcessFileName        STRING
InitiatingProcessCommandLine     STRING
InitiatingProcessAccountName     STRING
InitiatingProcessId              INT
ReportId                         STRING
```

#### DeviceLogonEvents
```
Timestamp                        TIMESTAMP
DeviceId                         STRING
DeviceName                       STRING
ActionType                       STRING      -- LogonSuccess, LogonFailed, LogonAttempted
AccountDomain                    STRING
AccountName                      STRING
AccountSid                       STRING
LogonType                        INT         -- 2=Interactive, 3=Network, 10=RemoteInteractive
LogonTypeName                    STRING
IsLocalAdmin                     BOOLEAN
FailureReason                    STRING      -- nullable
RemoteIP                         STRING      -- nullable
RemoteDeviceName                 STRING      -- nullable
ReportId                         STRING
```

#### DeviceEvents
```
Timestamp                        TIMESTAMP
DeviceId                         STRING
DeviceName                       STRING
ActionType                       STRING      -- AntivirusDetection, PowerShellCommand, etc.
FileName                         STRING      -- nullable
FolderPath                       STRING      -- nullable
SHA256                           STRING      -- nullable
ProcessCommandLine                STRING      -- nullable
AccountName                      STRING      -- nullable
AdditionalFields                 JSON        -- ActionType-specific fields
InitiatingProcessFileName        STRING
InitiatingProcessCommandLine     STRING
InitiatingProcessAccountName     STRING
InitiatingProcessId              INT
ReportId                         STRING
```

#### DeviceAlertEvents
```
Timestamp                        TIMESTAMP
DeviceId                         STRING
DeviceName                       STRING
AlertId                          STRING
Title                            STRING
Severity                         STRING      -- Informational | Low | Medium | High
ServiceSource                    STRING      -- MDE, MDO, MDI, MCAS
DetectionSource                  STRING
AttackTechniques                 STRING[]    -- MITRE technique IDs
ReportId                         STRING
```

#### IdentityLogonEvents
```
Timestamp                        TIMESTAMP
AccountUpn                       STRING
AccountObjectId                  STRING
AccountDisplayName               STRING
AccountDomain                    STRING
DeviceName                       STRING      -- nullable
IPAddress                        STRING
Port                             INT
DestinationDeviceName            STRING      -- nullable
DestinationIPAddress             STRING      -- nullable
DestinationPort                  INT         -- nullable
Protocol                         STRING
FailureReason                    STRING      -- nullable
LogonType                        STRING
ActionType                       STRING      -- LogonSuccess, LogonFailed
Application                      STRING      -- nullable
ReportId                         STRING
```

#### CloudAppEvents
```
Timestamp                        TIMESTAMP
Application                      STRING      -- Microsoft Teams, SharePoint, Exchange, etc.
ActionType                       STRING
AccountObjectId                  STRING
AccountDisplayName               STRING
AccountDomain                    STRING
IPAddress                        STRING
CountryCode                      STRING      -- nullable
City                             STRING      -- nullable
ISP                              STRING      -- nullable
DeviceType                       STRING      -- nullable
OSPlatform                       STRING      -- nullable
AdditionalFields                 JSON
ReportId                         STRING
```

### KQL operator coverage (MVP minimum)

These operators must be correctly transpiled to DuckDB SQL:

| KQL operator | DuckDB SQL equivalent | Notes |
|---|---|---|
| `where` | `WHERE` | All comparison operators, string predicates |
| `project` | `SELECT` | Column selection and rename |
| `project-away` | `SELECT` (exclusion) | Select all except named columns |
| `extend` | `SELECT *, expr AS col` | Computed columns |
| `summarize` by | `GROUP BY` | With aggregation functions |
| `count()` | `COUNT(*)` | |
| `dcount()` | `COUNT(DISTINCT col)` | |
| `sum()` / `avg()` / `min()` / `max()` | Direct equivalents | |
| `bin(Timestamp, 1h)` | `date_trunc('hour', Timestamp)` | Time bucketing |
| `ago(7d)` | `NOW() - INTERVAL 7 DAY` | Relative to query execution time |
| `between` | `BETWEEN` | Inclusive range |
| `contains` | `LIKE '%val%'` | Case-insensitive in MDE — document the delta |
| `startswith` | `LIKE 'val%'` | |
| `endswith` | `LIKE '%val'` | |
| `has` | `LIKE '%val%'` (word-boundary approximation) | |
| `matches regex` | `regexp_matches()` | |
| `in` / `!in` | `IN` / `NOT IN` | |
| `has_any()` | Multiple `LIKE` with `OR` | |
| `isempty()` / `isnotempty()` | `IS NULL` / `IS NOT NULL` | |
| `toupper()` / `tolower()` | `UPPER()` / `LOWER()` | |
| `tostring()` | `CAST(x AS VARCHAR)` | |
| `toint()` / `tolong()` | `CAST(x AS INT)` / `CAST(x AS BIGINT)` | |
| `strcat()` | `CONCAT()` | |
| `split()` | `string_split()` | |
| `parse_json()` / `AdditionalFields.Key` | `json_extract()` | For JSON columns |
| `mv-expand` | `UNNEST()` | Array expansion |
| `join kind=inner` | `INNER JOIN` | |
| `join kind=leftouter` | `LEFT JOIN` | |
| `union` | `UNION ALL` | KQL union is UNION ALL by default |
| `let` | CTE (`WITH x AS (...)`) | |
| `top N by col` | `ORDER BY col DESC LIMIT N` | |
| `order by` / `sort by` | `ORDER BY` | |
| `distinct` | `SELECT DISTINCT` | |
| `limit` / `take` | `LIMIT` | |
| `=~` (case-insensitive equals) | `LOWER(a) = LOWER(b)` | MDE-specific operator |
| `!~` (case-insensitive not-equals) | `LOWER(a) != LOWER(b)` | |
| `render` | Chart type hint in response metadata | Not SQL — metadata only |

### KQL semantic accuracy requirements

- `Timestamp` is always UTC. Normalize all timestamps to UTC at ingest.
- Column names are case-sensitive in MDE. The transpiler must preserve case exactly —
  `DeviceName` is not `devicename`. Test this explicitly.
- `ago()` calculates relative to query execution time, not ingest time.
- `summarize count() by bin(Timestamp, 1h)` is the canonical log volume query — must work.
- `AdditionalFields.SomeKey` accessor syntax must transpile to `json_extract()`.
- `=~` case-insensitive comparison is MDE-standard — must be supported.
- Detection queries that run in real MDE must be testable here with synthetic data that
  matches MDE field names and value formats exactly.

---

## SPL — Splunk Processing Language (secondary language)

SPL is the second supported language, targeting Splunk Enterprise Security search commands
used in correlation searches and threat hunting.

### SPL operator coverage (MVP minimum)

| SPL command | DuckDB SQL equivalent |
|---|---|
| `search field=value` | `WHERE field = 'value'` |
| `where` | `WHERE` |
| `fields` | `SELECT` |
| `table` | `SELECT` (formatted output hint) |
| `stats count by field` | `SELECT COUNT(*), field GROUP BY field` |
| `stats count, sum(x) by field` | `SELECT COUNT(*), SUM(x), field GROUP BY field` |
| `eval new=expr` | `SELECT *, expr AS new` |
| `rename old AS new` | Column alias in SELECT |
| `sort by field` / `sort -field` | `ORDER BY field ASC/DESC` |
| `head N` / `tail N` | `LIMIT N` / bottom-N pattern |
| `dedup field` | `SELECT DISTINCT` or `ROW_NUMBER()` partition |
| `rex field=x "pattern"` | `regexp_extract()` |
| `index=name` | Maps to MDE table name (index → table) |
| `sourcetype=value` | `WHERE source = 'value'` |
| `earliest=-7d latest=now` | `WHERE Timestamp >= NOW() - INTERVAL 7 DAY` |
| `bin span=1h _time` | `date_trunc('hour', Timestamp)` |

SPL `index=` maps to MDE table equivalents where possible:
- `index=wineventlog` → `DeviceEvents` + `DeviceLogonEvents`
- `index=endpoint` → `DeviceProcessEvents`, `DeviceNetworkEvents`, etc.

---

## SQL — direct query (tertiary language)

SQL is ANSI SQL passed directly to DuckDB after validation. It is not transpiled —
it is validated and sanitized, then executed as-is against the DuckDB views.

### SQL validation requirements

- Parse the SQL AST before execution — reject anything that is not a `SELECT` statement
- Reject: `INSERT`, `UPDATE`, `DELETE`, `DROP`, `CREATE`, `ALTER`, `EXEC`, `PRAGMA`
- Reject: data exfiltration patterns (e.g. `INTO OUTFILE`)
- Validate that all table references exist in the registered DuckDB view schema
- Apply the same query timeout as KQL and SPL
- Return column metadata alongside results (name + inferred type)

SQL gives power users direct access to DuckDB's full capability: window functions, CTEs,
lateral joins, `json_extract()`, and cross-table analytics. Document this in the UI.

---

## Detection rule schema

Detection rules are data, not code. Never eval() or exec() a rule's query string.
All rules must pass schema validation before being stored or executed.

The example below uses a real MDE-portable KQL query — this is the standard to maintain.

```yaml
# Example rule — FP-0001
id: FP-0001
name: Suspicious PowerShell encoded command execution
description: >
  Detects base64-encoded PowerShell commands (-EncodedCommand) commonly used in
  living-off-the-land attacks and malware loaders.
severity: high          # info | low | medium | high | critical
language: kql           # kql | spl | sql
query: |
  DeviceProcessEvents
  | where Timestamp > ago(1h)
  | where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
  | where ProcessCommandLine contains "-EncodedCommand"
      or ProcessCommandLine contains "-enc "
      or ProcessCommandLine contains "-ec "
  | project Timestamp, DeviceName, AccountName, ProcessCommandLine,
            InitiatingProcessFileName, InitiatingProcessCommandLine
  | order by Timestamp desc
tags:
  - T1059.001
  - execution
  - defense-evasion
mde_portable: true       # true = query runs unchanged in real MDE/Sentinel
enabled: true
created_at: 2025-01-01T00:00:00Z
updated_at: 2025-01-01T00:00:00Z
author: fried-plantains
false_positive_notes: >
  May trigger on legitimate admin automation. Verify AccountName and
  InitiatingProcessFileName context before escalating.
```

Rule ID format: `FP-XXXX` (four zero-padded digits, auto-incremented).

The `mde_portable` flag: if `true`, the rule's KQL query must execute without modification
in Microsoft Sentinel or MDE Advanced Hunting. The test suite must validate that every
`mde_portable: true` rule uses only MDE-supported table names and column names as defined
in `backend/schema/mde_tables.py`.

---

## AI log generation (scripts/generate_logs.py)

fried-plantains uses an AI-assisted log generator to create realistic synthetic datasets
including benign baseline activity and embedded malicious scenarios. Generated logs must
conform to MDE table schemas exactly — field names, value formats, and ActionType
enumerations must match what real MDE produces. This portability is the point.

### Generator requirements

- Output JSON lines (raw) AND normalized Parquet partitioned by MDE table name
- Target MDE tables: DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents,
  DeviceLogonEvents, DeviceRegistryEvents, DeviceEvents
- ActionType values must come from the MDE enumeration for each table — no invented values
- Benign-to-malicious ratio configurable (default: 95% benign, 5% malicious)
- Timestamps must be realistic and sequential — no random time ordering
- Include a manifest per generated batch:
  - Which MITRE techniques were embedded
  - At which timestamps and in which table/rows
  - Which detection rule IDs (FP-XXXX) are expected to fire
  - Used for automated detection validation

### Attack scenarios to support

| Scenario | Tables involved | MITRE techniques |
|---|---|---|
| Brute force → credential success | DeviceLogonEvents | T1110, T1078 |
| Phishing → attachment → C2 | DeviceFileEvents, DeviceProcessEvents, DeviceNetworkEvents | T1566, T1059, T1071 |
| Insider threat: bulk off-hours access | DeviceFileEvents, DeviceLogonEvents | T1078, T1048 |
| LOLBin abuse | DeviceProcessEvents | T1218, T1059 |
| Encoded PowerShell | DeviceProcessEvents | T1059.001 |
| Lateral movement via PsExec | DeviceNetworkEvents, DeviceLogonEvents, DeviceProcessEvents | T1021, T1570 |
| Persistence via registry run key | DeviceRegistryEvents | T1547.001 |
| Credential dumping (LSASS access) | DeviceProcessEvents | T1003.001 |

---

## Coding standards

### General

- All code must be production-quality with comments explaining *why*, not just *what*
- No `TODO` or `FIXME` left in committed code — implement it or open a documented issue
- Prefer explicit over implicit — no framework magic without an explanatory comment
- All file paths use constants or environment variables — never hardcode absolute paths
- The goal is portfolio-grade code: a detection engineering hiring manager reads any file
  and immediately understands the design intent and security posture

### Security — apply to every file, no exceptions

- **Input validation**: validate and sanitize ALL user input before it touches the query
  engine, file system, or database. Use allowlists, not blocklists.
- **Query injection**: never interpolate raw user input into DuckDB queries. Always use
  parameterized queries after transpilation. The transpiler is a security boundary — log
  and reject anything that fails to parse cleanly.
- **File upload safety**: validate MIME type AND magic bytes (not just file extension) on
  every upload. Enforce configurable max file size (default: 500MB). Store uploaded files
  in an isolated directory outside the web root. Never execute or eval uploaded content.
- **Path traversal**: normalize all file paths. Reject any path that resolves outside the
  designated storage root. Use `pathlib.Path` + `.is_relative_to()`. No exceptions.
- **Auth**: every API endpoint requires JWT authentication unless explicitly marked `public`.
  Short expiry (15 min) + refresh tokens. Never log tokens, secrets, or PII.
- **Secrets**: all credentials and connection strings live in `.env` (gitignored).
  Never commit secrets. Use `python-dotenv`. Reference via env vars only.
- **CORS**: lock CORS to the specific frontend origin. No wildcard `*` ever.
- **Rate limiting**: apply rate limiting to ingestion and query execution endpoints.
- **Error messages**: never expose stack traces, file paths, or internal errors to the
  frontend. Log internally; return generic messages to the client.
- **Dependencies**: run `pip-audit` and `npm audit` before adding any new dependency.
  Pin all versions.
- **CSP headers**: set Content-Security-Policy headers. Start in report-only mode.

### Backend (FastAPI / Python)

- Use `async` throughout — no blocking I/O on the main thread
- DuckDB connections are not thread-safe — always use the serialized connection pool in
  `engine/duckdb_pool.py`. Never instantiate a DuckDB connection directly in a route.
- All Parquet writes must be atomic: write to `.tmp`, then `os.rename()`.
- Detection rule execution is sandboxed — rules define queries, not code.
- Log all detection matches with: timestamp, rule_id, severity, raw_event_hash (SHA-256)
- Query timeouts enforced at DuckDB layer — kill any query exceeding `QUERY_TIMEOUT_SECONDS`
- Use Pydantic models for all request/response validation — no raw dict access in routes
- Custom exception hierarchy in `backend/exceptions.py`

### Frontend (React / TypeScript)

- Strict TypeScript throughout — no `any` without a documented justification comment
- All API calls go through `src/api/client.ts` — no raw `fetch()` in components
- Monaco Editor: queries sent to backend for execution — never run client-side
- Sanitize all log content rendered to the DOM with DOMPurify
- No sensitive data in `localStorage` — httpOnly cookies or in-memory state only
- All components have explicit typed prop interfaces

### Testing

Security tests are not optional:

- Input validation (valid and invalid for every endpoint)
- Path traversal attempts on upload and storage endpoints
- Query injection attempts through KQL, SPL, and SQL transpilers/validators
- KQL column name case-sensitivity (`DeviceName` ≠ `devicename`)
- `mde_portable: true` rules validated against `backend/schema/mde_tables.py`
- File upload rejection: wrong MIME, oversized, bad magic bytes
- Detection rule schema validation
- Alert generation from a known synthetic log + rule combination
- JWT auth: expired tokens, tampered tokens, missing header
- DuckDB connection pool under concurrent requests
- `ago()` resolves against query execution time, not ingest time
- `bin(Timestamp, 1h)` produces correct DuckDB SQL

---

## Naming conventions

| Context | Convention |
|---|---|
| Source files | `kebab-case` |
| Python functions / variables | `snake_case` |
| Python classes | `PascalCase` |
| TypeScript functions / variables | `camelCase` |
| React components | `PascalCase` |
| TypeScript interfaces / types | `PascalCase` prefixed with `I` or `T` |
| Detection rule IDs | `FP-XXXX` (four-digit, zero-padded, auto-incremented) |
| Parquet partition path | `storage/{MdeTableName}/{year}/{month}/{day}/data.parquet` |
| Environment variables | `SCREAMING_SNAKE_CASE` |
| MDE table names | Exact MDE casing — `DeviceProcessEvents`, not `device_process_events` |

---

## Parquet storage model

Data is partitioned by MDE table name, not by a generic normalized schema. Each MDE table
is a separate Parquet partition tree. This is what makes KQL queries natural — the table
name in a KQL query maps directly to a DuckDB view over the corresponding Parquet files.

```
storage/
├── DeviceProcessEvents/2025/01/15/data.parquet
├── DeviceNetworkEvents/2025/01/15/data.parquet
├── DeviceFileEvents/2025/01/15/data.parquet
├── DeviceLogonEvents/2025/01/15/data.parquet
├── DeviceRegistryEvents/2025/01/15/data.parquet
├── DeviceEvents/2025/01/15/data.parquet
├── IdentityLogonEvents/2025/01/15/data.parquet
└── CloudAppEvents/2025/01/15/data.parquet
```

DuckDB views are registered at startup for each table:
```sql
CREATE OR REPLACE VIEW DeviceProcessEvents AS
SELECT * FROM read_parquet('storage/DeviceProcessEvents/*/*/*/data.parquet');
```

A KQL query `DeviceProcessEvents | where Timestamp > ago(1h)` transpiles to:
```sql
SELECT ... FROM DeviceProcessEvents WHERE Timestamp > NOW() - INTERVAL 1 HOUR
```
and executes immediately against the Parquet files via the pre-registered view.

---

## What not to do

- Do not use `eval()`, `exec()`, or `new Function()` anywhere in the codebase
- Do not build a custom auth system from scratch — use established JWT libraries
- Do not invent MDE column names — every column must come from `backend/schema/mde_tables.py`
- Do not use a generic normalized schema — store data in MDE-named table partitions
- Do not add dependencies without checking audit status first
- Do not return internal error details, stack traces, or file paths to the client
- Do not use `SELECT *` in transpiler output — project only the columns in the query
- Do not allow the Monaco editor to execute queries locally — always round-trip to backend
- Do not skip the transpiler/validator — raw query strings never touch DuckDB directly
- Do not commit `.env`, `storage/`, or any `.parquet` files to the repository
- Do not implement CQL in the MVP — it is a planned future addition only