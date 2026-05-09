# fried-plantains

A self-hosted SIEM and threat hunting platform built on DuckDB and Apache Parquet. Designed to emulate Microsoft Sentinel / Defender for Endpoint (KQL), Splunk Enterprise Security (SPL), and direct SQL analytics — at homelab scale on an Intel NUC.

Detection rules written here are portable to real MDE and Microsoft Sentinel environments without modification.

---

## What it does

- Ingests and normalizes security logs from Windows Event logs, AWS CloudTrail, syslog, and MDE raw exports
- Stores data as hive-partitioned Parquet files, queryable with KQL, SPL, or SQL
- Runs detection rules on a schedule and generates alerts with severity and MITRE ATT&CK tagging
- Provides a browser UI for querying, alert triage, detection rule management, and log ingestion

---

## Stack

| Layer | Technology |
|---|---|
| Backend | FastAPI (Python) |
| Query engine | DuckDB |
| Storage | Apache Parquet (hive-style partitioning) |
| Detection rules | YAML |
| Auth | JWT (short expiry + refresh tokens) |
| Frontend | React 18 + Vite + TypeScript |
| UI components | shadcn/ui + Tailwind CSS |
| Query editor | Monaco Editor |
| Data tables | AG Grid Community |
| Charts | Recharts |
| Testing | pytest (backend), Vitest (frontend) |

---

## Getting started

**Backend**

```bash
pip install -r backend/requirements.txt
cp .env.example .env   # fill in secrets
uvicorn backend.main:app --reload
```

**Frontend**

```bash
cd frontend
npm install
npm run dev
```

The API runs on `http://localhost:8000` and the UI on `http://localhost:5173` by default.

---

## Repository structure

```
fried-plantains/
├── backend/
│   ├── api/            # FastAPI route handlers (auth, ingest, query, detections, alerts)
│   ├── engine/         # KQL → SQL, SPL → SQL transpilers, query router, detection runner
│   ├── ingest/         # Validator, normalizer, atomic Parquet writer
│   ├── parsers/        # Per-source normalization (Windows Events, CloudTrail, syslog, MDE)
│   ├── models/         # Pydantic models
│   ├── schema/         # Canonical MDE table definitions (source of truth)
│   └── tests/
├── detections/
│   └── rules/          # YAML detection rules (FP-XXXX series)
├── frontend/
│   └── src/
│       ├── views/      # Dashboard, Workbench, Detections, Alerts, Ingest, Settings
│       └── components/ # QueryEditor (Monaco), LogTable (AG Grid), AlertBadge, SeverityPill
├── scripts/
│   └── generate_logs.py  # Synthetic log generator with embedded malicious scenarios
└── storage/            # Parquet files (gitignored) — partitioned by table/year/month/day
```

---

## MDE table support

The following Microsoft Defender for Endpoint tables are implemented with exact column names and types:

`DeviceProcessEvents` · `DeviceNetworkEvents` · `DeviceFileEvents` · `DeviceLogonEvents` · `DeviceRegistryEvents` · `DeviceEvents` · `IdentityLogonEvents` · `CloudAppEvents`

---

## Detection rules

Rules live in `detections/rules/` as YAML files with auto-incrementing IDs (`FP-XXXX`). Each rule specifies a query language, severity, MITRE ATT&CK technique tags, and false positive notes. Rules are schema-validated before execution — never eval'd.

Example rule structure:

```yaml
id: FP-0001
name: Suspicious PowerShell Encoded Command
severity: high
query_language: kql
mitre: [T1059.001]
query: |
  DeviceProcessEvents
  | where FileName =~ "powershell.exe"
  | where ProcessCommandLine contains "-EncodedCommand"
```

---

## Storage layout

```
storage/
└── DeviceProcessEvents/
    └── 2025/
        └── 01/
            └── 15/
                └── data.parquet
```

Parquet files are registered as DuckDB views at startup, so KQL table references map directly to the files on disk. The same files can be loaded into ClickHouse, Snowflake, or Databricks without changing detection logic.
