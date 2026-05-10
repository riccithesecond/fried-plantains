# fried-plantains

A self-hosted SIEM and threat hunting platform built on DuckDB and Apache Parquet. Designed to emulate Microsoft Sentinel / Defender for Endpoint (KQL), Splunk Enterprise Security (SPL), and direct SQL analytics — at homelab scale on an Intel NUC.

Detection rules written here targeting MDE native tables are portable to real MDE and Microsoft Sentinel environments without modification.

---

## What it does

- Ingests and normalizes security logs from Windows Event logs, AWS CloudTrail, Cloudflare, Zscaler, Proofpoint TAP, Abnormal Security, syslog, and MDE raw exports
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
│   ├── parsers/        # Per-source normalization (Windows Events, CloudTrail, Cloudflare,
│   │                   # Zscaler, Proofpoint, Abnormal, syslog, MDE)
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

## Table support

19 tables implemented with exact column names, types, and ActionType enumerations.

### MDE native tables
Queries against these tables are portable to real Microsoft Sentinel and MDE Advanced Hunting without modification (`mde_portable: true`).

| Table | Source |
|---|---|
| `DeviceProcessEvents` | Process creation and injection |
| `DeviceNetworkEvents` | Network connections |
| `DeviceFileEvents` | File create, modify, delete, rename |
| `DeviceRegistryEvents` | Registry key and value changes |
| `DeviceLogonEvents` | Interactive, network, and remote logons |
| `DeviceEvents` | Antivirus, PowerShell, browser telemetry |
| `DeviceAlertEvents` | MDE-generated alert events |
| `IdentityLogonEvents` | Azure AD / on-prem AD authentication |
| `CloudAppEvents` | Microsoft 365 and cloud app activity |

### Cloud and proxy tables
Non-portable (`mde_portable: false`) — schema mirrors the vendor's native data model.

| Table | Source |
|---|---|
| `AWSCloudTrailEvents` | AWS CloudTrail API call events |
| `CloudflareHttpEvents` | Cloudflare edge HTTP/S requests (Logpush) |
| `CloudflareFirewallEvents` | Cloudflare firewall rule matches |
| `CloudflareDnsEvents` | Cloudflare Gateway DNS queries |
| `ZscalerWebEvents` | Zscaler Internet Access proxy transactions |
| `ZscalerDnsEvents` | Zscaler DNS Security query events |

### Email security tables
Non-portable (`mde_portable: false`). `NetworkMessageId` is the join key across all email tables — angle brackets stripped at ingest for consistency with MDO convention.

| Table | Source |
|---|---|
| `ProofpointMessageEvents` | Proofpoint TAP SIEM API — message filtering verdicts, scores, auth results |
| `ProofpointClickEvents` | Proofpoint TAP URL Defense — per-click block/permit events |
| `AbnormalThreatEvents` | Abnormal Security — AI-detected BEC, phishing, impostor threats |
| `AbnormalCaseEvents` | Abnormal Security — case lifecycle events (open, update, close) |

---

## Detection rules

Rules live in `detections/rules/` as YAML files with auto-incrementing IDs (`FP-XXXX`). Each rule specifies a query language, severity, MITRE ATT&CK technique tags, and false positive notes. Rules are schema-validated before execution — never eval'd.

### Current rules

| ID | Name | Severity | Tables | MITRE |
|---|---|---|---|---|
| FP-0001 | Suspicious PowerShell encoded command | high | DeviceProcessEvents | T1059.001 |
| FP-0002 | LSASS memory access (credential dumping) | critical | DeviceProcessEvents | T1003.001 |
| FP-0003 | Persistence via registry run key | high | DeviceRegistryEvents | T1547.001 |
| FP-0004 | Brute force → credential success | high | DeviceLogonEvents | T1110, T1078 |
| FP-0005 | LOLBin execution (certutil, regsvr32, rundll32) | medium | DeviceProcessEvents | T1218 |
| FP-0006 | Lateral movement via PsExec | high | DeviceNetworkEvents, DeviceLogonEvents | T1021, T1570 |
| FP-0007 | Bulk file access off-hours (insider threat) | high | DeviceFileEvents, DeviceLogonEvents | T1078, T1048 |
| FP-0008 | AWS root account API call | critical | AWSCloudTrailEvents | T1078.004 |
| FP-0009 | AWS IAM privilege escalation | high | AWSCloudTrailEvents | T1078.004, T1548 |
| FP-0010 | CloudTrail logging disabled | critical | AWSCloudTrailEvents | T1562.008 |
| FP-0011 | Cloudflare WAF block spike | high | CloudflareFirewallEvents | T1190 |
| FP-0012 | Cloudflare bot score anomaly | medium | CloudflareHttpEvents | T1595 |
| FP-0013 | Zscaler malware download blocked | high | ZscalerWebEvents | T1105 |
| FP-0014 | Zscaler DLP violation — potential exfiltration | high | ZscalerWebEvents | T1048 |
| FP-0015 | Zscaler DNS sinkhole — active C2 attempt | critical | ZscalerDnsEvents | T1071.004 |
| FP-0016 | Proofpoint phish blocked, VeryMalicious sender | high | ProofpointMessageEvents | T1566.001 |
| FP-0017 | Proofpoint impostor email delivered (BEC precursor) | high | ProofpointMessageEvents | T1566.001, T1534 |
| FP-0018 | Proofpoint malware attachment blocked by sandbox | critical | ProofpointMessageEvents | T1566.001, T1059 |
| FP-0019 | Proofpoint user clicked malicious URL | critical | ProofpointClickEvents | T1566.002, T1204.001 |
| FP-0020 | Abnormal BEC / impostor threat detected | high | AbnormalThreatEvents | T1566.001, T1534 |
| FP-0021 | Cross-layer: Proofpoint + Abnormal flagged same message | critical | ProofpointMessageEvents, AbnormalThreatEvents | T1566.001, T1566.002 |
| FP-0022 | Abnormal high-severity case opened | high | AbnormalCaseEvents | T1566, T1078 |

FP-0021 is a `let` + `join kind=inner` on `NetworkMessageId` — two independent AI engines independently flagging the same message.

Example rule structure:

```yaml
id: FP-0016
name: Proofpoint — high-confidence phishing blocked, VeryMalicious sender
severity: high
language: kql
mde_portable: false
query: |
  ProofpointMessageEvents
  | where Timestamp > ago(1h)
  | where ActionType in ("PhishFiltered", "Quarantined")
  | where SenderReputation == "VeryMalicious"
  | project Timestamp, SenderFromAddress, SenderFromDomain, SenderIP,
            SenderReputation, RecipientEmailAddress, Subject,
            PhishScore, ImpostorScore, DispositionAction, NetworkMessageId
  | order by PhishScore desc
tags:
  - T1566.001
  - phishing
mde_portable: false
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

Each MDE table name is a separate partition tree. DuckDB views are registered at startup so KQL table references map directly to Parquet files on disk. The same files can be queried in ClickHouse, Snowflake, or Databricks without changing detection logic.

---

## Log sources supported

| Parser | Ingest formats | `source=` value |
|---|---|---|
| Windows Event Log | JSON (Security, System, Application) | `windows_event` |
| AWS CloudTrail | JSON Records wrapper, single event, JSON lines | `cloudtrail` |
| Cloudflare | JSON lines (HTTP, Firewall, DNS Logpush datasets) | `cloudflare` |
| Zscaler | NSS key=value, JSON | `zscaler_web`, `zscaler_dns` |
| Proofpoint TAP | TAP SIEM API JSON, syslog/CEF | `proofpoint_tap`, `proofpoint_syslog` |
| Abnormal Security | `/threats` API, `/cases` API, webhook | `abnormal_threats`, `abnormal_cases` |
| Syslog | RFC 5424 | `syslog` |
| MDE export | MDE raw JSON export format | `defender` |
