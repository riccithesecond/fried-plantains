# ADR-0001: Alert storage and per-device granularity

**Status:** Accepted

## Context

The detection runner creates alerts when rules match events. Two design questions arose:

1. Where to persist alerts (the original MVP used a flat JSONL file)
2. At what granularity to write alert records given the MDE `DeviceAlertEvents` schema

## Decision

**Storage:** Alert events are written to the `DeviceAlertEvents` Parquet partition (same store as all other MDE tables). This makes alert history queryable via KQL alongside raw events — analysts can hunt across event data and alert history in a single query. Triage state (`status`, `notes`) is mutable and lives in a separate SQLite file (`storage/alerts/triage.db`), joined into the API response at read time. The Parquet record is immutable — it is the detection fact.

**Granularity:** The detection runner writes one `DeviceAlertEvents` row per unique device in the matched result set. This is faithful to how real MDE represents alerts. A single rule firing that matches 10 devices produces 10 rows, all sharing the same `AlertId`. The SQLite triage record links on `AlertId` and covers all device rows for that rule execution.

## Consequences

- If a result row is missing `DeviceId` or `DeviceName`, the runner falls back to `""` — no validation at rule-load time. Silent degradation is acceptable at homelab scale.
- Deduplication must consider `(rule_id, DeviceId)` or remain rule-level — TBD.
- `ServiceSource` is set to `"fried-plantains"` to distinguish local detections from ingested MDE alerts in the same table.
- The existing `alerts.jsonl` file is superseded; migration is a one-time load of existing records into Parquet + SQLite.
