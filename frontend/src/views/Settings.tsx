/**
 * Settings.tsx — Platform configuration and operator coverage display.
 *
 * Shows KQL and SPL COVERAGE dicts from backend as a readable table,
 * giving users a clear picture of which operators are supported.
 */

const KQL_COVERAGE: Record<string, string> = {
  "where": "supported",
  "project": "supported",
  "project-away": "supported",
  "extend": "supported",
  "summarize by": "supported",
  "count() / dcount()": "supported",
  "sum() / avg() / min() / max()": "supported",
  "bin(Timestamp, duration)": "supported",
  "ago(duration)": "supported",
  "between": "supported",
  "contains": "supported — case-insensitive via LOWER/LIKE",
  "startswith / endswith / has": "supported",
  "matches regex": "supported",
  "in / !in": "supported",
  "=~ case-insensitive equals": "supported → LOWER(a) = LOWER(b)",
  "!~ case-insensitive not-equals": "supported",
  "let → CTE": "supported",
  "join kind=inner / leftouter": "supported",
  "union": "supported → UNION ALL",
  "top N by col": "supported",
  "order by / sort by": "supported",
  "distinct": "supported",
  "limit / take": "supported",
  "mv-expand": "supported → UNNEST()",
  "AdditionalFields.Key": "supported → json_extract()",
  "toupper() / tolower()": "supported",
  "tostring() / toint() / tolong()": "supported",
  "strcat()": "supported → CONCAT()",
  "split()": "supported → string_split()",
  "render": "supported — chart type returned as metadata",
  "has_any()": "partial: requires column context",
  "make_set() / make_list()": "planned",
  "arg_max() / arg_min()": "planned",
  "evaluate plugin": "planned",
};

const SPL_COVERAGE: Record<string, string> = {
  "search field=value": "supported",
  "where": "supported",
  "fields / table": "supported",
  "stats count by field": "supported",
  "stats count, sum(x) by field": "supported",
  "eval new=expr": "supported",
  "rename old AS new": "supported",
  "sort / sort -field": "supported",
  "head N / tail N": "supported",
  "dedup field": "supported → DISTINCT",
  "rex field=x pattern": "supported → regexp_extract()",
  "index=name": "supported — mapped to MDE table",
  "sourcetype=value": "supported → WHERE source = 'value'",
  "earliest=-7d latest=now": "supported",
  "bin span=1h _time": "supported → date_trunc()",
  "transaction": "planned",
  "lookup": "planned",
  "tstats": "planned",
};

function CoverageTable({ coverage }: { coverage: Record<string, string> }) {
  return (
    <table className="w-full text-sm">
      <thead>
        <tr className="border-b border-border text-muted-foreground text-left">
          <th className="pb-2 pr-4">Operator</th>
          <th className="pb-2">Status</th>
        </tr>
      </thead>
      <tbody className="divide-y divide-border">
        {Object.entries(coverage).map(([op, status]) => (
          <tr key={op}>
            <td className="py-2 pr-4 font-mono text-xs">{op}</td>
            <td className="py-2">
              <span
                className={`text-xs ${
                  status.startsWith("supported")
                    ? "text-green-400"
                    : status.startsWith("partial")
                    ? "text-yellow-400"
                    : "text-muted-foreground"
                }`}
              >
                {status}
              </span>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function Settings() {
  return (
    <div className="p-6 space-y-8 max-w-3xl">
      <h1 className="text-xl font-bold">Settings</h1>

      <div className="bg-card border border-border rounded-lg p-4 space-y-2">
        <h2 className="text-sm font-medium">Platform configuration</h2>
        <div className="grid grid-cols-2 gap-2 text-sm">
          <span className="text-muted-foreground">Query timeout</span>
          <span>30 seconds</span>
          <span className="text-muted-foreground">Max upload size</span>
          <span>500 MB</span>
          <span className="text-muted-foreground">Token expiry</span>
          <span>15 minutes (access) / 7 days (refresh)</span>
          <span className="text-muted-foreground">Detection run interval</span>
          <span>Every 5 minutes</span>
          <span className="text-muted-foreground">Alert dedup window</span>
          <span>1 hour</span>
        </div>
      </div>

      <div className="bg-card border border-border rounded-lg p-4 space-y-4">
        <div>
          <h2 className="text-sm font-medium mb-1">KQL operator coverage</h2>
          <p className="text-xs text-muted-foreground mb-3">
            Operators supported by the KQL → DuckDB transpiler.
          </p>
          <CoverageTable coverage={KQL_COVERAGE} />
        </div>
      </div>

      <div className="bg-card border border-border rounded-lg p-4 space-y-4">
        <div>
          <h2 className="text-sm font-medium mb-1">SPL operator coverage</h2>
          <p className="text-xs text-muted-foreground mb-3">
            Splunk commands supported by the SPL → DuckDB transpiler.
          </p>
          <CoverageTable coverage={SPL_COVERAGE} />
        </div>
      </div>
    </div>
  );
}
