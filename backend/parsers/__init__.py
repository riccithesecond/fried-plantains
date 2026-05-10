"""
Parsers package — per-source log format detection and normalization.

Auto-detection order: each parser's detect_source() is called in sequence;
the first match wins. Defender (MDE native) is checked last since its detection
heuristic is broad (any JSON with ReportId).

Cloud parsers (CloudTrail, Cloudflare, Zscaler) return {"table", "data"} dicts
or dicts keyed by table name. The ingest pipeline handles both formats.
"""

from backend.parsers.base_parser import BaseParser
from backend.parsers.cloudflare import CloudflareParser
from backend.parsers.cloudtrail import CloudTrailParser
from backend.parsers.defender import DefenderParser
from backend.parsers.syslog import SyslogParser
from backend.parsers.windows_event import WindowsEventParser
from backend.parsers.zscaler import ZscalerParser

# Ordered by specificity — most specific format first
PARSERS: list[type[BaseParser]] = [
    WindowsEventParser,
    CloudTrailParser,
    CloudflareParser,
    ZscalerParser,
    SyslogParser,
    DefenderParser,  # Broad heuristic — must be last
]

# Named source type registry used by the ingest API when the caller specifies
# an explicit source. Values are parser classes; the ingest layer handles the
# different return shapes (list[{table,data}] vs dict[table, list]).
SOURCE_TYPES: dict[str, type] = {
    "cloudtrail": CloudTrailParser,
    "cloudflare": CloudflareParser,
    "zscaler_web": ZscalerParser,
    "zscaler_dns": ZscalerParser,
    "windows_event": WindowsEventParser,
    "syslog": SyslogParser,
    "defender": DefenderParser,
}


def detect_and_parse(raw: str) -> list[dict]:
    """Auto-detect the log format and parse it.

    Returns:
        List of raw event dicts. For legacy parsers each dict has '_target_table'.
        For cloud parsers each dict has 'table' and 'data' keys.
        Empty list if no parser matches.
    """
    for parser in PARSERS:
        if parser.detect_source(raw):
            result = parser.parse(raw)
            # CloudflareParser returns dict[str, list] — flatten to list[{table,data}]
            if isinstance(result, dict):
                flat: list[dict] = []
                for table_name, events in result.items():
                    for evt in events:
                        flat.append({"table": table_name, "data": evt})
                return flat
            return result
    return []
