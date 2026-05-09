"""
Parsers package — per-source log format detection and normalization.

Auto-detection order: each parser's detect_source() is called in sequence;
the first match wins. Defender (MDE native) is checked last since its detection
heuristic is broad (any JSON with ReportId).
"""

from backend.parsers.base_parser import BaseParser
from backend.parsers.cloudtrail import CloudTrailParser
from backend.parsers.defender import DefenderParser
from backend.parsers.syslog import SyslogParser
from backend.parsers.windows_event import WindowsEventParser

# Ordered by specificity — most specific format first
PARSERS: list[type[BaseParser]] = [
    WindowsEventParser,
    CloudTrailParser,
    SyslogParser,
    DefenderParser,  # Broad heuristic — must be last
]


def detect_and_parse(raw: str) -> list[dict]:
    """Auto-detect the log format and parse it.

    Returns:
        List of raw event dicts with '_target_table' set.
        Empty list if no parser matches.
    """
    for parser in PARSERS:
        if parser.detect_source(raw):
            return parser.parse(raw)
    return []
