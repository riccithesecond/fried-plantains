"""
mde_native.py — Passthrough parser for pre-normalized MDE-format NDJSON.

Used by logforge and other tools that generate logs already in the MDE table
schema (column names, ActionType enums, Timestamp format). No field mapping
needed — rows pass straight through to write_parquet().

Detection: valid JSON on every non-empty line, at least one line contains
both "Timestamp" and "ReportId" (the two required fields in every MDE table).
"""

from __future__ import annotations

import json

from backend.parsers.base_parser import BaseParser


class MdeNativeParser(BaseParser):
    """Accept pre-normalized MDE NDJSON and route rows to their target table."""

    @classmethod
    def detect_source(cls, raw: str) -> bool:
        lines = [l.strip() for l in raw.strip().splitlines() if l.strip()]
        if not lines:
            return False
        try:
            first = json.loads(lines[0])
            return isinstance(first, dict) and "Timestamp" in first and "ReportId" in first
        except (json.JSONDecodeError, KeyError):
            return False

    @classmethod
    def parse(cls, raw: str) -> list[dict]:
        """
        Parse NDJSON into a flat list of row dicts. Each row keeps its fields
        as-is — the normalizer and write_parquet handle coercion. _target_table
        is not set here; the ingest endpoint sets it from the `table` parameter.
        """
        rows = []
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
                if isinstance(row, dict):
                    rows.append(row)
            except json.JSONDecodeError:
                continue
        return rows
