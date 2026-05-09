"""
parsers/base_parser.py — Abstract base class for all log source parsers.

Each parser is responsible for:
  1. Detecting whether raw input is in its format (detect_source)
  2. Parsing the raw input into a list of raw event dicts (parse)
  3. Indicating which MDE table each event belongs to

Parsers produce raw events; the normalizer maps those to MDE schema columns.
"""

from abc import ABC, abstractmethod


class BaseParser(ABC):
    """Abstract base for all log format parsers."""

    @classmethod
    @abstractmethod
    def detect_source(cls, raw: str) -> bool:
        """Return True if this parser can handle the given raw input."""
        ...

    @classmethod
    @abstractmethod
    def parse(cls, raw: str) -> list[dict]:
        """Parse raw log content into a list of event dicts.

        Each dict must include a '_target_table' key indicating which MDE table
        the event belongs to. The normalizer uses this to select the correct schema.

        Returns:
            List of raw event dicts with '_target_table' set.
        """
        ...
