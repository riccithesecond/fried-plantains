"""
models/detection.py — Detection rule Pydantic model.

Matches the YAML schema defined in CLAUDE.md exactly. The query validator
calls the query router to ensure the rule's query parses for its declared
language — an unparseable detection rule is rejected at creation time, not
at execution time.

Rule ID format: FP-XXXX (four zero-padded digits, auto-incremented).
mde_portable: true means the KQL query must run unchanged in real MDE/Sentinel.
"""

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, Field, field_validator

from backend.engine.query_router import route
from backend.exceptions import QueryException


class DetectionRule(BaseModel):
    """Complete detection rule schema."""

    id: str = Field(pattern=r"^(FP|SYN)-\d{4}$", description="Rule ID — FP-XXXX (production) or SYN-XXXX (synthetic test)")
    name: str = Field(min_length=5, max_length=200)
    description: str
    severity: str = Field(pattern=r"^(info|low|medium|high|critical)$")
    language: str = Field(pattern=r"^(kql|spl|sql)$")
    query: str
    tags: list[str] = Field(default_factory=list)
    mde_portable: bool = False
    synthetic: bool = False
    enabled: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    author: str = "fried-plantains"
    false_positive_notes: str = ""

    @field_validator("query")
    @classmethod
    def query_must_parse(cls, query: str, info: object) -> str:
        """Validate the query parses for the declared language.

        Uses the query router to attempt transpilation — if this fails, the
        rule is rejected before storage. A rule with an invalid query would
        silently never fire, which is worse than a loud rejection at creation.
        """
        # Access language from the model's other fields
        language = None
        if hasattr(info, "data") and "language" in info.data:
            language = info.data["language"]
        if language:
            try:
                route(query, language)
            except QueryException as exc:
                raise ValueError(f"Query parse error: {exc.detail}") from exc
        return query


class DetectionRuleCreate(BaseModel):
    """Schema for creating a new detection rule (id is auto-assigned)."""

    name: str = Field(min_length=5, max_length=200)
    description: str
    severity: str = Field(pattern=r"^(info|low|medium|high|critical)$")
    language: str = Field(pattern=r"^(kql|spl|sql)$")
    query: str
    tags: list[str] = Field(default_factory=list)
    mde_portable: bool = False
    enabled: bool = True
    author: str = "fried-plantains"
    false_positive_notes: str = ""

    @field_validator("query")
    @classmethod
    def query_must_parse(cls, query: str, info: object) -> str:
        language = None
        if hasattr(info, "data") and "language" in info.data:
            language = info.data["language"]
        if language:
            try:
                route(query, language)
            except QueryException as exc:
                raise ValueError(f"Query parse error: {exc.detail}") from exc
        return query


class DetectionRulePatch(BaseModel):
    """Partial update — used for enable/disable and notes updates."""

    enabled: bool | None = None
    false_positive_notes: str | None = None
    severity: Annotated[str | None, Field(pattern=r"^(info|low|medium|high|critical)$")] = None


class DetectionTestResult(BaseModel):
    """Result of running a detection rule against recent data."""

    rule_id: str
    match_count: int
    sample_rows: list[dict]
    duration_ms: int
