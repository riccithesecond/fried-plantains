"""
kql_transpiler.py — KQL to DuckDB SQL transpiler.

Architecture: four-class recursive descent pipeline.
  KqlTokenizer  →  list[KqlToken]       (lexical analysis)
  KqlParser     →  KqlPipeline (AST)    (syntactic analysis, typed nodes)
  SchemaValidator → list[SchemaWarning]  (semantic validation against MDE schema)
  SqlEmitter    →  EmitResult            (code generation)

Public API: KqlTranspiler.transpile(kql) → str (backward compatible).
For richer output (render hints, warnings, CTE names) use SqlEmitter directly.

MDE schema fidelity: column references against known tables are validated
against backend.schema.mde_tables. Unknown columns generate SchemaWarnings —
they indicate a rule that will fail in real MDE.

Case sensitivity: MDE column names are case-sensitive. DeviceName ≠ devicename.
The transpiler preserves column name casing exactly — it does not normalize.
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Optional

from backend.exceptions import QueryException
from backend.schema.mde_tables import MDE_TABLES, validate_columns

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Coverage — portfolio artifact: engineering honesty about what's implemented
# ---------------------------------------------------------------------------

COVERAGE: dict[str, str] = {
    "where": "supported",
    "project": "supported — column selection and rename (alias = col)",
    "project-away": "supported — excludes named columns from schema",
    "extend": "supported — computed columns via assignment",
    "summarize by": "supported — GROUP BY with aggregation functions",
    "count()": "supported → COUNT(*)",
    "dcount()": "supported → COUNT(DISTINCT col)",
    "sum() / avg() / min() / max()": "supported → direct SQL equivalents",
    "bin(Timestamp, duration)": "supported → date_trunc('unit', col)",
    "ago(duration)": "supported → NOW() - INTERVAL N UNIT",
    "between": "supported → BETWEEN low AND high",
    "contains": "supported — case-insensitive via LOWER/LIKE",
    "startswith": "supported — LOWER/LIKE prefix match",
    "endswith": "supported — LOWER/LIKE suffix match",
    "has": "supported — word-boundary approximation via LOWER/LIKE",
    "has_any()": "supported — multi-value OR LIKE expansion",
    "matches regex": "supported → regexp_matches()",
    "in": "supported → IN (...)",
    "!in": "supported → NOT IN (...)",
    "isempty() / isnotempty()": "supported → IS NULL / IS NOT NULL checks",
    "toupper() / tolower()": "supported → UPPER() / LOWER()",
    "tostring() / toint() / tolong()": "supported → CAST()",
    "strcat()": "supported → CONCAT()",
    "split()": "supported → string_split()",
    "parse_json() / AdditionalFields.Key": "supported → json_extract()",
    "mv-expand": "supported → CROSS JOIN UNNEST(col) AS t(col)",
    "join kind=inner": "supported → INNER JOIN",
    "join kind=leftouter": "supported → LEFT JOIN",
    "join kind=leftanti": "supported → LEFT JOIN ... WHERE right IS NULL",
    "union": "supported → UNION ALL",
    "let (scalar)": "supported → CTE scalar value",
    "let (sub-pipeline)": "supported → CTE from recursively transpiled sub-query",
    "top N by col": "supported → ORDER BY ... LIMIT N",
    "order by / sort by": "supported → ORDER BY ASC/DESC",
    "distinct": "supported → SELECT DISTINCT",
    "limit / take": "supported → LIMIT N",
    "=~ case-insensitive equals": "supported → LOWER(a) = LOWER(b)",
    "!~ case-insensitive not-equals": "supported → LOWER(a) != LOWER(b)",
    "render": "supported — stripped from SQL; chart type in EmitResult.render_hint",
    "getschema": "supported — returns ColumnName, ColumnOrdinal, DataType, ColumnType from MDE schema (full table schema; project-before-getschema not reflected)",
    "make_set() / make_list()": "planned",
    "arg_max() / arg_min()": "planned",
    "pack() / pack_all()": "planned",
    "series_stats()": "planned",
    "evaluate plugin": "planned",
    "externaldata": "planned",
}


# ---------------------------------------------------------------------------
# Parse error — raised by tokenizer and parser; carries position for UI
# ---------------------------------------------------------------------------

class KqlParseError(QueryException):
    """KQL-specific parse error with source line/column context.

    Subclasses QueryException so callers that catch QueryException still work.
    Frontend can use line/column to highlight the offending token.
    """

    def __init__(self, message: str, line: int = 0, column: int = 0) -> None:
        super().__init__(detail=message, line=line, column=column)


# ---------------------------------------------------------------------------
# Token types
# ---------------------------------------------------------------------------

class TT(Enum):
    # Structural
    PIPE = auto()
    EOF = auto()
    SEMICOLON = auto()
    # Literals
    IDENT = auto()
    STRING = auto()
    NUMBER = auto()
    BOOLEAN = auto()   # true / false
    NULL = auto()      # null
    # Delimiters
    LPAREN = auto()
    RPAREN = auto()
    LBRACKET = auto()
    RBRACKET = auto()
    COMMA = auto()
    DOT = auto()
    STAR = auto()
    # Comparison operators
    EQ = auto()        # = or ==
    NEQ = auto()       # !=
    EQ_TILDE = auto()  # =~
    NEQ_TILDE = auto() # !~ or !=~
    LT = auto()
    LTE = auto()
    GT = auto()
    GTE = auto()
    BANG = auto()      # ! (standalone, for !in)
    # Arithmetic
    PLUS = auto()
    MINUS = auto()
    SLASH = auto()
    # Logical (separate token types, not just KEYWORD)
    AND = auto()
    OR = auto()
    NOT = auto()
    # Pipeline stage keywords
    KEYWORD = auto()


# All lowercase keyword strings — matched case-insensitively at tokenize time
KQL_KEYWORDS: frozenset[str] = frozenset({
    "where", "project", "project-away", "extend", "summarize", "by",
    "count", "dcount", "sum", "avg", "min", "max", "bin", "ago",
    "between", "contains", "startswith", "endswith", "has", "has_any",
    "matches", "regex", "in", "not", "let", "join", "kind",
    "inner", "leftouter", "leftanti", "rightouter", "on",
    "union", "top", "order", "sort", "asc", "desc",
    "distinct", "limit", "take", "render", "mv-expand",
    "isempty", "isnotempty", "toupper", "tolower", "tostring",
    "toint", "tolong", "strcat", "split", "parse_json",
    "getschema",
})


@dataclass
class KqlToken:
    type: TT
    value: str
    line: int
    col: int


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

class KqlTokenizer:
    def __init__(self, source: str) -> None:
        self.source = source
        self.pos = 0
        self.line = 1
        self.col = 1

    def _peek(self, offset: int = 0) -> str:
        idx = self.pos + offset
        return self.source[idx] if idx < len(self.source) else ""

    def _advance(self) -> str:
        ch = self.source[self.pos]
        self.pos += 1
        if ch == "\n":
            self.line += 1
            self.col = 1
        else:
            self.col += 1
        return ch

    def _skip_whitespace_and_comments(self) -> None:
        while self.pos < len(self.source):
            ch = self._peek()
            if ch in " \t\r\n":
                self._advance()
            elif ch == "/" and self._peek(1) == "/":
                while self.pos < len(self.source) and self._peek() != "\n":
                    self._advance()
            else:
                break

    def tokenize(self) -> list[KqlToken]:
        tokens: list[KqlToken] = []
        while True:
            self._skip_whitespace_and_comments()
            if self.pos >= len(self.source):
                tokens.append(KqlToken(TT.EOF, "", self.line, self.col))
                break

            line, col = self.line, self.col
            ch = self._peek()

            if ch == "|":
                self._advance()
                tokens.append(KqlToken(TT.PIPE, "|", line, col))
            elif ch == "(":
                self._advance()
                tokens.append(KqlToken(TT.LPAREN, "(", line, col))
            elif ch == ")":
                self._advance()
                tokens.append(KqlToken(TT.RPAREN, ")", line, col))
            elif ch == "[":
                self._advance()
                tokens.append(KqlToken(TT.LBRACKET, "[", line, col))
            elif ch == "]":
                self._advance()
                tokens.append(KqlToken(TT.RBRACKET, "]", line, col))
            elif ch == ",":
                self._advance()
                tokens.append(KqlToken(TT.COMMA, ",", line, col))
            elif ch == ".":
                self._advance()
                tokens.append(KqlToken(TT.DOT, ".", line, col))
            elif ch == ";":
                self._advance()
                tokens.append(KqlToken(TT.SEMICOLON, ";", line, col))
            elif ch == "*":
                self._advance()
                tokens.append(KqlToken(TT.STAR, "*", line, col))
            elif ch == "+":
                self._advance()
                tokens.append(KqlToken(TT.PLUS, "+", line, col))
            elif ch == "/":
                self._advance()
                tokens.append(KqlToken(TT.SLASH, "/", line, col))
            elif ch == "-":
                self._advance()
                tokens.append(KqlToken(TT.MINUS, "-", line, col))
            elif ch == "=":
                self._advance()
                if self._peek() == "~":
                    self._advance()
                    tokens.append(KqlToken(TT.EQ_TILDE, "=~", line, col))
                elif self._peek() == "=":
                    self._advance()
                    tokens.append(KqlToken(TT.EQ, "==", line, col))
                else:
                    tokens.append(KqlToken(TT.EQ, "=", line, col))
            elif ch == "!":
                self._advance()
                if self._peek() == "=":
                    self._advance()
                    if self._peek() == "~":
                        self._advance()
                        tokens.append(KqlToken(TT.NEQ_TILDE, "!=~", line, col))
                    else:
                        tokens.append(KqlToken(TT.NEQ, "!=", line, col))
                elif self._peek() == "~":
                    self._advance()
                    tokens.append(KqlToken(TT.NEQ_TILDE, "!~", line, col))
                else:
                    tokens.append(KqlToken(TT.BANG, "!", line, col))
            elif ch == "<":
                self._advance()
                if self._peek() == "=":
                    self._advance()
                    tokens.append(KqlToken(TT.LTE, "<=", line, col))
                else:
                    tokens.append(KqlToken(TT.LT, "<", line, col))
            elif ch == ">":
                self._advance()
                if self._peek() == "=":
                    self._advance()
                    tokens.append(KqlToken(TT.GTE, ">=", line, col))
                else:
                    tokens.append(KqlToken(TT.GT, ">", line, col))
            elif ch in ('"', "'"):
                tokens.append(self._read_string(ch, line, col))
            elif ch.isdigit():
                tokens.append(self._read_number(line, col))
            elif ch.isalpha() or ch == "_":
                tokens.append(self._read_ident(line, col))
            else:
                self._advance()  # Skip unknown characters gracefully
        return tokens

    def _read_string(self, quote: str, line: int, col: int) -> KqlToken:
        self._advance()  # Opening quote
        buf: list[str] = []
        while self.pos < len(self.source):
            ch = self._advance()
            if ch == quote:
                break
            if ch == "\\" and self.pos < len(self.source):
                buf.append(self._advance())
            else:
                buf.append(ch)
        return KqlToken(TT.STRING, "".join(buf), line, col)

    def _read_number(self, line: int, col: int) -> KqlToken:
        buf: list[str] = []
        while self.pos < len(self.source) and (self._peek().isdigit() or self._peek() == "."):
            buf.append(self._advance())
        # Consume duration unit suffix immediately following (7d, 1h, 30m, 60s, 500ms)
        if self.pos < len(self.source) and self._peek().isalpha():
            if self._peek() == "m" and self.pos + 1 < len(self.source) and self.source[self.pos + 1] == "s":
                buf.append(self._advance())
                buf.append(self._advance())
            elif self._peek() in "dhms":
                buf.append(self._advance())
        return KqlToken(TT.NUMBER, "".join(buf), line, col)

    def _read_ident(self, line: int, col: int) -> KqlToken:
        buf: list[str] = []
        while self.pos < len(self.source) and (self._peek().isalnum() or self._peek() in "_-."):
            # Stop at '-' only if next char is not alphanumeric (handles project-away, mv-expand)
            if self._peek() == "-" and not (self.pos + 1 < len(self.source) and self.source[self.pos + 1].isalpha()):
                break
            buf.append(self._advance())
        value = "".join(buf)
        lower = value.lower()
        if lower == "and":
            return KqlToken(TT.AND, value, line, col)
        if lower == "or":
            return KqlToken(TT.OR, value, line, col)
        if lower == "not":
            return KqlToken(TT.NOT, value, line, col)
        if lower in ("true", "false"):
            return KqlToken(TT.BOOLEAN, value, line, col)
        if lower == "null":
            return KqlToken(TT.NULL, value, line, col)
        if lower in KQL_KEYWORDS:
            return KqlToken(TT.KEYWORD, value, line, col)
        return KqlToken(TT.IDENT, value, line, col)


# ---------------------------------------------------------------------------
# Typed expression AST nodes
# ---------------------------------------------------------------------------

@dataclass
class ColumnRef:
    """Reference to a table column, with optional JSON path for AdditionalFields.Key."""
    column: str
    table: Optional[str] = None
    path: Optional[str] = None  # "Key" for AdditionalFields.Key → json_extract


@dataclass
class Literal:
    """Scalar literal value."""
    value: Any
    dtype: str   # "string" | "number" | "bool" | "null" | "timespan"
    timespan_unit: Optional[str] = None  # "d" | "h" | "m" | "s" | "ms"


@dataclass
class FunctionCall:
    """Named function invocation: count(), ago(7d), bin(Timestamp, 1h)."""
    name: str
    args: list  # list[Expr] — Any due to forward-reference limitations


@dataclass
class BinaryOp:
    """Binary operation: comparison, logical, or string predicate."""
    op: str     # "=", "!=", "=~", "!~", "<", ">", "AND", "OR", "contains", etc.
    left: Any   # Expr
    right: Any  # Expr or list[Expr] for "in"/"!in"/"between"


@dataclass
class UnaryOp:
    """Unary prefix operation: NOT, unary minus."""
    op: str    # "NOT" | "MINUS"
    operand: Any  # Expr


@dataclass
class Assignment:
    """Named binding: alias = expr. name="" means no alias (use expr directly)."""
    name: str
    expr: Any  # Expr


# ---------------------------------------------------------------------------
# Pipeline and stage AST nodes
# ---------------------------------------------------------------------------

@dataclass
class LetBinding:
    """let name = expression; — stored as SQL string after recursive transpilation."""
    name: str
    expression: str  # SQL string — either a scalar value or a sub-query


@dataclass
class TableSource:
    """Source table reference."""
    name: str


@dataclass
class WhereStage:
    predicate: Any  # Expr (BinaryOp, UnaryOp, or FunctionCall)


@dataclass
class ProjectStage:
    columns: list  # list[Assignment]


@dataclass
class ProjectAwayStage:
    columns: list[str]  # Column names to exclude


@dataclass
class ExtendStage:
    assignments: list  # list[Assignment]


@dataclass
class SummarizeStage:
    aggregations: list  # list[Assignment]
    by_columns: list    # list[Expr]


@dataclass
class OrderStage:
    columns: list  # list[tuple[str, str]] — (col_name, "asc"|"desc")


@dataclass
class LimitStage:
    n: int


@dataclass
class TopStage:
    n: int
    by_col: str
    direction: str  # "asc" | "desc"


@dataclass
class DistinctStage:
    columns: list[str]


@dataclass
class JoinStage:
    kind: str           # "inner" | "leftouter" | "leftanti"
    right_table: str
    on_columns: list[str]


@dataclass
class UnionStage:
    tables: list[str]


@dataclass
class MvExpandStage:
    column: str


@dataclass
class GetSchemaStage:
    pass


@dataclass
class KqlPipeline:
    table: str
    stages: list
    lets: list = field(default_factory=list)   # list[LetBinding]
    render_hint: Optional[str] = None


# ---------------------------------------------------------------------------
# Parser — recursive descent, produces typed AST nodes
# ---------------------------------------------------------------------------

# Functions that can appear as the first token in a column expression context
_FUNC_KEYWORDS = frozenset({
    "count", "dcount", "sum", "avg", "min", "max", "bin",
    "toupper", "tolower", "tostring", "toint", "tolong",
    "strcat", "split", "parse_json", "ago", "has_any",
    "isempty", "isnotempty",
})


class KqlParser:
    """Recursive descent parser: token stream → KqlPipeline AST."""

    def __init__(self, tokens: list[KqlToken]) -> None:
        self.tokens = tokens
        self.pos = 0

    def _peek(self) -> KqlToken:
        return self.tokens[self.pos]

    def _advance(self) -> KqlToken:
        tok = self.tokens[self.pos]
        if tok.type != TT.EOF:
            self.pos += 1
        return tok

    def _expect(self, tt: TT) -> KqlToken:
        tok = self._advance()
        if tok.type != tt:
            raise KqlParseError(
                f"Expected {tt.name}, got '{tok.value}'",
                line=tok.line,
                column=tok.col,
            )
        return tok

    def _match_keyword(self, *keywords: str) -> bool:
        tok = self._peek()
        return tok.type == TT.KEYWORD and tok.value.lower() in {k.lower() for k in keywords}

    def _match_ident_or_keyword(self, name: str) -> bool:
        tok = self._peek()
        return tok.type in (TT.IDENT, TT.KEYWORD) and tok.value.lower() == name.lower()

    def parse(self) -> KqlPipeline:
        lets: list[LetBinding] = []
        while self._match_keyword("let"):
            lets.append(self._parse_let())
            if self._peek().type == TT.SEMICOLON:
                self._advance()

        table = self._parse_table_name()
        stages: list[Any] = []
        render_hint: Optional[str] = None

        while self._peek().type == TT.PIPE:
            self._advance()  # consume |
            tok = self._peek()

            if self._match_keyword("where"):
                self._advance()
                stages.append(self._parse_where())
            elif self._match_keyword("project-away"):
                self._advance()
                stages.append(self._parse_project_away())
            elif self._match_keyword("project"):
                self._advance()
                stages.append(self._parse_project())
            elif self._match_keyword("extend"):
                self._advance()
                stages.append(self._parse_extend())
            elif self._match_keyword("summarize"):
                self._advance()
                stages.append(self._parse_summarize())
            elif self._match_keyword("order", "sort"):
                self._advance()
                if self._match_keyword("by"):
                    self._advance()
                stages.append(self._parse_order())
            elif self._match_keyword("top"):
                self._advance()
                stages.append(self._parse_top())
            elif self._match_keyword("limit", "take"):
                self._advance()
                stages.append(self._parse_limit())
            elif self._match_keyword("distinct"):
                self._advance()
                stages.append(self._parse_distinct())
            elif self._match_keyword("join"):
                self._advance()
                stages.append(self._parse_join())
            elif self._match_keyword("union"):
                self._advance()
                stages.append(self._parse_union())
            elif self._match_keyword("mv-expand"):
                self._advance()
                stages.append(self._parse_mv_expand())
            elif self._match_keyword("getschema"):
                self._advance()
                stages.append(GetSchemaStage())
            elif self._match_keyword("render"):
                self._advance()
                render_hint = self._parse_render()
            else:
                raise KqlParseError(
                    f"Unsupported KQL operator '{tok.value}'",
                    line=tok.line,
                    column=tok.col,
                )

        return KqlPipeline(table=table, stages=stages, lets=lets, render_hint=render_hint)

    def _parse_table_name(self) -> str:
        tok = self._peek()
        if tok.type in (TT.IDENT, TT.KEYWORD):
            self._advance()
            return tok.value
        raise KqlParseError(
            f"Expected table name, got '{tok.value}'",
            line=tok.line,
            column=tok.col,
        )

    def _parse_let(self) -> LetBinding:
        """Parse: let name = expr;

        Sub-pipelines (let x = Table | where ...) are recursively transpiled
        so they become proper CTEs in the output SQL.
        """
        self._advance()  # consume 'let'
        name_tok = self._advance()
        self._expect(TT.EQ)

        expr_tokens: list[str] = []
        depth = 0
        while self._peek().type != TT.EOF:
            tok = self._peek()
            if tok.type == TT.LPAREN:
                depth += 1
            elif tok.type == TT.RPAREN:
                depth -= 1
            if depth == 0 and tok.type == TT.SEMICOLON:
                break
            expr_tokens.append(self._advance().value)
        raw_expr = " ".join(expr_tokens).strip()

        first_word = raw_expr.split()[0] if raw_expr else ""
        if first_word in MDE_TABLES and "|" in raw_expr:
            try:
                sql_expr = KqlTranspiler.transpile(raw_expr)
                return LetBinding(name=name_tok.value, expression=sql_expr)
            except Exception:
                pass

        return LetBinding(name=name_tok.value, expression=raw_expr)

    # --- Stage parsers ---

    def _parse_where(self) -> WhereStage:
        return WhereStage(predicate=self._parse_predicate())

    def _parse_project(self) -> ProjectStage:
        cols: list[Assignment] = []
        while self._peek().type not in (TT.PIPE, TT.EOF):
            if self._peek().type == TT.COMMA:
                self._advance()
                continue
            cols.append(self._parse_column_expr())
        return ProjectStage(columns=cols)

    def _parse_project_away(self) -> ProjectAwayStage:
        return ProjectAwayStage(columns=self._parse_column_list())

    def _parse_extend(self) -> ExtendStage:
        assignments: list[Assignment] = []
        while self._peek().type not in (TT.PIPE, TT.EOF):
            if self._peek().type == TT.COMMA:
                self._advance()
                continue
            assignments.append(self._parse_column_expr())
        return ExtendStage(assignments=assignments)

    def _parse_summarize(self) -> SummarizeStage:
        aggs: list[Assignment] = []
        while not self._match_keyword("by") and self._peek().type not in (TT.PIPE, TT.EOF):
            aggs.append(self._parse_column_expr())
            if self._peek().type == TT.COMMA:
                self._advance()

        by_cols: list[Any] = []
        if self._match_keyword("by"):
            self._advance()
            while self._peek().type not in (TT.PIPE, TT.EOF):
                if self._peek().type == TT.COMMA:
                    self._advance()
                    continue
                by_cols.append(self._parse_expression())
        return SummarizeStage(aggregations=aggs, by_columns=by_cols)

    def _parse_order(self) -> OrderStage:
        cols: list[tuple[str, str]] = []
        while self._peek().type not in (TT.PIPE, TT.EOF):
            tok = self._advance()
            col_name = tok.value
            direction = "asc"
            if self._match_keyword("asc"):
                self._advance()
            elif self._match_keyword("desc"):
                self._advance()
                direction = "desc"
            cols.append((col_name, direction))
            if self._peek().type == TT.COMMA:
                self._advance()
        return OrderStage(columns=cols)

    def _parse_top(self) -> TopStage:
        n_tok = self._advance()
        n = int(n_tok.value)
        if self._match_keyword("by"):
            self._advance()
        col_tok = self._advance()
        direction = "desc"
        if self._match_keyword("asc"):
            self._advance()
            direction = "asc"
        elif self._match_keyword("desc"):
            self._advance()
        return TopStage(n=n, by_col=col_tok.value, direction=direction)

    def _parse_limit(self) -> LimitStage:
        return LimitStage(n=int(self._advance().value))

    def _parse_distinct(self) -> DistinctStage:
        return DistinctStage(columns=self._parse_column_list())

    def _parse_join(self) -> JoinStage:
        kind = "inner"
        if self._match_keyword("kind"):
            self._advance()
            self._expect(TT.EQ)
            kind = self._advance().value.lower()
        right_table = ""
        on_cols: list[str] = []
        if self._peek().type == TT.LPAREN:
            self._advance()
            right_table = self._parse_table_name()
            while self._peek().type not in (TT.RPAREN, TT.EOF):
                self._advance()
            if self._peek().type == TT.RPAREN:
                self._advance()
        if self._match_keyword("on"):
            self._advance()
            on_cols = self._parse_column_list()
        return JoinStage(kind=kind, right_table=right_table, on_columns=on_cols)

    def _parse_union(self) -> UnionStage:
        tables: list[str] = []
        while self._peek().type not in (TT.PIPE, TT.EOF):
            if self._peek().type == TT.LPAREN:
                self._advance()
                tables.append(self._parse_table_name())
                if self._peek().type == TT.RPAREN:
                    self._advance()
            elif self._peek().type == TT.COMMA:
                self._advance()
            else:
                tables.append(self._advance().value)
        return UnionStage(tables=tables)

    def _parse_mv_expand(self) -> MvExpandStage:
        return MvExpandStage(column=self._advance().value)

    def _parse_render(self) -> str:
        if self._peek().type in (TT.IDENT, TT.KEYWORD):
            return self._advance().value
        return "table"

    # --- Column list (bare names only — for project-away, distinct) ---

    def _parse_column_list(self) -> list[str]:
        cols: list[str] = []
        while self._peek().type not in (TT.PIPE, TT.EOF):
            tok = self._peek()
            if tok.type == TT.KEYWORD and tok.value.lower() == "by":
                break
            if tok.type == TT.COMMA:
                self._advance()
                continue
            tok = self._advance()
            col = tok.value
            while self._peek().type == TT.DOT:
                self._advance()
                col += "." + self._advance().value
            cols.append(col)
        return cols

    # --- Column expression (assignment or bare expr — for project, extend, summarize) ---

    def _parse_column_expr(self) -> Assignment:
        """Parse `alias = expr` or a bare expression.

        Returns Assignment("", expr) for bare expressions (no alias),
        Assignment(name, expr) for alias-qualified expressions.
        """
        tok = self._peek()

        # If first token is a recognized function keyword, parse without alias
        if tok.type in (TT.KEYWORD, TT.IDENT) and tok.value.lower() in _FUNC_KEYWORDS:
            expr = self._parse_expression()
            return Assignment(name="", expr=expr)

        # Could be `ColumnName` or `Alias = expr`
        name_tok = self._advance()

        if self._peek().type == TT.EQ and self._peek().value == "=":
            self._advance()  # consume single '='
            expr = self._parse_expression()
            return Assignment(name=name_tok.value, expr=expr)

        # Bare column reference — possibly dotted
        col = name_tok.value
        while self._peek().type == TT.DOT:
            self._advance()
            col += "." + self._advance().value

        # Tokenizer may merge dots into IDENT (AdditionalFields.Key → one token)
        if "." in col:
            parts = col.split(".", 1)
            return Assignment(name="", expr=ColumnRef(column=parts[0], path=parts[1]))
        return Assignment(name="", expr=ColumnRef(column=col))

    # --- Predicate / expression parsing (returns typed Expr nodes) ---

    def _parse_predicate(self) -> Any:
        return self._parse_or_expr()

    def _parse_or_expr(self) -> Any:
        left = self._parse_and_expr()
        while self._peek().type == TT.OR:
            self._advance()
            right = self._parse_and_expr()
            left = BinaryOp(op="OR", left=left, right=right)
        return left

    def _parse_and_expr(self) -> Any:
        left = self._parse_not_expr()
        while self._peek().type == TT.AND:
            self._advance()
            right = self._parse_not_expr()
            left = BinaryOp(op="AND", left=left, right=right)
        return left

    def _parse_not_expr(self) -> Any:
        if self._peek().type == TT.NOT:
            self._advance()
            inner = self._parse_comparison()
            return UnaryOp(op="NOT", operand=inner)
        return self._parse_comparison()

    def _parse_comparison(self) -> Any:
        left = self._parse_expression()
        tok = self._peek()

        if tok.type == TT.EQ:
            self._advance()
            return BinaryOp("=", left, self._parse_expression())
        elif tok.type == TT.NEQ:
            self._advance()
            return BinaryOp("!=", left, self._parse_expression())
        elif tok.type == TT.EQ_TILDE:
            self._advance()
            return BinaryOp("=~", left, self._parse_expression())
        elif tok.type == TT.NEQ_TILDE:
            self._advance()
            return BinaryOp("!~", left, self._parse_expression())
        elif tok.type == TT.LT:
            self._advance()
            return BinaryOp("<", left, self._parse_expression())
        elif tok.type == TT.LTE:
            self._advance()
            return BinaryOp("<=", left, self._parse_expression())
        elif tok.type == TT.GT:
            self._advance()
            return BinaryOp(">", left, self._parse_expression())
        elif tok.type == TT.GTE:
            self._advance()
            return BinaryOp(">=", left, self._parse_expression())
        elif self._match_keyword("contains"):
            self._advance()
            return BinaryOp("contains", left, self._parse_expression())
        elif self._match_keyword("startswith"):
            self._advance()
            return BinaryOp("startswith", left, self._parse_expression())
        elif self._match_keyword("endswith"):
            self._advance()
            return BinaryOp("endswith", left, self._parse_expression())
        elif self._match_keyword("has_any"):
            self._advance()
            self._expect(TT.LPAREN)
            value_args = self._parse_func_args()
            self._expect(TT.RPAREN)
            return FunctionCall("has_any", [left] + value_args)
        elif self._match_keyword("has"):
            self._advance()
            return BinaryOp("has", left, self._parse_expression())
        elif tok.type == TT.KEYWORD and tok.value.lower() == "matches":
            self._advance()  # consume "matches"
            if self._peek().type in (TT.KEYWORD, TT.IDENT) and self._peek().value.lower() == "regex":
                self._advance()  # consume "regex"
            return BinaryOp("matches regex", left, self._parse_expression())
        elif self._match_keyword("in"):
            self._advance()
            values = self._parse_value_list()
            return BinaryOp("in", left, values)
        elif tok.type == TT.BANG:
            # !in operator — consume ! then check for 'in'
            self._advance()  # consume !
            if self._match_keyword("in"):
                self._advance()  # consume 'in'
                values = self._parse_value_list()
                return BinaryOp("!in", left, values)
            # Fall through: return left unchanged
        elif self._match_keyword("between"):
            self._advance()
            self._expect(TT.LPAREN)
            low = self._parse_expression()
            # Consume '..' — two DOT tokens
            if self._peek().type == TT.DOT:
                self._advance()
            if self._peek().type == TT.DOT:
                self._advance()
            high = self._parse_expression()
            self._expect(TT.RPAREN)
            return BinaryOp("between", left, [low, high])
        elif self._match_keyword("isempty"):
            self._advance()
            self._expect(TT.LPAREN)
            self._expect(TT.RPAREN)
            return FunctionCall("isempty", [left])
        elif self._match_keyword("isnotempty"):
            self._advance()
            self._expect(TT.LPAREN)
            self._expect(TT.RPAREN)
            return FunctionCall("isnotempty", [left])
        return left

    def _parse_value_list(self) -> list:
        """Parse (val1, val2, ...) returning a list of Expr nodes."""
        if self._peek().type == TT.LPAREN:
            self._advance()
        values: list[Any] = []
        while self._peek().type not in (TT.RPAREN, TT.EOF):
            if self._peek().type == TT.COMMA:
                self._advance()
                continue
            values.append(self._parse_expression())
        if self._peek().type == TT.RPAREN:
            self._advance()
        return values

    def _parse_expression(self) -> Any:
        """Parse a single value, function call, or column reference → typed Expr node."""
        tok = self._peek()

        if tok.type == TT.LPAREN:
            self._advance()
            inner = self._parse_predicate()
            self._expect(TT.RPAREN)
            return inner  # No wrapping node needed — parentheses are structural

        if tok.type == TT.STRING:
            self._advance()
            return Literal(value=tok.value, dtype="string")

        if tok.type == TT.NUMBER:
            self._advance()
            return Literal(value=tok.value, dtype="number")

        if tok.type == TT.BOOLEAN:
            self._advance()
            return Literal(value=tok.value.lower(), dtype="bool")

        if tok.type == TT.NULL:
            self._advance()
            return Literal(value=None, dtype="null")

        if tok.type in (TT.KEYWORD, TT.IDENT):
            value = tok.value.lower()

            if value == "ago":
                return self._parse_ago()

            if value == "bin":
                return self._parse_bin()

            if value == "count":
                self._advance()
                if self._peek().type == TT.LPAREN:
                    self._advance()
                    self._expect(TT.RPAREN)
                return FunctionCall("count", [])

            if value == "dcount":
                self._advance()
                self._expect(TT.LPAREN)
                col = self._parse_expression()
                self._expect(TT.RPAREN)
                return FunctionCall("dcount", [col])

            if value in ("sum", "avg", "min", "max"):
                self._advance()
                self._expect(TT.LPAREN)
                col = self._parse_expression()
                self._expect(TT.RPAREN)
                return FunctionCall(value, [col])

            if value == "toupper":
                self._advance()
                self._expect(TT.LPAREN)
                col = self._parse_expression()
                self._expect(TT.RPAREN)
                return FunctionCall("toupper", [col])

            if value == "tolower":
                self._advance()
                self._expect(TT.LPAREN)
                col = self._parse_expression()
                self._expect(TT.RPAREN)
                return FunctionCall("tolower", [col])

            if value == "tostring":
                self._advance()
                self._expect(TT.LPAREN)
                col = self._parse_expression()
                self._expect(TT.RPAREN)
                return FunctionCall("tostring", [col])

            if value == "toint":
                self._advance()
                self._expect(TT.LPAREN)
                col = self._parse_expression()
                self._expect(TT.RPAREN)
                return FunctionCall("toint", [col])

            if value == "tolong":
                self._advance()
                self._expect(TT.LPAREN)
                col = self._parse_expression()
                self._expect(TT.RPAREN)
                return FunctionCall("tolong", [col])

            if value == "strcat":
                self._advance()
                self._expect(TT.LPAREN)
                args = self._parse_func_args()
                self._expect(TT.RPAREN)
                return FunctionCall("strcat", args)

            if value == "split":
                self._advance()
                self._expect(TT.LPAREN)
                args = self._parse_func_args()
                self._expect(TT.RPAREN)
                return FunctionCall("split", args)

            if value == "parse_json":
                self._advance()
                self._expect(TT.LPAREN)
                col = self._parse_expression()
                self._expect(TT.RPAREN)
                return col  # parse_json is a no-op at expression level; json_extract at access

            # Column reference — possibly dotted (AdditionalFields.Key)
            self._advance()
            col_name = tok.value
            while self._peek().type == TT.DOT:
                self._advance()
                col_name += "." + self._advance().value

            # Tokenizer may merge dots into IDENT (AdditionalFields.Key → single token)
            if "." in col_name:
                parts = col_name.split(".", 1)
                return ColumnRef(column=parts[0], path=parts[1])
            return ColumnRef(column=col_name)

        if tok.type == TT.MINUS:
            self._advance()
            return UnaryOp(op="MINUS", operand=self._parse_expression())

        raise KqlParseError(
            f"Unexpected token '{tok.value}'",
            line=tok.line,
            column=tok.col,
        )

    def _parse_ago(self) -> FunctionCall:
        """ago(7d) → FunctionCall("ago", [Literal("7d", "number")])"""
        self._advance()  # consume 'ago'
        self._expect(TT.LPAREN)
        duration_tok = self._advance()
        self._expect(TT.RPAREN)
        return FunctionCall("ago", [Literal(value=duration_tok.value, dtype="number")])

    def _parse_bin(self) -> FunctionCall:
        """bin(Timestamp, 1h) → FunctionCall("bin", [ColumnRef, Literal])"""
        self._advance()  # consume 'bin'
        self._expect(TT.LPAREN)
        col = self._parse_expression()
        self._expect(TT.COMMA)
        duration_tok = self._advance()
        self._expect(TT.RPAREN)
        return FunctionCall("bin", [col, Literal(value=duration_tok.value, dtype="number")])

    def _parse_func_args(self) -> list:
        args: list[Any] = []
        while self._peek().type not in (TT.RPAREN, TT.EOF):
            if self._peek().type == TT.COMMA:
                self._advance()
                continue
            args.append(self._parse_expression())
        return args


# ---------------------------------------------------------------------------
# Duration helpers
# ---------------------------------------------------------------------------

_DURATION_UNITS: dict[str, str] = {
    "d": "DAY", "h": "HOUR", "m": "MINUTE", "s": "SECOND", "ms": "MILLISECOND",
}

_BIN_UNITS: dict[str, str] = {
    "d": "day", "h": "hour", "m": "minute", "s": "second",
}


def _parse_duration_to_sql(duration: str, line: int, col: int) -> str:
    """'7d' → 'NOW() - INTERVAL 7 DAY'"""
    match = re.fullmatch(r"(\d+(?:\.\d+)?)(ms|[dhms])", duration)
    if not match:
        raise KqlParseError(
            f"Invalid duration '{duration}' — expected format like 7d, 24h, 30m",
            line=line,
            column=col,
        )
    n, unit_suffix = match.groups()
    sql_unit = _DURATION_UNITS.get(unit_suffix, "SECOND")
    # Use integer if no decimal part
    n_str = str(int(float(n))) if float(n) == int(float(n)) else n
    return f"NOW() - INTERVAL {n_str} {sql_unit}"


def _parse_bin_unit(duration: str, line: int, col: int) -> str:
    """'1h' → 'hour' (for date_trunc)"""
    match = re.fullmatch(r"\d+(ms|[dhms])", duration)
    if not match:
        raise KqlParseError(f"Invalid bin duration '{duration}'", line=line, column=col)
    return _BIN_UNITS.get(match.group(1), "second")


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------

@dataclass
class SchemaWarning:
    """Column reference that does not exist in the MDE schema for a known table."""
    column: str
    table: str
    message: str


@dataclass
class EmitResult:
    """Output of SqlEmitter.emit(): SQL plus metadata for the query router."""
    sql: str
    render_hint: Optional[str]
    warnings: list  # list[SchemaWarning]
    cte_names: list[str]


class SchemaValidator:
    """Validates column references in a KqlPipeline against the MDE schema registry.

    Validation is advisory — unknown columns generate SchemaWarnings rather
    than hard errors, because let-bindings and computed columns create valid
    column aliases that don't appear in the static schema.
    """

    def validate(self, pipeline: KqlPipeline) -> list[SchemaWarning]:
        """Return SchemaWarning for every column not in the MDE schema."""
        table = pipeline.table
        if table not in MDE_TABLES:
            return []  # Unknown table (let alias or future table) — skip

        referenced: set[str] = self._collect_column_refs(pipeline)
        invalid_names = validate_columns(table, list(referenced))
        return [
            SchemaWarning(
                column=col,
                table=table,
                message=f"Column '{col}' does not exist in MDE table '{table}'",
            )
            for col in invalid_names
        ]

    def validate_mde_portable(self, pipeline: KqlPipeline) -> list[str]:
        """Return error strings for columns that would fail in real MDE/Sentinel."""
        warnings = self.validate(pipeline)
        return [w.message for w in warnings]

    def _collect_column_refs(self, pipeline: KqlPipeline) -> set[str]:
        """Walk stages and collect bare column names (not json_extract paths)."""
        refs: set[str] = set()
        for stage in pipeline.stages:
            if isinstance(stage, (WhereStage,)):
                self._collect_from_expr(stage.predicate, refs)
            elif isinstance(stage, ProjectStage):
                for a in stage.columns:
                    self._collect_from_expr(a.expr, refs)
            elif isinstance(stage, ExtendStage):
                for a in stage.assignments:
                    self._collect_from_expr(a.expr, refs)
            elif isinstance(stage, SummarizeStage):
                for a in stage.aggregations:
                    self._collect_from_expr(a.expr, refs)
                for expr in stage.by_columns:
                    self._collect_from_expr(expr, refs)
        return refs

    def _collect_from_expr(self, expr: Any, refs: set[str]) -> None:
        if isinstance(expr, ColumnRef):
            refs.add(expr.column)
        elif isinstance(expr, FunctionCall):
            for arg in expr.args:
                self._collect_from_expr(arg, refs)
        elif isinstance(expr, BinaryOp):
            self._collect_from_expr(expr.left, refs)
            if isinstance(expr.right, list):
                for item in expr.right:
                    self._collect_from_expr(item, refs)
            else:
                self._collect_from_expr(expr.right, refs)
        elif isinstance(expr, UnaryOp):
            self._collect_from_expr(expr.operand, refs)
        elif isinstance(expr, Assignment):
            self._collect_from_expr(expr.expr, refs)


# ---------------------------------------------------------------------------
# SQL Emitter — typed AST → DuckDB SQL string
# ---------------------------------------------------------------------------

class SqlEmitter:
    """Converts a KqlPipeline AST to DuckDB SQL, returning an EmitResult."""

    def emit(self, pipeline: KqlPipeline, warnings: Optional[list] = None) -> EmitResult:
        table = pipeline.table
        if table not in MDE_TABLES and table not in MDE_TABLES:
            logger.debug("KQL references unknown table: %s", table)

        ctes: list[str] = []
        cte_names: list[str] = []
        for let in pipeline.lets:
            ctes.append(f"{let.name} AS ({let.expression})")
            cte_names.append(let.name)

        select_clause = "*"
        where_clauses: list[str] = []
        group_by: Optional[str] = None
        order_by: Optional[str] = None
        limit_clause: Optional[str] = None
        distinct = False

        for stage in pipeline.stages:
            if isinstance(stage, WhereStage):
                where_clauses.append(self._emit_expr(stage.predicate))

            elif isinstance(stage, ProjectStage):
                parts = [self._emit_assignment_as_select(a) for a in stage.columns]
                select_clause = ", ".join(parts)

            elif isinstance(stage, ProjectAwayStage):
                tbl = MDE_TABLES.get(table)
                if tbl:
                    kept = [c.name for c in tbl.columns if c.name not in stage.columns]
                    select_clause = ", ".join(kept) if kept else "*"
                # Unknown table — leave select_clause as "*"

            elif isinstance(stage, ExtendStage):
                parts = [self._emit_assignment_as_select(a) for a in stage.assignments]
                if select_clause == "*":
                    select_clause = "*, " + ", ".join(parts)
                else:
                    select_clause += ", " + ", ".join(parts)

            elif isinstance(stage, SummarizeStage):
                agg_parts = [self._emit_assignment_as_select(a) for a in stage.aggregations]
                by_parts = [self._emit_expr(c) for c in stage.by_columns]
                if by_parts:
                    select_clause = ", ".join(by_parts + agg_parts)
                    group_by = ", ".join(by_parts)
                else:
                    select_clause = ", ".join(agg_parts)

            elif isinstance(stage, OrderStage):
                parts = [f"{col} {direction.upper()}" for col, direction in stage.columns]
                order_by = ", ".join(parts)

            elif isinstance(stage, LimitStage):
                limit_clause = str(stage.n)

            elif isinstance(stage, TopStage):
                order_by = f"{stage.by_col} {stage.direction.upper()}"
                limit_clause = str(stage.n)

            elif isinstance(stage, DistinctStage):
                distinct = True
                if stage.columns and stage.columns != ["*"]:
                    select_clause = ", ".join(stage.columns)

            elif isinstance(stage, MvExpandStage):
                col = stage.column
                where_clauses.append(f"1=1")  # placeholder; real expansion via CROSS JOIN
                select_clause = f"*, t_{col}.{col}"
                # Append CROSS JOIN to FROM — handled in SQL assembly below
                sql = self._assemble_sql(
                    select_clause="*",
                    table=table,
                    where_clauses=where_clauses[:-1],
                    group_by=None,
                    order_by=None,
                    limit_clause=None,
                    distinct=distinct,
                    extra_join=f"CROSS JOIN UNNEST({col}) AS t_{col}({col})",
                    ctes=ctes,
                )
                return EmitResult(
                    sql=sql,
                    render_hint=pipeline.render_hint,
                    warnings=warnings or [],
                    cte_names=cte_names,
                )

            elif isinstance(stage, GetSchemaStage):
                tbl_def = MDE_TABLES.get(table)
                if tbl_def:
                    rows = [
                        f"('{col.name}', {i}, '{col.dtype}', '{col.dtype}')"
                        for i, col in enumerate(tbl_def.columns)
                    ]
                    values_sql = ",\n  ".join(rows)
                    sql = (
                        f"SELECT * FROM (VALUES\n  {values_sql}\n)"
                        f" t(ColumnName, ColumnOrdinal, DataType, ColumnType)"
                    )
                else:
                    sql = (
                        "SELECT NULL AS ColumnName, NULL AS ColumnOrdinal, "
                        "NULL AS DataType, NULL AS ColumnType WHERE 1=0"
                    )
                if ctes:
                    sql = f"WITH {', '.join(ctes)}\n{sql}"
                return EmitResult(
                    sql=sql,
                    render_hint=pipeline.render_hint,
                    warnings=warnings or [],
                    cte_names=cte_names,
                )

            elif isinstance(stage, JoinStage):
                join_type_map = {
                    "inner": "INNER JOIN",
                    "leftouter": "LEFT JOIN",
                    "leftanti": "LEFT JOIN",
                }
                join_type = join_type_map.get(stage.kind, "INNER JOIN")
                on_clause = " AND ".join(f"t1.{c} = t2.{c}" for c in stage.on_columns)
                sql = f"SELECT t1.* FROM {table} t1 {join_type} {stage.right_table} t2 ON {on_clause}"
                if stage.kind == "leftanti":
                    null_check = " AND ".join(f"t2.{c} IS NULL" for c in stage.on_columns)
                    sql += f" WHERE {null_check}"
                if ctes:
                    sql = f"WITH {', '.join(ctes)}\n{sql}"
                return EmitResult(
                    sql=sql,
                    render_hint=pipeline.render_hint,
                    warnings=warnings or [],
                    cte_names=cte_names,
                )

            elif isinstance(stage, UnionStage):
                parts = [f"SELECT * FROM {t}" for t in [table] + stage.tables]
                sql = " UNION ALL ".join(parts)
                if ctes:
                    sql = f"WITH {', '.join(ctes)}\n{sql}"
                return EmitResult(
                    sql=sql,
                    render_hint=pipeline.render_hint,
                    warnings=warnings or [],
                    cte_names=cte_names,
                )

        sql = self._assemble_sql(
            select_clause=select_clause,
            table=table,
            where_clauses=where_clauses,
            group_by=group_by,
            order_by=order_by,
            limit_clause=limit_clause,
            distinct=distinct,
            extra_join=None,
            ctes=ctes,
        )
        return EmitResult(
            sql=sql,
            render_hint=pipeline.render_hint,
            warnings=warnings or [],
            cte_names=cte_names,
        )

    def _assemble_sql(
        self,
        select_clause: str,
        table: str,
        where_clauses: list[str],
        group_by: Optional[str],
        order_by: Optional[str],
        limit_clause: Optional[str],
        distinct: bool,
        extra_join: Optional[str],
        ctes: list[str],
    ) -> str:
        distinct_kw = "DISTINCT " if distinct else ""
        sql = f"SELECT {distinct_kw}{select_clause}\nFROM {table}"
        if extra_join:
            sql += f"\n{extra_join}"
        if where_clauses:
            combined = " AND ".join(f"({c})" for c in where_clauses)
            sql += f"\nWHERE {combined}"
        if group_by:
            sql += f"\nGROUP BY {group_by}"
        if order_by:
            sql += f"\nORDER BY {order_by}"
        if limit_clause:
            sql += f"\nLIMIT {limit_clause}"
        if ctes:
            sql = f"WITH {', '.join(ctes)}\n{sql}"
        return sql

    def _emit_assignment_as_select(self, a: Assignment) -> str:
        expr_str = self._emit_expr(a.expr)
        if a.name:
            return f"{expr_str} AS {a.name}"
        return expr_str

    def _emit_expr(self, expr: Any) -> str:
        """Convert a typed AST expression node to a DuckDB SQL string."""
        if isinstance(expr, ColumnRef):
            if expr.path:
                return f"json_extract({expr.column}, '$.{expr.path}')"
            return expr.column

        if isinstance(expr, Literal):
            if expr.dtype == "string":
                escaped = str(expr.value).replace("'", "''")
                return f"'{escaped}'"
            if expr.dtype == "bool":
                return expr.value.upper()
            if expr.dtype == "null":
                return "NULL"
            # number (plain or timespan — duration handled by FunctionCall("ago"/bin))
            return str(expr.value)

        if isinstance(expr, FunctionCall):
            return self._emit_function(expr)

        if isinstance(expr, BinaryOp):
            return self._emit_binary(expr)

        if isinstance(expr, UnaryOp):
            operand = self._emit_expr(expr.operand)
            if expr.op == "NOT":
                return f"NOT ({operand})"
            return f"-{operand}"

        # Fallback for any unexpected node type
        return str(expr)

    def _emit_function(self, func: FunctionCall) -> str:
        name = func.name.lower()
        args = func.args

        if name == "ago":
            duration = self._emit_expr(args[0])
            # duration is a raw number string like "7d"
            return _parse_duration_to_sql(str(args[0].value), 0, 0)

        if name == "bin":
            col = self._emit_expr(args[0])
            duration_lit = args[1]
            unit = _parse_bin_unit(str(duration_lit.value), 0, 0)
            return f"date_trunc('{unit}', {col})"

        if name == "count":
            return "COUNT(*)"

        if name == "dcount":
            col = self._emit_expr(args[0])
            return f"COUNT(DISTINCT {col})"

        if name in ("sum", "avg", "min", "max"):
            col = self._emit_expr(args[0])
            return f"{name.upper()}({col})"

        if name == "toupper":
            return f"UPPER({self._emit_expr(args[0])})"

        if name == "tolower":
            return f"LOWER({self._emit_expr(args[0])})"

        if name == "tostring":
            return f"CAST({self._emit_expr(args[0])} AS VARCHAR)"

        if name == "toint":
            return f"CAST({self._emit_expr(args[0])} AS INTEGER)"

        if name == "tolong":
            return f"CAST({self._emit_expr(args[0])} AS BIGINT)"

        if name == "strcat":
            return f"CONCAT({', '.join(self._emit_expr(a) for a in args)})"

        if name == "split":
            return f"string_split({', '.join(self._emit_expr(a) for a in args)})"

        if name == "has_any":
            # args[0] is the column expr; args[1:] are the values to match
            col = self._emit_expr(args[0])
            if len(args) < 2:
                return "FALSE"
            parts = [
                f"LOWER({col}) LIKE LOWER(CONCAT('%', {self._emit_expr(v)}, '%'))"
                for v in args[1:]
            ]
            return " OR ".join(parts)

        if name == "isempty":
            col = self._emit_expr(args[0])
            return f"({col} IS NULL OR {col} = '')"

        if name == "isnotempty":
            col = self._emit_expr(args[0])
            return f"({col} IS NOT NULL AND {col} != '')"

        # Generic fallback
        arg_strs = ", ".join(self._emit_expr(a) for a in args)
        return f"{name.upper()}({arg_strs})"

    def _emit_binary(self, expr: BinaryOp) -> str:
        left = self._emit_expr(expr.left)
        op = expr.op

        # List-valued right operand (in, !in, between)
        if op == "in":
            values = [self._emit_expr(v) for v in expr.right]
            return f"{left} IN ({', '.join(values)})"
        if op == "!in":
            values = [self._emit_expr(v) for v in expr.right]
            return f"{left} NOT IN ({', '.join(values)})"
        if op == "between":
            low, high = expr.right
            return f"{left} BETWEEN {self._emit_expr(low)} AND {self._emit_expr(high)}"

        right = self._emit_expr(expr.right)

        if op == "=":
            return f"{left} = {right}"
        if op == "!=":
            return f"{left} != {right}"
        if op == "=~":
            return f"LOWER({left}) = LOWER({right})"
        if op == "!~":
            return f"LOWER({left}) != LOWER({right})"
        if op == "<":
            return f"{left} < {right}"
        if op == "<=":
            return f"{left} <= {right}"
        if op == ">":
            return f"{left} > {right}"
        if op == ">=":
            return f"{left} >= {right}"
        if op == "contains":
            return f"LOWER({left}) LIKE LOWER(CONCAT('%', {right}, '%'))"
        if op == "startswith":
            return f"LOWER({left}) LIKE LOWER(CONCAT({right}, '%'))"
        if op == "endswith":
            return f"LOWER({left}) LIKE LOWER(CONCAT('%', {right}))"
        if op == "has":
            return f"LOWER({left}) LIKE LOWER(CONCAT('%', {right}, '%'))"
        if op == "matches regex":
            return f"regexp_matches({left}, {right})"
        if op == "AND":
            return f"({left} AND {right})"
        if op == "OR":
            return f"({left} OR {right})"

        return f"{left} {op} {right}"

    def _emit_column(self, col: Any) -> str:
        """Emit a column — accepts str (legacy) or typed ColumnRef."""
        if isinstance(col, ColumnRef):
            return self._emit_expr(col)
        if isinstance(col, str) and "." in col and not col.startswith("json_extract"):
            parts = col.split(".", 1)
            return f"json_extract({parts[0]}, '$.{parts[1]}')"
        return str(col)


# Backward-compatible alias — KqlEmitter was the previous class name
KqlEmitter = SqlEmitter


# ---------------------------------------------------------------------------
# Injection guard
# ---------------------------------------------------------------------------

def _check_for_injection(kql: str) -> None:
    """Reject queries containing SQL DDL/DML keywords that bypass KQL syntax.

    A correctly parsed KQL query never contains DROP/INSERT/etc. in the input.
    This guard catches obfuscation attempts and tokenizer edge cases.
    """
    dangerous = re.compile(
        r"\b(DROP|DELETE|INSERT|UPDATE|CREATE|ALTER|EXEC|EXECUTE|PRAGMA)\b",
        re.IGNORECASE,
    )
    if dangerous.search(kql):
        raise KqlParseError(
            "Query contains disallowed SQL keywords.",
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class KqlTranspiler:
    """Entry point for KQL → DuckDB SQL transpilation.

    KqlTranspiler.transpile(kql) → str is the backward-compatible API.
    For richer output, use SqlEmitter.emit(pipeline) → EmitResult directly.

    Pipeline:
      KqlTokenizer.tokenize()   →  list[KqlToken]
      KqlParser.parse()         →  KqlPipeline (typed AST)
      SchemaValidator.validate() → list[SchemaWarning]
      SqlEmitter.emit()         →  EmitResult
    """

    @staticmethod
    def transpile(kql: str) -> str:
        """Transpile a KQL query string to DuckDB SQL.

        Raises:
            KqlParseError: On any lexical, syntactic, or injection-check failure.
            QueryException: Base class; callers catching this are unaffected.
        """
        _check_for_injection(kql)

        tokens = KqlTokenizer(kql.strip()).tokenize()
        pipeline = KqlParser(tokens).parse()

        warnings = SchemaValidator().validate(pipeline)
        if warnings:
            logger.warning(
                "KQL schema warnings for table %s: %s",
                pipeline.table,
                [w.column for w in warnings],
            )

        result = SqlEmitter().emit(pipeline, warnings=warnings)
        logger.debug(
            "KQL transpiled | source=%.80s | sql=%.200s",
            kql.replace("\n", " "),
            result.sql.replace("\n", " "),
        )
        return result.sql
