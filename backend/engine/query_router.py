"""
query_router.py — Routes queries by language to the correct transpiler.

This is the single dispatch point for all query execution. Adding a new language
(CQL, Sigma, YARA-L) means: implement a transpiler with a transpile() or validate()
method, then add it to SUPPORTED_LANGUAGES. Nothing else changes.
"""

from backend.engine.kql_transpiler import KqlTranspiler
from backend.engine.spl_transpiler import SplTranspiler
from backend.engine.sql_transpiler import SqlValidator
from backend.exceptions import QueryException

SUPPORTED_LANGUAGES: dict[str, type] = {
    "kql": KqlTranspiler,
    "spl": SplTranspiler,
    "sql": SqlValidator,
}


def route(query: str, language: str) -> str:
    """Transpile or validate a query and return DuckDB SQL.

    Args:
        query: The raw query string from the user.
        language: One of "kql", "spl", "sql".

    Returns:
        DuckDB SQL ready for execution via the pool.

    Raises:
        QueryException: If language is unsupported or transpilation fails.
    """
    lang_lower = language.lower().strip()
    if lang_lower not in SUPPORTED_LANGUAGES:
        raise QueryException(
            detail=f"Unsupported language '{language}'. Supported: {list(SUPPORTED_LANGUAGES.keys())}",
        )

    transpiler = SUPPORTED_LANGUAGES[lang_lower]
    if lang_lower == "sql":
        return transpiler.validate(query)
    return transpiler.transpile(query)
