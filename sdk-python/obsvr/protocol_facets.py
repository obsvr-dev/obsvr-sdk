"""Deterministic protocol facets (twin of sdk-typescript/src/policy/protocol-facets.ts).

A policy rule that matches a regex against a SQL string is guessing. The same
statement written with a comment, a different quote style, or a line break
defeats the pattern, and the pattern also fires on prose that merely mentions
the word. A rule that says "the verb is DROP" instead of "the text matches
``/drop\\s+table/i``" is asking a question about the STATEMENT rather than
about the characters, and gets an answer that survives reformatting.

This module decomposes a statement into addressable facets - ``sql.verb``,
``sql.target``, ``sql.tables``, ``sql.functions`` - which the rules engine's
``protocol_facet`` type matches against operator-declared values. Pure and
total: no clock, no I/O, no state, one linear pass.

Stdlib only, and it says what it cannot do
-------------------------------------------

A real SQL grammar is a dependency, and this package ships none. So this is a
bounded lexical decomposition, not a parser, and it is explicit about that:
every result carries ``parsed``, and one with ``parsed: False`` carries the
reason. What it handles is the shape of a statement - the leading verb, the
object a DDL statement names, the relations it reads or writes, and the
functions it calls. What it does NOT handle is nested subqueries as separate
scopes, CTEs, dialect-specific syntax, or anything requiring precedence.

Failing closed
--------------

Input this cannot decompose returns ``parsed: False``, and the rules engine
treats that as a MATCH: a rule that cannot evaluate must not quietly permit.
That is the opposite of the usual "no match, carry on", and it is the whole
reason the facet rule is worth having - an attacker who can make a statement
unparseable would otherwise have found the bypass.

Bounded on purpose: input beyond ``MAX_FACET_INPUT`` characters and token
counts beyond ``MAX_FACET_TOKENS`` stop the scan and report ``parsed: False``
with a reason, so a large input degrades into a refusal rather than into
unbounded work on a call path.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

__all__ = [
    "MAX_FACET_INPUT",
    "MAX_FACET_TOKENS",
    "strip_sql_comments",
    "extract_sql_facets",
    "read_facet",
    "SQL_FACET_NAMES",
]

#: Longest statement this will look at. Beyond it, ``parsed: False``.
MAX_FACET_INPUT = 8192

#: Most tokens this will produce. Beyond it, ``parsed: False``.
MAX_FACET_TOKENS = 2048

# Statement verbs recognised as the head of a SQL statement. A leading word
# outside this set means the text is not a statement this module can speak
# about, which is parsed: False rather than a guess.
_SQL_VERBS = frozenset(
    {
        "SELECT", "INSERT", "UPDATE", "DELETE", "MERGE", "REPLACE",
        "CREATE", "ALTER", "DROP", "TRUNCATE", "RENAME",
        "GRANT", "REVOKE",
        "CALL", "EXEC", "EXECUTE",
        "WITH", "EXPLAIN", "SET", "COMMIT", "ROLLBACK", "SAVEPOINT", "USE",
        "COPY", "VACUUM", "ANALYZE", "REINDEX", "CLUSTER", "COMMENT", "LOCK",
    }
)

# Object types a DDL verb can name, e.g. ``DROP TABLE x``.
_SQL_OBJECT_TYPES = frozenset(
    {
        "TABLE", "INDEX", "VIEW", "SCHEMA", "DATABASE", "SEQUENCE", "TRIGGER",
        "FUNCTION", "PROCEDURE", "ROLE", "USER", "TYPE", "EXTENSION", "POLICY",
        "MATERIALIZED", "TEMPORARY", "TEMP", "COLUMN", "CONSTRAINT",
    }
)

# Words that can precede a relation name. FROM/JOIN read, INTO/UPDATE write;
# both are relations the statement touches, which is what a policy cares about.
_RELATION_INTRODUCERS = frozenset({"FROM", "JOIN", "INTO", "UPDATE", "TABLE"})

# Verbs for which "the object this statement names" is a well-defined single
# thing. ``sql.target`` is computed only for these. SELECT and WITH are
# deliberately absent: the first name after SELECT is a column, and reporting
# it as the statement's target would be a confident wrong answer. GRANT and
# REVOKE are absent too - their object follows ON, and this does not follow it
# rather than guess at the first name it sees.
_TARGET_VERBS = frozenset(
    {
        "DROP", "CREATE", "ALTER", "TRUNCATE", "RENAME",
        "INSERT", "UPDATE", "DELETE", "MERGE", "REPLACE",
        "COMMENT", "LOCK", "CALL", "EXEC", "EXECUTE",
        "USE", "COPY", "VACUUM", "ANALYZE", "REINDEX", "CLUSTER",
    }
)

# Keywords that must never be mistaken for a relation or a function name.
# Deliberately narrow: it holds the words that actually appear right after a
# relation introducer or right before a parenthesis in ordinary SQL.
_NOT_A_NAME = frozenset(
    {
        "SELECT", "WHERE", "SET", "VALUES", "AS", "ON", "AND", "OR", "NOT", "IN",
        "EXISTS", "BY", "GROUP", "ORDER", "HAVING", "LIMIT", "OFFSET", "UNION",
        "ALL", "DISTINCT", "INNER", "LEFT", "RIGHT", "FULL", "OUTER", "CROSS",
        "NATURAL", "USING", "IF", "CASE", "WHEN", "THEN", "ELSE", "END", "ONLY",
    }
)

_IDENT_START = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_")
_IDENT_PART = _IDENT_START | frozenset("0123456789$.")
_WHITESPACE = frozenset(" \t\n\r\f\v")


def strip_sql_comments(text: str) -> str:
    """Strip SQL comments.

    Done before tokenising because a comment can sit inside a statement
    anywhere, including between a verb and its object - the classic way a
    pattern matching ``DROP\\s+TABLE`` is defeated while the statement still
    means exactly what it meant.

    Single-character scan, no regex, so there is no backtracking to exploit.
    String literals are respected: a ``--`` inside quotes is data.
    """
    out: List[str] = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c in ("'", '"', "`"):
            quote = c
            out.append(c)
            i += 1
            while i < n:
                if text[i] == quote:
                    if i + 1 < n and text[i + 1] == quote:
                        out.append(quote + quote)
                        i += 2
                        continue
                    out.append(quote)
                    i += 1
                    break
                out.append(text[i])
                i += 1
            continue
        if c == "-" and i + 1 < n and text[i + 1] == "-":
            while i < n and text[i] != "\n":
                i += 1
            out.append(" ")
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                i += 1
            i += 2
            out.append(" ")
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _tokenize(text: str):
    """Tokenise a comment-stripped statement. Linear, bounded, no regex."""
    tokens = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c in _WHITESPACE:
            i += 1
            continue
        if len(tokens) >= MAX_FACET_TOKENS:
            return tokens, True
        if c in ("'", '"', "`"):
            quote = c
            value_parts: List[str] = []
            i += 1
            while i < n:
                if text[i] == quote:
                    if i + 1 < n and text[i + 1] == quote:
                        value_parts.append(quote)
                        i += 2
                        continue
                    i += 1
                    break
                value_parts.append(text[i])
                i += 1
            value = "".join(value_parts)
            # A single-quoted run is a string LITERAL; double/backtick quoting
            # is a delimited IDENTIFIER. Only the latter can name a relation,
            # so the literal is marked and never used as a name.
            tokens.append(
                {
                    "value": value,
                    "upper": value.upper(),
                    "quoted": quote == "'",
                    "calls_out": i < n and text[i] == "(",
                }
            )
            continue
        if c in _IDENT_START:
            start = i
            i += 1
            while i < n and text[i] in _IDENT_PART:
                i += 1
            value = text[start:i]
            tokens.append(
                {
                    "value": value,
                    "upper": value.upper(),
                    "quoted": False,
                    "calls_out": i < n and text[i] == "(",
                }
            )
            continue
        # Punctuation and operators are structural.
        tokens.append({"value": c, "upper": c, "quoted": False, "calls_out": False})
        i += 1
    return tokens, False


def _unparsed(reason: str, multiple: bool = False) -> Dict[str, Any]:
    return {
        "parsed": False,
        "reason": reason,
        "tables": [],
        "functions": [],
        "multiple_statements": multiple,
    }


def _bare_name(value: str) -> str:
    """Strip a schema qualifier: ``public.users`` -> ``users``."""
    dot = value.rfind(".")
    return value if dot == -1 else value[dot + 1 :]


def extract_sql_facets(text: Any) -> Dict[str, Any]:
    """Decompose a SQL statement into facets.

    Deterministic and total: every input returns a result, and one that could
    not be decomposed says so rather than returning empty facets that would
    read as "nothing dangerous here". Pinned by
    conformance/fixtures/protocol_facets.json.
    """
    if not isinstance(text, str):
        return _unparsed("not_a_string")
    if not text:
        return _unparsed("empty")
    if len(text) > MAX_FACET_INPUT:
        return _unparsed("input_too_long")

    stripped = strip_sql_comments(text)
    tokens, truncated = _tokenize(stripped)
    if truncated:
        return _unparsed("too_many_tokens")
    if not tokens:
        return _unparsed("no_tokens")

    # Stacked statements: a trailing ';' is ordinary punctuation, but a ';'
    # with anything after it is a second statement. Worth its own facet,
    # because "one statement whose verb is SELECT" and "a SELECT followed by a
    # DROP" are the same string to a verb-only check.
    multiple = any(
        t["value"] == ";" and i < len(tokens) - 1 for i, t in enumerate(tokens)
    )

    first = tokens[0]
    if first["quoted"] or first["upper"] not in _SQL_VERBS:
        return _unparsed("unrecognized_verb", multiple)
    verb = first["upper"]

    tables = set()
    functions = set()
    target: Optional[str] = None

    def _is_name(t) -> bool:
        return (
            t is not None
            and not t["quoted"]
            and bool(t["value"])
            and t["value"][0] in _IDENT_START
            and t["upper"] not in _NOT_A_NAME
            and t["upper"] not in _SQL_OBJECT_TYPES
        )

    for i, t in enumerate(tokens):
        # A function call is an identifier immediately followed by '(' - the
        # adjacency matters, since `FROM (SELECT ...)` is not a call and only
        # the identifier form is claimed.
        if (
            t["calls_out"]
            and not t["quoted"]
            and t["value"]
            and t["value"][0] in _IDENT_START
            and t["upper"] not in _NOT_A_NAME
        ):
            functions.add(_bare_name(t["value"]).lower())

        if t["quoted"]:
            continue

        if t["upper"] in _RELATION_INTRODUCERS:
            # Skip DDL object-type words so `DROP TABLE users` names `users`,
            # and `CREATE MATERIALIZED VIEW v` reaches `v`.
            j = i + 1
            while j < len(tokens) and tokens[j]["upper"] in _SQL_OBJECT_TYPES:
                j += 1
            # `IF NOT EXISTS` / `IF EXISTS` sit between the type and the name.
            while j < len(tokens) and tokens[j]["upper"] in _NOT_A_NAME:
                j += 1
            candidate = tokens[j] if j < len(tokens) else None
            if _is_name(candidate) and not candidate["calls_out"]:
                tables.add(_bare_name(candidate["value"]).lower())
            continue

        # The object a statement names: the first name after the verb, past
        # any object-type word, existence word, or relation introducer
        # (INSERT INTO x, DELETE FROM x). Only for verbs that name one.
        if target is None and i == 0 and verb in _TARGET_VERBS:
            j = 1
            while j < len(tokens) and (
                tokens[j]["upper"] in _SQL_OBJECT_TYPES
                or tokens[j]["upper"] in _NOT_A_NAME
                or tokens[j]["upper"] in _RELATION_INTRODUCERS
            ):
                j += 1
            candidate = tokens[j] if j < len(tokens) else None
            # A trailing "(" is allowed here, unlike for a relation:
            # `CALL sp(1)` and `CREATE FUNCTION f(...)` name their object and
            # then open its argument list.
            if _is_name(candidate):
                target = _bare_name(candidate["value"]).lower()

    result: Dict[str, Any] = {"parsed": True, "verb": verb}
    if target is not None:
        result["target"] = target
    result["tables"] = sorted(tables)
    result["functions"] = sorted(functions)
    result["multiple_statements"] = multiple
    return result


#: The facet names a rule may address.
SQL_FACET_NAMES = (
    "sql.verb",
    "sql.target",
    "sql.tables",
    "sql.functions",
    "sql.multiple_statements",
)


def read_facet(facets: Dict[str, Any], name: str) -> List[str]:
    """Read one facet as a list of comparable strings.

    Scalar facets yield a one-element list and list facets yield themselves, so
    a rule's ``facet_in`` / ``facet_not_in`` semantics are the same shape
    regardless of which facet it addresses. An absent facet yields an empty
    list.
    """
    if name == "sql.verb":
        verb = facets.get("verb")
        return [] if verb is None else [verb.lower()]
    if name == "sql.target":
        target = facets.get("target")
        return [] if target is None else [target]
    if name == "sql.tables":
        return list(facets.get("tables") or [])
    if name == "sql.functions":
        return list(facets.get("functions") or [])
    if name == "sql.multiple_statements":
        return ["true" if facets.get("multiple_statements") else "false"]
    return []
