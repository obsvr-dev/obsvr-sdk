/**
 * Deterministic protocol facets.
 *
 * A policy rule that matches a regex against a SQL string is guessing. The
 * same statement written with a comment, a different quote style, or a line
 * break defeats the pattern, and the pattern also fires on prose that merely
 * mentions the word. A rule that says "the verb is DROP" instead of "the text
 * matches /drop\s+table/i" is asking a question about the STATEMENT rather
 * than about the characters, and gets an answer that survives reformatting.
 *
 * This module decomposes a statement into addressable facets — `sql.verb`,
 * `sql.target`, `sql.tables`, `sql.functions` — which the rules engine's
 * `protocol_facet` type then matches against operator-declared values. It is
 * pure and total: no clock, no I/O, no state, one linear pass.
 *
 * ## Stdlib only, and it says what it cannot do
 *
 * A real SQL grammar is a dependency, and this package ships none. So this is
 * a bounded lexical decomposition, not a parser, and it is explicit about
 * that: every result carries `parsed`, and a result with `parsed: false`
 * carries the reason. What it handles is the shape of a statement — the
 * leading verb, the object a DDL statement names, the relations a query reads
 * or writes, and the functions it calls. What it does NOT handle is nested
 * subqueries as separate scopes, CTEs, dialect-specific syntax, or anything
 * requiring precedence. It reports what it found, and a caller that needs more
 * has to say so rather than assume.
 *
 * ## Failing closed
 *
 * Input this cannot decompose returns `parsed: false`, and the rules engine
 * treats that as a MATCH: a rule that cannot evaluate must not quietly permit.
 * That is the opposite of the usual "no match, carry on", and it is the whole
 * reason the facet rule is worth having — an attacker who can make a statement
 * unparseable would otherwise have found the bypass.
 *
 * Bounded on purpose: input beyond {@link MAX_FACET_INPUT} characters and
 * token counts beyond {@link MAX_FACET_TOKENS} stop the scan and report
 * `parsed: false` with a reason, so a large input degrades into a refusal
 * rather than into unbounded work on a call path.
 *
 * @packageDocumentation
 */

/** Longest statement this will look at. Beyond it, `parsed: false`. */
export const MAX_FACET_INPUT = 8192;

/** Most tokens this will produce. Beyond it, `parsed: false`. */
export const MAX_FACET_TOKENS = 2048;

/**
 * Statement verbs recognized as the head of a SQL statement. A leading word
 * outside this set means the text is not a statement this module can speak
 * about, which is `parsed: false` rather than a guess.
 */
const SQL_VERBS = new Set([
  "SELECT", "INSERT", "UPDATE", "DELETE", "MERGE", "REPLACE",
  "CREATE", "ALTER", "DROP", "TRUNCATE", "RENAME",
  "GRANT", "REVOKE",
  "CALL", "EXEC", "EXECUTE",
  "WITH", "EXPLAIN", "SET", "COMMIT", "ROLLBACK", "SAVEPOINT", "USE",
  "COPY", "VACUUM", "ANALYZE", "REINDEX", "CLUSTER", "COMMENT", "LOCK",
]);

/** Object types a DDL verb can name, e.g. `DROP TABLE x`. */
const SQL_OBJECT_TYPES = new Set([
  "TABLE", "INDEX", "VIEW", "SCHEMA", "DATABASE", "SEQUENCE", "TRIGGER",
  "FUNCTION", "PROCEDURE", "ROLE", "USER", "TYPE", "EXTENSION", "POLICY",
  "MATERIALIZED", "TEMPORARY", "TEMP", "COLUMN", "CONSTRAINT",
]);

/**
 * Words that can precede a relation name. `FROM`/`JOIN` read, `INTO`/`UPDATE`
 * write; both are relations the statement touches, which is what a policy
 * cares about.
 */
const RELATION_INTRODUCERS = new Set(["FROM", "JOIN", "INTO", "UPDATE", "TABLE"]);

/**
 * Verbs for which "the object this statement names" is a well-defined single
 * thing. `sql.target` is computed only for these.
 *
 * SELECT and WITH are deliberately absent: the first name after SELECT is a
 * column, and reporting it as the statement's target would be a confident
 * wrong answer. GRANT and REVOKE are absent too — their object follows ON,
 * and this does not follow it rather than guess at the first name it sees.
 */
const TARGET_VERBS = new Set([
  "DROP", "CREATE", "ALTER", "TRUNCATE", "RENAME",
  "INSERT", "UPDATE", "DELETE", "MERGE", "REPLACE",
  "COMMENT", "LOCK", "CALL", "EXEC", "EXECUTE",
  "USE", "COPY", "VACUUM", "ANALYZE", "REINDEX", "CLUSTER",
]);

/**
 * Keywords that must never be mistaken for a relation or a function name.
 * Deliberately narrow: it holds the words that actually appear right after a
 * relation introducer or right before a parenthesis in ordinary SQL.
 */
const NOT_A_NAME = new Set([
  "SELECT", "WHERE", "SET", "VALUES", "AS", "ON", "AND", "OR", "NOT", "IN",
  "EXISTS", "BY", "GROUP", "ORDER", "HAVING", "LIMIT", "OFFSET", "UNION",
  "ALL", "DISTINCT", "INNER", "LEFT", "RIGHT", "FULL", "OUTER", "CROSS",
  "NATURAL", "USING", "IF", "CASE", "WHEN", "THEN", "ELSE", "END", "ONLY",
]);

/** One lexical token. `quoted` marks a string literal, which is never a name. */
interface Token {
  /** The token text, with SQL quoting removed for identifiers. */
  value: string;
  /** Uppercased `value`, for keyword comparison. */
  upper: string;
  quoted: boolean;
  /** True when the very next character (ignoring nothing) is `(`. */
  callsOut: boolean;
}

const IDENT_START = /[A-Za-z_]/;
const IDENT_PART = /[A-Za-z0-9_$.]/;

/**
 * Strip SQL comments. Done before tokenizing because a comment can sit inside
 * a statement anywhere, including between a verb and its object — the classic
 * way a pattern that matches `DROP\s+TABLE` is defeated while the statement
 * still means exactly what it meant.
 *
 * Single-character scan, no regex, so there is no backtracking to exploit.
 * String literals are respected: a `--` inside quotes is data, not a comment.
 */
export function stripSqlComments(text: string): string {
  let out = "";
  let i = 0;
  const n = text.length;
  while (i < n) {
    const c = text[i];
    if (c === "'" || c === '"' || c === "`") {
      const quote = c;
      out += c;
      i++;
      while (i < n) {
        if (text[i] === quote) {
          // Doubled quote is an escaped quote inside the literal.
          if (text[i + 1] === quote) {
            out += quote + quote;
            i += 2;
            continue;
          }
          out += quote;
          i++;
          break;
        }
        out += text[i];
        i++;
      }
      continue;
    }
    if (c === "-" && text[i + 1] === "-") {
      while (i < n && text[i] !== "\n") i++;
      out += " ";
      continue;
    }
    if (c === "/" && text[i + 1] === "*") {
      i += 2;
      while (i < n && !(text[i] === "*" && text[i + 1] === "/")) i++;
      i += 2;
      out += " ";
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

/** Tokenize a comment-stripped statement. Linear, bounded, no regex engine. */
function tokenize(text: string): { tokens: Token[]; truncated: boolean } {
  const tokens: Token[] = [];
  let i = 0;
  const n = text.length;
  while (i < n) {
    const c = text[i];
    if (c === " " || c === "\t" || c === "\n" || c === "\r" || c === "\f" || c === "\v") {
      i++;
      continue;
    }
    if (tokens.length >= MAX_FACET_TOKENS) return { tokens, truncated: true };
    if (c === "'" || c === '"' || c === "`") {
      const quote = c;
      let value = "";
      i++;
      while (i < n) {
        if (text[i] === quote) {
          if (text[i + 1] === quote) {
            value += quote;
            i += 2;
            continue;
          }
          i++;
          break;
        }
        value += text[i];
        i++;
      }
      // A single-quoted run is a string LITERAL; double/backtick quoting is a
      // delimited IDENTIFIER. Only the latter can name a relation, so the
      // literal is marked and never used as a name.
      const quotedLiteral = quote === "'";
      tokens.push({
        value,
        upper: value.toUpperCase(),
        quoted: quotedLiteral,
        callsOut: text[i] === "(",
      });
      continue;
    }
    if (IDENT_START.test(c)) {
      let value = c;
      i++;
      while (i < n && IDENT_PART.test(text[i])) {
        value += text[i];
        i++;
      }
      tokens.push({
        value,
        upper: value.toUpperCase(),
        quoted: false,
        callsOut: text[i] === "(",
      });
      continue;
    }
    // Punctuation and operators are structural; only ';' and '(' matter here
    // and they are read from the raw text by the caller.
    tokens.push({ value: c, upper: c, quoted: false, callsOut: false });
    i++;
  }
  return { tokens, truncated: false };
}

/** The decomposition of one statement. */
export interface SqlFacets {
  /** False when the statement could not be decomposed; see `reason`. */
  parsed: boolean;
  /** Why it could not be decomposed. Absent when `parsed`. */
  reason?: string;
  /** The statement verb, uppercased. */
  verb?: string;
  /** The object a DDL statement names, e.g. `DROP TABLE users` -> `users`. */
  target?: string;
  /** Relations the statement reads or writes, lowercased, sorted, deduped. */
  tables: string[];
  /** Functions the statement calls, lowercased, sorted, deduped. */
  functions: string[];
  /** True when more than one statement was present (stacked queries). */
  multiple_statements: boolean;
}

/** An empty, unparsed result carrying a reason. */
function unparsed(reason: string): SqlFacets {
  return { parsed: false, reason, tables: [], functions: [], multiple_statements: false };
}

/** Strip a schema qualifier: `public.users` -> `users`. Names compare bare. */
function bareName(value: string): string {
  const dot = value.lastIndexOf(".");
  return dot === -1 ? value : value.slice(dot + 1);
}

/**
 * Decompose a SQL statement into facets. Deterministic and total: every input
 * returns a result, and one that could not be decomposed says so rather than
 * returning empty facets that would read as "nothing dangerous here".
 *
 * Pinned by conformance/fixtures/protocol_facets.json.
 */
export function extractSqlFacets(text: unknown): SqlFacets {
  if (typeof text !== "string") return unparsed("not_a_string");
  if (text.length === 0) return unparsed("empty");
  if (text.length > MAX_FACET_INPUT) return unparsed("input_too_long");

  const stripped = stripSqlComments(text);
  const { tokens, truncated } = tokenize(stripped);
  if (truncated) return unparsed("too_many_tokens");
  if (tokens.length === 0) return unparsed("no_tokens");

  // Stacked statements: a trailing ';' is ordinary punctuation, but a ';' with
  // anything after it is a second statement. That is worth its own facet
  // because "one statement whose verb is SELECT" and "a SELECT followed by a
  // DROP" are the same string to a verb-only check.
  let multiple = false;
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i].value === ";" && i < tokens.length - 1) {
      multiple = true;
      break;
    }
  }

  const first = tokens[0];
  if (first.quoted || !SQL_VERBS.has(first.upper)) {
    return { ...unparsed("unrecognized_verb"), multiple_statements: multiple };
  }
  const verb = first.upper;

  const tables = new Set<string>();
  const functions = new Set<string>();
  let target: string | undefined;

  const isName = (t: Token | undefined): boolean =>
    t !== undefined &&
    !t.quoted &&
    IDENT_START.test(t.value[0] ?? "") &&
    !NOT_A_NAME.has(t.upper) &&
    !SQL_OBJECT_TYPES.has(t.upper);

  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];

    // A function call is an identifier immediately followed by '(' — the
    // adjacency matters, since `count (x)` with a space is still a call but
    // `FROM (SELECT ...)` is not, and only the identifier form is claimed.
    if (t.callsOut && !t.quoted && IDENT_START.test(t.value[0] ?? "") && !NOT_A_NAME.has(t.upper)) {
      functions.add(bareName(t.value).toLowerCase());
    }

    if (t.quoted) continue;

    if (RELATION_INTRODUCERS.has(t.upper)) {
      // Skip DDL object-type words so `DROP TABLE users` names `users`, not
      // `TABLE`, and `CREATE MATERIALIZED VIEW v` reaches `v`.
      let j = i + 1;
      while (j < tokens.length && SQL_OBJECT_TYPES.has(tokens[j].upper)) j++;
      // `IF NOT EXISTS` and `IF EXISTS` sit between the object type and name.
      while (j < tokens.length && NOT_A_NAME.has(tokens[j].upper)) j++;
      const candidate = tokens[j];
      if (isName(candidate) && !candidate.callsOut) {
        tables.add(bareName(candidate.value).toLowerCase());
      }
      continue;
    }

    // The object a statement names: the first name after the verb, past any
    // object-type word, existence word, or relation introducer (INSERT INTO x,
    // DELETE FROM x). Only for verbs that name one — see TARGET_VERBS.
    if (target === undefined && i === 0 && TARGET_VERBS.has(verb)) {
      let j = 1;
      while (
        j < tokens.length &&
        (SQL_OBJECT_TYPES.has(tokens[j].upper) ||
          NOT_A_NAME.has(tokens[j].upper) ||
          RELATION_INTRODUCERS.has(tokens[j].upper))
      ) {
        j++;
      }
      const candidate = tokens[j];
      // A trailing "(" is allowed here, unlike for a relation: `CALL sp(1)`
      // and `CREATE FUNCTION f(...)` name their object and then open its
      // argument list.
      if (isName(candidate)) {
        target = bareName(candidate.value).toLowerCase();
      }
    }
  }

  return {
    parsed: true,
    verb,
    ...(target !== undefined ? { target } : {}),
    tables: [...tables].sort(),
    functions: [...functions].sort(),
    multiple_statements: multiple,
  };
}

/** The facet names a rule may address. */
export const SQL_FACET_NAMES = [
  "sql.verb",
  "sql.target",
  "sql.tables",
  "sql.functions",
  "sql.multiple_statements",
] as const;

export type SqlFacetName = (typeof SQL_FACET_NAMES)[number];

/**
 * Read one facet as a list of comparable strings. Scalar facets yield a
 * one-element list and list facets yield themselves, so a rule's `equals` /
 * `in` / `not_in` semantics are the same shape regardless of which facet it
 * addresses. An absent facet yields an empty list.
 */
export function readFacet(facets: SqlFacets, name: string): string[] {
  switch (name) {
    case "sql.verb":
      return facets.verb === undefined ? [] : [facets.verb.toLowerCase()];
    case "sql.target":
      return facets.target === undefined ? [] : [facets.target];
    case "sql.tables":
      return facets.tables;
    case "sql.functions":
      return facets.functions;
    case "sql.multiple_statements":
      return [facets.multiple_statements ? "true" : "false"];
    default:
      return [];
  }
}
