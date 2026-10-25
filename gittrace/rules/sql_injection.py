"""
GT-SQLI-001 — SQL built from strings at run time.

Matches a call that executes SQL, whatever the receiver (it is usually an
unresolved parameter such as `db_session` or `cursor`):
  - a method named execute, executemany, executescript, mogrify, raw,
    read_sql or read_sql_query;
  - sqlalchemy.text(), django's RawSQL(), pandas.read_sql[_query]();
when its query argument (first positional, or sql= / query= / statement= /
operation= / stmt=) is built at run time: an f-string with placeholders, `+`,
`%`, `.format()`, `.join()`, or a local variable assigned or augmented
(`sql += ...`) from one of those.

Not findings: constant SQL; parameterised queries (`execute("... ?", (x,))`);
a query passed in unchanged as a parameter (the string was built elsewhere,
and this rule does not follow values across function calls); a query
returned by another function (`execute(build_query())`).
"""

from __future__ import annotations

from gittrace.languages.base import CallSite
from gittrace.rules.base import Match, Rule, last_name

SQL_METHODS = frozenset({
    "execute", "executemany", "executescript", "mogrify", "raw", "read_sql", "read_sql_query",
})
SQL_FUNCTIONS = frozenset({
    "sqlalchemy.text", "sqlalchemy.sql.text", "sqlalchemy.sql.expression.text",
    "django.db.models.expressions.RawSQL", "django.db.models.RawSQL",
    "pandas.read_sql", "pandas.read_sql_query",
})
QUERY_KEYWORDS = ("sql", "query", "statement", "operation", "stmt")


class SqlInjection(Rule):
    rule_id = "GT-SQLI-001"
    category = "sql-injection"
    title = "SQL query built from strings"
    base_severity = "high"

    def check_call(self, call: CallSite) -> Match | None:
        if call.dotted not in SQL_FUNCTIONS and last_name(call.dotted) not in SQL_METHODS:
            return None
        query = call.argument(0, *QUERY_KEYWORDS)
        if query is None or query.kind != "built":
            return None
        return self.match_call(
            call, f"`{call.dotted}` runs a SQL query built at run time; use bound parameters.",
            query,
        )
