"""
gittrace.core.glossary — plain definitions for the technical terms that
`explain` summaries use.

The system prompt asks the model to explain every technical term the first
time it uses one; in the untouched evaluation neither model did ("blueprint"
13 times, explained 0 times). So it is done in code instead: GLOSSARY is a
fixed list of terms, each with a plain definition and the word forms that
count as using it, and `terms_in` finds the ones a text uses. `explain`
attaches them to each summary as "Terms used". Nothing here calls a model.

What counts as a use: the term as a word in the prose, in any of its listed
forms (case-insensitive, except for acronyms, which must be upper case).
Code-like text is ignored first: function ids and paths (`app/auth/routes.py`,
`routes.py::login`), dotted names (`bp.route`, `db.session`), calls
(`commit()`) and anything in backticks. Identifiers with underscores never
match (`token_auth` does not use "token").
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class Term:
    term: str
    definition: str
    pattern: re.Pattern


def _t(term: str, definition: str, forms: str, case: bool = False) -> Term:
    return Term(term, definition, re.compile(rf"\b(?:{forms})\b", 0 if case else re.IGNORECASE))


GLOSSARY: tuple[Term, ...] = (
    _t("API", "a set of URLs (or functions) that other programs call to use this one", "APIs?", case=True),
    _t("async", "code that can wait for something slow (the network, a database) without stopping "
                "other work", "async|asynchronous(?:ly)?"),
    _t("blueprint", "in Flask, a group of related routes that is registered on the app as one unit",
       "blueprints?"),
    _t("cache", "a store of recent results kept so they need not be computed or fetched again",
       "cache[sd]?|caching"),
    _t("callback", "a function handed to other code, which calls it later when something happens",
       "callbacks?"),
    _t("CLI", "a command-line interface: commands typed in a terminal", "CLIs?", case=True),
    _t("commit", "making the pending changes to a database permanent", "commit(?:s|ted|ting)?"),
    _t("cookie", "a small piece of data the browser keeps and sends back with every request to the site",
       "cookies?"),
    _t("decorator", "a line starting with @ above a function; it wraps the function or registers it, "
                    "for example as a route", "decorators?|decorated"),
    _t("dependency", "in FastAPI, a function that runs before a route's handler and passes it a value "
                     "(often the logged-in user)", "dependenc(?:y|ies)"),
    _t("endpoint", "a URL the app answers, together with its HTTP method (GET, POST, ...)", "endpoints?"),
    _t("environment variable", "a setting given to the program by the system it runs on, outside the code",
       "environment variables?|env vars?"),
    _t("handler", "the function that runs when a request (or another event) arrives", "handlers?"),
    _t("hash", "a fixed-length fingerprint of some data; a password hash cannot be turned back into "
               "the password", "hash(?:es|ed|ing)?"),
    _t("HTTP", "the protocol browsers and apps use to request pages and data from a web server",
       "HTTPS?", case=True),
    _t("JSON", "a text format for structured data (names and values), used by most web APIs", "JSON",
       case=True),
    _t("JWT", "JSON Web Token: a signed string that proves who a user is", "JWTs?", case=True),
    _t("middleware", "code that runs on every request, before or after the route's handler", "middlewares?"),
    _t("migration", "a script that changes the structure of the database (tables, columns) one step "
                    "at a time", "migrations?"),
    _t("ORM", "Object-Relational Mapper: a library that maps Python classes to database tables and "
              "writes the SQL", "ORMs?", case=True),
    _t("query", "a request for data sent to a database (or a search index)", "quer(?:y|ies|ied|ying)"),
    _t("queue", "a list of jobs waiting for a background worker to run them", "queue[sd]?|queuing"),
    _t("route", "a URL pattern linked to the function that handles it", "routes?|routing"),
    _t("router", "in FastAPI, a group of routes that the app includes, often under a common URL prefix",
       "routers?"),
    _t("schema", "a description of the shape of some data: which fields it has and of which types",
       "schemas?"),
    _t("serialize", "turn objects into text or bytes (such as JSON) so they can be stored or sent",
       "(?:de)?seriali[sz](?:e|es|ed|ing|ation)"),
    _t("session", "either what a web app remembers about a visitor between requests (often in a cookie), "
                  "or, in SQLAlchemy, a unit of work with the database that holds changes until they "
                  "are committed", "sessions?"),
    _t("SQL", "the language used to read and change data in relational databases", "SQL", case=True),
    _t("subprocess", "another program started by this one", "subprocess(?:es)?"),
    _t("template", "an HTML file with placeholders that the app fills in before sending the page",
       "templates?"),
    _t("token", "a string that proves who a user is, sent with requests instead of a password",
       "tokens?"),
    _t("transaction", "a group of database changes that are saved or undone together", "transactions?"),
)

_CODE = re.compile(
    r"`[^`]*`"                                  # anything in backticks
    r"|\S*[/\\]\S*"                             # paths: app/auth/routes, app\db.py
    r"|[\w.<>#-]+\.py(?:::[\w.<>#]+)?"          # files and function ids
    r"|\w+(?:\.\w+)+(?:\(\))?"                  # dotted names: bp.route, db.session.commit()
    r"|\w+\(\)"                                 # calls: commit()
)


def prose(text: str) -> str:
    """`text` with code-like parts blanked out."""
    return _CODE.sub(" ", text)


def terms_in(texts: Iterable[str]) -> list[Term]:
    """The glossary terms the texts use, in glossary order."""
    body = " ".join(prose(t) for t in texts if t)
    return [t for t in GLOSSARY if t.pattern.search(body)]


__all__ = ["GLOSSARY", "Term", "prose", "terms_in"]
