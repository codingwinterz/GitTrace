"""
GT-SECRET-001 — hardcoded secret.

Matches a string constant bound to a name (`API_KEY = "..."`,
`self.smtp_password = "..."`, `app.config["SECRET_KEY"] = "..."`) when:
  - the name's last word is a secret word: key, secret, password, passwd,
    pwd, pass, token, or a compound ending in one (apikey, accesstoken, ...),
    and the word before `key`/`token` is not a non-secret qualifier
    (primary_key, sort_key, cache_key, public_key, next_token, ...);
  - the value is at least 4 characters and is not an obvious placeholder
    (changeme, xxx, ***, <your-key>, ${VAR}, {name}, your-..., an
    ENV_VAR_NAME with an underscore, the name itself, a sentence of plain
    words, a dunder name, a URL or path);
  - for names ending in key/token, the value is not a letters-only dotted,
    kebab or snake identifier (i18n and cache keys), and a bare `key` or
    `token` holds at least two of lower case, upper case and digits.

Not findings: values read from the environment or config (they are not
constants), names that describe a secret rather than hold one
(PASSWORD_FIELD, TOKEN_URL, API_KEY_HEADER), and placeholders.

This rule is not flow-sensitive: a secret in the source is exposed to
everyone who can read the repository, so reachability does not change its
severity. The reported snippet masks the value (first 3 characters kept).
"""

from __future__ import annotations

import re
from dataclasses import replace

from gittrace.languages.base import AssignFact
from gittrace.rules.base import Match, Rule

SECRET_WORDS = frozenset({"key", "secret", "password", "passwd", "pwd", "pass", "token"})
SECRET_SUFFIXES = (
    "apikey", "secretkey", "accesskey", "privatekey", "authkey", "signingkey",
    "accesstoken", "authtoken", "apitoken", "refreshtoken", "bearertoken",
    "apisecret", "clientsecret", "password", "passwd",
)
NOT_SECRET_QUALIFIERS = frozenset({
    "primary", "foreign", "sort", "cache", "lookup", "partition", "dict", "unique",
    "composite", "hash", "row", "map", "idempotency", "group", "message", "translation",
    "i18n", "setting", "settings", "config", "column", "field", "index", "object",
    "redis", "storage", "public", "dedup", "dedupe", "json", "query", "search", "cursor",
    "page", "next", "prev", "previous", "continuation", "pagination", "sentinel", "end",
    "start", "eos", "bos", "pad", "unk", "mask", "sep", "cls", "max", "min", "num",
    "ctx", "context", "env", "header", "cookie", "claim", "attr", "param", "lock",
})
_PLACEHOLDER = re.compile(
    r"""^(?:
        change[-_ ]?me.*|changeit|placeholder|example|sample|dummy|fake|tests?|testing
      | secret|password|passwd|token|key|none|null|nil|undefined|default|todo|fixme
      | redacted|hidden|x+|\*+|\.+|-+|_+|#+
      | <[^>]*> | \$\{[^}]*\} | \{\{.*\}\} | %\([^)]*\)s | %s
      | (?:your|my|insert|enter|replace)[-_ ].*
    )$""",
    re.IGNORECASE | re.VERBOSE,
)
# An environment variable's name, e.g. GITHUB_TOKEN; needs an underscore, so
# an all-caps secret such as MYSUPERSECRETKEY is not mistaken for one.
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")
_WORDS = re.compile(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])")
_DUNDER = re.compile(r"^__\w+__$")
_URL_OR_PATH = re.compile(r"^(?:/|https?://)")
# Letters-only words joined by . - or _: i18n keys, cache keys, attribute names
# ("recipe.create-progress.reading", "test_key"). A value with digits is not one.
_IDENTIFIER = re.compile(r"^[a-z]+(?:[._-][a-z]+)+$")
_PROSE_WORD = re.compile(r"^[A-Za-z][A-Za-z']*[.,:;!?]?$")


def name_words(name: str) -> list[str]:
    return [w.lower() for w in _WORDS.findall(name)]


def is_secret_name(name: str) -> bool:
    words = name_words(name)
    if not words:
        return False
    last = words[-1]
    if last not in SECRET_WORDS and not last.endswith(SECRET_SUFFIXES):
        return False
    if last in ("key", "token") and len(words) > 1 and words[-2] in NOT_SECRET_QUALIFIERS:
        return False
    return True


def mask(value: str) -> str:
    return value[:3] + "*" * (len(value) - 3)


def is_prose(value: str) -> bool:
    """Two or more words of plain letters: a message, not a secret."""
    words = value.split()
    return len(words) >= 2 and all(_PROSE_WORD.match(w) for w in words)


def is_placeholder(value: str, name: str) -> bool:
    v = value.strip()
    return (
        len(v) < 4
        or is_prose(v)
        or bool(_PLACEHOLDER.match(v))
        or ("{" in v and "}" in v)
        or bool(_ENV_NAME.match(v))
        or bool(_DUNDER.match(v))
        or bool(_URL_OR_PATH.match(v))
        or v.lower() == name.lower()
    )


def is_identifier_value(value: str, name: str) -> bool:
    """For names ending in key/token: values that name something rather than
    authenticate. A bare `key`/`token` (usually a dict or cache key) also needs
    at least two of lower case, upper case and digits to count as a secret."""
    words = name_words(name)
    if words[-1] not in ("key", "token") and not words[-1].endswith(("key", "token")):
        return False
    if _IDENTIFIER.match(value):
        return True
    if len(words) == 1 and words[0] in ("key", "token"):
        classes = sum(bool(re.search(p, value)) for p in ("[a-z]", "[A-Z]", "[0-9]"))
        return classes < 2
    return False


class HardcodedSecret(Rule):
    rule_id = "GT-SECRET-001"
    category = "hardcoded-secret"
    title = "Hardcoded secret"
    base_severity = "medium"
    flow_sensitive = False

    def check_assignment(self, assignment: AssignFact) -> Match | None:
        value = assignment.value
        if not value.is_literal or not isinstance(value.value, str):
            return None
        target = assignment.target
        if (not is_secret_name(target) or is_placeholder(value.value, target)
                or is_identifier_value(value.value, target)):
            return None
        # Reports end up in CI logs: never repeat the secret itself.
        site = replace(assignment.site, snippet=assignment.site.snippet.replace(value.value, mask(value.value)))
        return Match(
            rule_id=self.rule_id, category=self.category, title=self.title,
            base_severity=self.base_severity, function_id=assignment.function_id,
            site=site,
            message=f"`{assignment.target}` is assigned a hardcoded secret; load it from the environment.",
            evidence=(f"string constant of {len(value.value)} characters",),
            flow_sensitive=False,
        )
