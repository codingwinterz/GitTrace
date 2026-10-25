"""
GT-SECRET-001 — hardcoded secret.

Matches a string constant bound to a name (`API_KEY = "..."`,
`self.smtp_password = "..."`) when:
  - the name's last word is a secret word: key, secret, password, passwd,
    pwd, pass, token, or a compound ending in one (apikey, accesstoken, ...),
    and the word before `key`/`token` is not a non-secret qualifier
    (primary_key, sort_key, cache_key, public_key, next_token, ...);
  - the value is not empty, has no whitespace, is at least 4 characters, and
    is not an obvious placeholder (changeme, xxx, ***, <your-key>, ${VAR},
    {name}, your-..., an ENV_VAR_NAME, the name itself, ...).

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
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
_WORDS = re.compile(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])")


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


def is_placeholder(value: str, name: str) -> bool:
    v = value.strip()
    return (
        len(v) < 4
        or any(ch.isspace() for ch in v)
        or bool(_PLACEHOLDER.match(v))
        or ("{" in v and "}" in v)
        or bool(_ENV_NAME.match(v))
        or v.lower() == name.lower()
    )


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
        if not is_secret_name(assignment.target) or is_placeholder(value.value, assignment.target):
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
