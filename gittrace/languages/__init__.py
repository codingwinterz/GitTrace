"""Language plug-ins: each provides a parser, a call resolver, a route detector and a rule set
behind the common interface in gittrace.languages.base. Python is the only one for now."""

from __future__ import annotations

from gittrace.languages.base import LanguagePlugin


def plugins() -> list[LanguagePlugin]:
    from gittrace.languages.python import PythonPlugin

    return [PythonPlugin()]
