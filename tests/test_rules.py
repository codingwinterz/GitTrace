"""
test_rules.py — offline tests for the rules and for the facts they read.

Each case is a small source snippet; the assertion is which rule matches at
which line (or that nothing does), and for flow facts, which parameters the
dangerous value derives from.

Run:  pytest tests/test_rules.py -v
"""

from __future__ import annotations

import textwrap

import pytest

from gittrace.languages.base import SourceFile
from gittrace.languages.python import PythonPlugin
from gittrace.rules import ALL_RULES, rules_for, run_rules
from gittrace.rules.hardcoded_secret import is_placeholder, is_secret_name


def _matches(source: str, path: str = "m.py"):
    plugin = PythonPlugin()
    parsed = plugin.parse([SourceFile(path, textwrap.dedent(source).encode())])
    assert not parsed.failures, parsed.failures
    return run_rules(plugin.rules(), plugin.resolve_calls(parsed), parsed.assignments)


def _found(source: str) -> list[tuple[str, int]]:
    return [(m.rule_id, m.site.line) for m in _matches(source)]


class TestRegistry:
    def test_rule_ids_are_unique_and_documented(self):
        ids = [r.rule_id for r in ALL_RULES]
        assert len(ids) == len(set(ids)) == 5
        for rule in ALL_RULES:
            module = __import__(type(rule).__module__, fromlist=["_"])
            assert module.__doc__.strip().startswith(rule.rule_id), rule.rule_id

    def test_python_plugin_gets_every_rule(self):
        assert rules_for("python") == ALL_RULES
        assert rules_for("javascript") == ()


class TestSqlInjection:
    @pytest.mark.parametrize("query, how", [
        ('f"SELECT * FROM t WHERE a = {x}"', "f-string"),
        ('"SELECT * FROM t WHERE a = " + x', "string concatenation (+)"),
        ('"SELECT * FROM t WHERE a = %s" % x', "%-formatting"),
        ('"SELECT * FROM t WHERE a = {}".format(x)', ".format()"),
        ('" AND ".join(x)', ".join()"),
    ])
    def test_built_queries(self, query, how):
        matches = _matches(f"def f(cursor, x):\n    cursor.execute({query})\n")
        assert [(m.rule_id, m.site.line) for m in matches] == [("GT-SQLI-001", 2)]
        assert matches[0].evidence[0] == how
        assert matches[0].params == ("x",)

    def test_through_variables_and_augmented_assignment(self):
        matches = _matches("""
            def f(db_session, name, order):
                q = "SELECT * FROM t WHERE n = '" + name + "'"
                q += " ORDER BY " + order
                db_session.execute(q)
        """)
        assert [(m.rule_id, m.site.line) for m in matches] == [("GT-SQLI-001", 5)]
        assert matches[0].params == ("name", "order")
        assert "via variable `q`" in matches[0].evidence

    def test_sqlalchemy_text_and_keywords(self):
        assert _found("""
            from sqlalchemy import text
            import pandas as pd
            def f(conn, x):
                text(f"SELECT {x}")
                conn.execute(statement=f"DELETE FROM t WHERE id = {x}")
                pd.read_sql("SELECT * FROM t WHERE a = " + x, conn)
        """) == [("GT-SQLI-001", 5), ("GT-SQLI-001", 6), ("GT-SQLI-001", 7)]

    def test_not_findings(self):
        assert _found("""
            import streamlit as st
            QUERY = "SELECT COUNT(*) FROM t"
            def f(cursor, x, sql):
                cursor.execute("SELECT * FROM t")
                cursor.execute("SELECT * FROM t WHERE a = ?", (x,))
                cursor.execute(QUERY)
                cursor.execute("SELECT " + "1")
                cursor.execute(sql)
                cursor.execute(build(x))
                st.text(f"hello {x}")
                prefix = "SELECT * FROM t"
                cursor.execute(prefix)
        """) == []

    def test_f_string_of_constants_is_constant(self):
        assert _found("""
            from sqlalchemy import text
            SCHEMA = "dispatch_core"
            def f(conn, x):
                table = "users"
                conn.execute(text(f'set search_path to "{SCHEMA}"'))
                conn.execute(f"SELECT * FROM {table}")
                conn.execute(f"SELECT * FROM {table} WHERE id = {x}")
        """) == [("GT-SQLI-001", 8)]


class TestCodeEval:
    def test_non_constant_source(self):
        assert _found("""
            def f(expr, src):
                eval(expr)
                exec("x = " + expr)
                compile(src, "<string>", "exec")
        """) == [("GT-EVAL-001", 3), ("GT-EVAL-001", 4), ("GT-EVAL-001", 5)]

    def test_not_findings(self):
        assert _found("""
            import re
            def f(pattern):
                eval("1 + 1")
                re.compile(pattern)
                literal_eval(pattern)
        """) == []

    def test_a_local_function_named_eval_is_project_code(self):
        assert _found("def eval(x):\n    return x\n\ndef g(y):\n    return eval(y)\n") == []


class TestCommandInjection:
    def test_findings(self):
        assert _found("""
            import os
            import subprocess
            from os import system as sh
            def f(cmd, host):
                subprocess.run(cmd, shell=True)
                subprocess.Popen("ping " + host, shell=True)
                os.system(cmd)
                os.popen(f"ls {host}")
                subprocess.getoutput(cmd)
                sh(cmd)
        """) == [("GT-CMDI-001", n) for n in (6, 7, 8, 9, 10, 11)]

    def test_not_findings(self):
        assert _found("""
            import os
            import subprocess
            def f(cmd, flag):
                subprocess.run(["ls", cmd])
                subprocess.run(cmd, shell=False)
                subprocess.run(cmd, shell=flag)
                subprocess.run("ls -la", shell=True)
                os.system("make clean")
        """) == []

    def test_evidence_names_shell_true(self):
        (m,) = _matches("import subprocess\ndef f(c):\n    subprocess.call(c, shell=True)\n")
        assert m.evidence[0] == "shell=True"
        assert m.callee == "subprocess.call"


class TestDeserialization:
    def test_findings(self):
        assert _found("""
            import marshal
            import pickle
            import yaml
            def f(data, stream):
                pickle.loads(data)
                pickle.load(stream)
                yaml.load(data)
                yaml.load(data, Loader=yaml.FullLoader)
                yaml.unsafe_load(data)
                marshal.loads(data)
                pd.read_pickle(stream)
        """.replace("import yaml", "import yaml\nimport pandas as pd")) == [
            ("GT-DESER-001", n) for n in (7, 8, 9, 10, 11, 12, 13)]

    def test_not_findings(self):
        assert _found("""
            import json
            import pickle
            import yaml
            from yaml import CSafeLoader
            def f(data):
                yaml.safe_load(data)
                yaml.load(data, Loader=yaml.SafeLoader)
                yaml.load(data, CSafeLoader)
                pickle.loads(b"constant")
                json.loads(data)
        """) == []


class TestHardcodedSecret:
    def test_findings(self):
        assert _found("""
            API_KEY = "sk_live_9f8e7d6c5b4a"
            apiToken = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
            class Client:
                def __init__(self):
                    self.db_password = "hunter2hunter2"
        """) == [("GT-SECRET-001", 2), ("GT-SECRET-001", 3), ("GT-SECRET-001", 6)]

    def test_the_secret_is_masked_in_the_report(self):
        (m,) = _matches('API_KEY = "sk_live_9f8e7d6c5b4a"  # prod\n')
        assert m.site.snippet == 'API_KEY = "sk_*****************"  # prod'
        assert "9f8e" not in m.message + " ".join(m.evidence)

    def test_not_findings(self):
        assert _found("""
            import os
            SECRET_KEY = os.environ["SECRET_KEY"]
            API_TOKEN = os.getenv("API_TOKEN", "")
            DB_PASSWORD = ""
            ADMIN_PASSWORD = "changeme"
            JWT_SECRET = "<your-secret>"
            TOKEN = "${TOKEN}"
            PASSWORD_FIELD = "password"
            TOKEN_URL = "https://example.com/token"
            API_KEY_HEADER = "X-API-Key"
            PRIMARY_KEY = "id_9f8e7d6c"
            PUBLIC_KEY = "ssh-ed25519AAAAC3NzaC1lZDI1NTE5"
            GITHUB_TOKEN = "GITHUB_TOKEN"
            PROMPT_PASSWORD = "Enter your password"
            SESSION_KEY = f"session-{os.getpid()}"
        """) == []

    @pytest.mark.parametrize("name, secret", [
        ("API_KEY", True), ("secret", True), ("db_pass", True), ("smtpPassword", True),
        ("client_secret", True), ("refreshtoken", True), ("next_token", False),
        ("sort_key", False), ("TOKEN_TYPE", False), ("monkey", False), ("keys", False),
        ("REQUEST_ID_CTX_KEY", False), ("HEADER_TOKEN", False),
    ])
    def test_secret_names(self, name, secret):
        assert is_secret_name(name) is secret

    @pytest.mark.parametrize("value, placeholder", [
        ("xxx", True), ("*****", True), ("change-me-later", True), ("your_api_key", True),
        ("{token}", True), ("%(password)s", True), ("abc", True), ("not set yet", True),
        # Deliberately fake secret (a made-up Stripe-style test key) for the placeholder check; not a real credential.
        ("Zq8!pL2#", False), ("sk_test_4eC39HqLyjWDarjtT1zdp7dc", False),
    ])
    def test_placeholders(self, value, placeholder):
        assert is_placeholder(value, "API_KEY") is placeholder


class TestParameterTracking:
    def test_closure_loop_and_with_bindings(self):
        matches = _matches("""
            import os
            import pickle
            def outer(cmd, paths):
                def inner():
                    os.system("echo " + cmd)
                for p in paths:
                    os.system("rm " + p)
                with open(paths[0], "rb") as fh:
                    pickle.load(fh)
        """)
        assert [(m.site.line, m.params) for m in matches] == [
            (6, ("cmd",)), (8, ("paths",)), (10, ("paths",)),
        ]

    def test_globals_and_constants_are_not_parameters(self):
        (m,) = _matches("""
            import os
            HOST = input()
            def f():
                os.system("ping " + HOST)
        """)
        assert (m.param_derived, m.params) == (False, ())

    def test_site_facts(self):
        (m,) = _matches("import os\ndef f(c):\n    x = 1; os.system(\n        c)\n")
        assert (m.site.line, m.site.column, m.site.end_line) == (3, 12, 4)
        assert m.site.snippet == "    x = 1; os.system(\n        c)"
        assert m.sink_id == "m.py::3::12"

    def test_a_rebound_parameter_still_counts(self):
        # fix 8: user_input = BytesIO(user_input...) keeps the parameter as a source
        (m,) = _matches("""
            import io
            import pickle
            def f(user_input):
                user_input = io.BytesIO(user_input.encode("utf-8"))
                return pickle.load(user_input)
        """)
        assert (m.param_derived, m.params) == (True, ("user_input",))


class TestTuningFixes:
    """The rule fixes approved after the untouched evaluation (eval/)."""

    def test_secret_through_a_string_subscript(self):
        # fix 1
        assert _found("""
            import os
            app.config["SECRET_KEY"] = "aaaaaaa"
            os.environ["API_TOKEN"] = "ghp_16C7e42F292c6912E7710c838347Ae"
            settings[name] = "hunter2hunter2"
            app.config["DEBUG_MODE"] = "verbose"
        """) == [("GT-SECRET-001", 3), ("GT-SECRET-001", 4)]

    def test_whitespace_only_excludes_prose(self):
        # fix 2
        assert _found(r"""
            app.secret_key = 'F12Zr47j\3yX R~X@H!jmM]Lwf/,?KT'
            PROMPT_PASSWORD = "Enter your password, please"
        """) == [("GT-SECRET-001", 2)]

    def test_all_caps_value_without_underscore_is_a_secret(self):
        # fix 3
        assert _found("""
            secret = "MYSUPERSECRETKEY"
            GITHUB_TOKEN = "GH_PAT_VALUE"
        """) == [("GT-SECRET-001", 2)]

    def test_join_and_format_only_on_strings(self):
        # fix 4
        assert _found("""
            from sqlalchemy import select
            FMT = "INSERT INTO t VALUES ('{}')"
            def f(db, cursor, x, sep):
                db.session.execute(select(Users).where(Users.id == x).join(Teams, Users.team_id == Teams.id))
                cursor.execute(sep.join(x))
                cursor.execute(FMT.format(x))
                cursor.execute(", ".join(x))
        """) == [("GT-SQLI-001", 7), ("GT-SQLI-001", 8)]

    def test_identifier_values_under_key_and_token_names(self):
        # fix 5
        assert _found("""
            progress_key = "recipe.create-progress.reading-source"
            CBV_CLASS_KEY = "__cbv_class__"
            auth_token = "/api/auth/token"
            DOCS_URL_PASSWORD = "https://example.com/docs/password"
            key = "healthcheck"
            token_key = "access_token"
            key = "JHtM1wEt1I1J9N_Evjwqr3yYauXIqSxYzFnRhcf0ZG0="
            SECRET_KEY = "aaaaaaa"
            API_TOKEN = "s3cr3t-token-123"
        """) == [("GT-SECRET-001", 8), ("GT-SECRET-001", 9), ("GT-SECRET-001", 10)]

    def test_sql_from_model_and_class_constants(self):
        # fix 6
        assert _found("""
            from sqlalchemy import text
            LEGACY = ("a_table", "b_table")
            class Model:
                THRESHOLD = "0.5"
                @classmethod
                def search(cls, session):
                    session.execute(text(f"set similarity = {cls.THRESHOLD};"))
                def tune(self, session):
                    session.execute(text(f"set similarity = {self.THRESHOLD};"))
            def migrate(op, session, tables):
                session.execute(text(f"SELECT id FROM {Model.__tablename__}"))
                for table in LEGACY:
                    op.execute(text(f"DELETE FROM {table}"))
                for u, p in [("admin", "x"), ("tim", "y")]:
                    session.execute("INSERT INTO users VALUES ('%s', '%s')" % (u, p))
                for t in tables:
                    op.execute(text(f"DELETE FROM {t}"))
        """) == [("GT-SQLI-001", 18)]
