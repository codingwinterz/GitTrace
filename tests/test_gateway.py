"""
tests/test_gateway.py — the model layer through the Respan Gateway, offline.

Covers:
  1. the switch: $GITTRACE_GATEWAY, and $GITTRACE_GATEWAY_CONFIG naming a file
     (the gateway.toml in the current folder is never read: it is the project
     being scanned)
  2. what the gateway is asked: model, messages, options, JSON schema
  3. errors: a provider's 4xx and 5xx, a timeout, a missing package, a bad config
  4. the integrated path: `gittrace scan` triage through a real in-process
     gateway whose provider is a fixture on loopback — no provider keys, no
     outside network, and a route name from the config

Run:  pytest tests/test_gateway.py -v
"""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import sys
import threading
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import httpx
import pytest
from typer.testing import CliRunner

import expected_sample_app
from gittrace.cli import app
from gittrace.llm import gateway as gateway_mod
from gittrace.llm.client import ModelCallFailed, ModelClient, ModelUnavailable
from gittrace.llm.schemas import TriageVerdict

ROOT = expected_sample_app.ROOT
SQLI = "app/db.py::17::9"                       # cursor.execute(f"... '{name}'")
runner = CliRunner()
HAS_RESPAN = importlib.util.find_spec("respan_gateway") is not None

REASON = "the name comes from the URL path and reaches the query"
# The install command the README gives for the gateway extra.
INSTALL = 'pipx install --force "gittrace[gateway] @ git+https://github.com/codingwinterz/GitTrace@v2.1.0"'


def reply(**extra) -> str:
    """A triage reply the schema accepts."""
    return json.dumps({"values": [{"value": "name", "source": "attacker"}],
                       "verdict": "likely_real", "reason": REASON,
                       "severity_adjustment": 1, "fix_code": None, **extra})


class Response:
    """What respan_gateway's `gw.request` gives back, for the tests."""

    def __init__(self, status_code: int, payload: dict | None = None, text: str | None = None):
        self.status_code, self._payload = status_code, payload
        self.text = text if text is not None else json.dumps(payload or {})

    def json(self):
        if self._payload is None:
            raise ValueError("not JSON")
        return self._payload


def chat(content: str) -> Response:
    return Response(200, {"choices": [{"index": 0, "message": {"role": "assistant",
                                                              "content": content}}]})


def error(status: int, message: str) -> Response:
    return Response(status, {"error": {"message": message, "type": "upstream"}})


def fake_respan(*outcomes) -> types.ModuleType:
    """A stand-in respan_gateway module. `Gateway(...)` records the config it
    was given, and each request answers with the next outcome: a response, or a
    callable that raises."""
    mod = types.ModuleType("respan_gateway")

    class ConfigError(ValueError):
        pass

    class GatewayError(RuntimeError):
        pass

    mod.ConfigError, mod.GatewayError = ConfigError, GatewayError
    mod.configs: list = []                  # the config of every gateway built
    mod.requests: list = []                 # the kwargs of every request
    pending = list(outcomes)

    class Gateway:
        def __init__(self, config=None, *, path=None):
            mod.configs.append(path if path is not None else config)
            self.closed = False

        @classmethod
        def from_file(cls, path):
            return cls(path=path)

        def request(self, method, target, **kwargs):
            mod.requests.append({"method": method, "path": target, **kwargs})
            outcome = pending.pop(0)
            if callable(outcome):
                outcome(mod)
            return outcome

        def close(self):
            self.closed = True

    mod.Gateway = Gateway
    return mod


@pytest.fixture(autouse=True)
def _clean_gateway(monkeypatch):
    """Every test starts with the gateway off, and keeps no gateway of its own."""
    monkeypatch.delenv(gateway_mod.GATEWAY_ENV, raising=False)
    monkeypatch.delenv(gateway_mod.CONFIG_ENV, raising=False)
    gateway_mod._reset()
    yield
    gateway_mod._reset()


@pytest.fixture(autouse=True)
def _no_provider_keys(monkeypatch):
    """The config built from the environment must not see the machine's own keys."""
    for _, var in gateway_mod.ENV_VENDORS:
        monkeypatch.delenv(var, raising=False)


def gateway_call(mod, *, model="gpt-x", timeout=42):
    """One ModelClient reply with `mod` standing in for respan_gateway."""
    with patch.dict(sys.modules, {"respan_gateway": mod}):
        return ModelClient(model, timeout=timeout).complete("sys", "user", TriageVerdict)


# ---------------------------------------------------------------------------
# 1. The switch and the config
# ---------------------------------------------------------------------------

class TestSwitch:
    def test_off_unless_asked(self, monkeypatch):
        assert not gateway_mod.enabled()
        for value in ("0", "off", "no", ""):
            monkeypatch.setenv(gateway_mod.GATEWAY_ENV, value)
            assert not gateway_mod.enabled()
        for value in ("1", "on", "true", "yes", " ON "):
            monkeypatch.setenv(gateway_mod.GATEWAY_ENV, value)
            assert gateway_mod.enabled()

    def test_the_environment_builds_the_provider_list(self, monkeypatch):
        config = gateway_mod._config()
        assert isinstance(config, str)
        assert "[providers.ollama]" in config and "[providers.openai]" not in config
        monkeypatch.setenv("OPENAI_API_KEY", "sk-not-in-the-config")
        monkeypatch.setenv("GROQ_API_KEY", "gsk-not-in-the-config")
        config = gateway_mod._config()
        assert '[providers.openai]\nvendor = "openai"\nkey = "env:OPENAI_API_KEY"' in config
        assert 'vendor = "groq"' in config
        assert "sk-not-in-the-config" not in config and "gsk-not-in-the-config" not in config

    def test_ollama_base_url_is_passed_on(self, monkeypatch):
        monkeypatch.setenv(gateway_mod.OLLAMA_BASE_ENV, "http://127.0.0.1:11500")
        assert 'base_url = "http://127.0.0.1:11500"' in gateway_mod._config()

    def test_a_named_file_is_read(self, tmp_path, monkeypatch):
        toml = tmp_path / "gateway.toml"
        toml.write_text('[providers.openai]\nvendor = "openai"\n', encoding="utf-8")
        monkeypatch.setenv(gateway_mod.CONFIG_ENV, str(toml))
        monkeypatch.setenv(gateway_mod.GATEWAY_ENV, "1")
        mod = fake_respan(chat(reply()))
        with patch.dict(sys.modules, {"respan_gateway": mod}):
            gateway_mod.complete("gpt-x", [], TriageVerdict, timeout=42)
        assert mod.configs == [toml]

    def test_the_current_folder_toml_is_never_read(self, tmp_path, monkeypatch):
        (tmp_path / "gateway.toml").write_text('[providers.evil]\nvendor = "openai"\n',
                                              encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv(gateway_mod.GATEWAY_ENV, "1")
        mod = fake_respan(chat(reply()))
        with patch.dict(sys.modules, {"respan_gateway": mod}):
            gateway_mod.complete("gpt-x", [], TriageVerdict, timeout=42)
        [config] = mod.configs
        assert isinstance(config, str) and "[providers.evil]" not in config


# ---------------------------------------------------------------------------
# 2. What the gateway is asked
# ---------------------------------------------------------------------------

class TestTheCall:
    def test_the_request_and_its_options(self, monkeypatch):
        monkeypatch.setenv(gateway_mod.GATEWAY_ENV, "1")
        mod = fake_respan(chat(reply()))
        out = gateway_call(mod)
        [sent] = mod.requests
        assert (sent["method"], sent["path"]) == ("POST", "/v1/chat/completions")
        assert sent["timeout"] == 42
        body = sent["json"]
        assert body["model"] == "gpt-x"
        assert body["messages"] == [{"role": "system", "content": "sys"},
                                    {"role": "user", "content": "user"}]
        assert body["temperature"] <= 0.2 and body["max_tokens"] == 1024 and body["seed"] == 7
        assert body["response_format"]["type"] == "json_schema"
        assert body["response_format"]["json_schema"]["name"] == "TriageVerdict"
        assert body["response_format"]["json_schema"]["schema"] == TriageVerdict.model_json_schema()
        assert (out.value.verdict, out.value.severity_adjustment, out.attempts) == ("likely_real", 1, 1)

    def test_the_model_name_is_the_gateways(self, monkeypatch):
        """A route name (`--model smart`) reaches the gateway untouched, so a
        gateway.toml decides where it goes; no LiteLLM prefix is added."""
        monkeypatch.setenv(gateway_mod.GATEWAY_ENV, "1")
        mod = fake_respan(chat(reply()))
        gateway_call(mod, model="smart")
        assert mod.requests[0]["json"]["model"] == "smart"

    def test_one_gateway_for_the_process(self, monkeypatch):
        monkeypatch.setenv(gateway_mod.GATEWAY_ENV, "1")
        mod = fake_respan(chat(reply()), chat(reply()))
        with patch.dict(sys.modules, {"respan_gateway": mod}):
            client = ModelClient("gpt-x", timeout=42)
            client.complete("sys", "user", TriageVerdict)
            client.complete("sys", "user", TriageVerdict)
        assert len(mod.configs) == 1 and len(mod.requests) == 2


# ---------------------------------------------------------------------------
# 3. Errors
# ---------------------------------------------------------------------------

class TestErrors:
    def test_an_invalid_reply_is_retried_here_too(self, monkeypatch):
        monkeypatch.setenv(gateway_mod.GATEWAY_ENV, "1")
        mod = fake_respan(chat("not json at all"), chat(reply()))
        out = gateway_call(mod)
        assert (out.value.verdict, out.attempts) == ("likely_real", 2)

    def test_a_provider_error_fails_this_call(self, monkeypatch):
        monkeypatch.setenv(gateway_mod.GATEWAY_ENV, "1")
        mod = fake_respan(error(502, "provider 'ollama' could not be reached"))
        with pytest.raises(ModelCallFailed, match="502.*could not be reached"):
            gateway_call(mod)

    def test_a_bad_key_means_the_model_is_unavailable(self, monkeypatch):
        monkeypatch.setenv(gateway_mod.GATEWAY_ENV, "1")
        mod = fake_respan(error(401, "bad key from the provider"))
        with pytest.raises(ModelUnavailable, match="401.*bad key"):
            gateway_call(mod)

    def test_a_timeout_says_so(self, monkeypatch):
        monkeypatch.setenv(gateway_mod.GATEWAY_ENV, "1")

        def slow(_mod):
            raise httpx.ReadTimeout("timed out")

        with pytest.raises(ModelCallFailed, match="did not answer within 42 s"):
            gateway_call(fake_respan(slow))

    def test_a_gateway_that_cannot_run_is_unavailable(self, monkeypatch):
        monkeypatch.setenv(gateway_mod.GATEWAY_ENV, "1")
        mod = fake_respan()

        def broken(*args, **kwargs):
            raise mod.GatewayError("no tokio runtime")

        mod.Gateway = broken
        with pytest.raises(ModelUnavailable, match="could not be started.*no tokio runtime"):
            gateway_call(mod)

    def test_an_invalid_config_is_unavailable(self, monkeypatch):
        monkeypatch.setenv(gateway_mod.GATEWAY_ENV, "1")
        mod = fake_respan()

        def refused(config=None, *, path=None):
            raise mod.ConfigError("providers: none configured")

        mod.Gateway = refused
        with pytest.raises(ModelUnavailable, match="configuration could not be read.*none configured"):
            gateway_call(mod)

    def test_the_package_not_installed_is_unavailable(self, monkeypatch):
        monkeypatch.setenv(gateway_mod.GATEWAY_ENV, "1")
        with patch.dict(sys.modules, {"respan_gateway": None}):      # an import of it fails
            with pytest.raises(ModelUnavailable, match=re.escape(INSTALL)):
                ModelClient("gpt-x", timeout=42).complete("sys", "user", TriageVerdict)

    def test_the_cli_prints_the_install_command_in_full(self, monkeypatch, tmp_path):
        # The CLI prints errors through Rich: "[gateway]" must not be read as markup.
        project = tmp_path / "sample_app"
        shutil.copytree(ROOT, project, ignore=shutil.ignore_patterns(".gittrace"))
        monkeypatch.setenv(gateway_mod.GATEWAY_ENV, "1")
        with patch.dict(sys.modules, {"respan_gateway": None}):
            out = runner.invoke(app, ["scan", str(project), "--no-blame"], env={"COLUMNS": "300"})
        assert out.exit_code == 2
        assert INSTALL in " ".join(out.output.split())

    def test_a_reply_with_no_message_fails(self, monkeypatch):
        monkeypatch.setenv(gateway_mod.GATEWAY_ENV, "1")
        mod = fake_respan(Response(200, {"id": "chatcmpl-1"}))
        with pytest.raises(ModelCallFailed, match="no message"):
            gateway_call(mod)

    def test_an_error_body_without_a_json_message_still_says_something(self, monkeypatch):
        monkeypatch.setenv(gateway_mod.GATEWAY_ENV, "1")
        mod = fake_respan(Response(503, text="upstream is down"))
        with pytest.raises(ModelCallFailed, match="503 upstream is down"):
            gateway_call(mod)


# ---------------------------------------------------------------------------
# 4. The integrated path: `gittrace scan` through a real gateway
# ---------------------------------------------------------------------------

@pytest.fixture
def provider():
    """A local OpenAI-compatible provider (respan-gateway's `openai-chat`
    format) on loopback. It answers every chat request with a triage reply and
    records the bodies it was sent."""
    bodies: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):       # keep the test output clean
            pass

        def _answer(self, status: int, payload: dict) -> None:
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self._answer(200, {"object": "list", "data": [
                {"id": "fixture-model", "object": "model", "owned_by": "fixture"}]})

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            bodies.append(json.loads(self.rfile.read(length) or b"{}"))
            self._answer(200, {"id": "chatcmpl-1", "object": "chat.completion", "created": 0,
                               "model": "fixture-model",
                               "choices": [{"index": 0, "finish_reason": "stop",
                                            "message": {"role": "assistant", "content": reply()}}],
                               "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield SimpleNamespace(url=f"http://127.0.0.1:{server.server_address[1]}", bodies=bodies)
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def write_gateway_toml(path: Path, provider_url: str, routes: str = "") -> Path:
    path.write_text('ui = false\n'
                    '\n[providers.fixture]\n'
                    'formats = ["openai-chat"]\n'
                    f'base_url = "{provider_url}/v1"\n'
                    + routes, encoding="utf-8")
    return path


@pytest.mark.skipif(not HAS_RESPAN, reason="respan-gateway is not installed")
class TestTheIntegratedPath:
    def _scan(self, project, *args):
        return runner.invoke(app, ["scan", str(project), "--offline", "--no-blame", "--fail-on", "none",
                                   *args], env={"COLUMNS": "400"})

    @pytest.fixture
    def project(self, tmp_path):
        return Path(shutil.copytree(ROOT, tmp_path / "sample_app",
                                    ignore=shutil.ignore_patterns(".gittrace", "__pycache__")))

    def test_scan_triage_goes_through_the_gateway(self, project, provider, tmp_path, monkeypatch):
        config = write_gateway_toml(tmp_path / "gateway.toml", provider.url)
        monkeypatch.setenv(gateway_mod.GATEWAY_ENV, "1")
        monkeypatch.setenv(gateway_mod.CONFIG_ENV, str(config))
        monkeypatch.setenv("GITTRACE_MODEL", "fixture-model")

        out = self._scan(project, "--format", "json")
        assert out.exit_code == 0, out.output
        data = json.loads(out.stdout)
        assert data["llm"]["model"] == "fixture-model"
        assert (data["llm"]["enabled"], data["llm"]["triaged"], data["llm"]["errors"]) == (True, 13, 0)

        # The real gateway routed one request per finding to the fixture.
        assert len(provider.bodies) == 13
        sent = provider.bodies[0]
        assert sent["model"] == "fixture-model"
        assert sent["response_format"]["json_schema"]["name"] == "TriageVerdict"
        assert sent["messages"][0]["role"] == "system"
        assert "BEGIN_UNTRUSTED" in sent["messages"][1]["content"]

        triaged = next(f for f in data["findings"] if f["id"] == SQLI)["triage"]
        assert (triaged["verdict"], triaged["severity_adjustment"], triaged["reason"]) == \
            ("likely_real", 1, REASON)

    def test_a_route_name_from_the_config_is_used(self, provider, tmp_path, monkeypatch):
        """`--model smart` is not a model: the gateway's `[routes.smart]` picks
        one, and the provider sees the model it names."""
        config = write_gateway_toml(tmp_path / "gateway.toml", provider.url,
                                    '\n[routes.smart]\nto = ["fixture/asked-model"]\n')
        monkeypatch.setenv(gateway_mod.GATEWAY_ENV, "1")
        monkeypatch.setenv(gateway_mod.CONFIG_ENV, str(config))

        out = ModelClient("smart", timeout=30).complete("sys", "user", TriageVerdict)
        assert out.value.verdict == "likely_real"
        assert [body["model"] for body in provider.bodies] == ["asked-model"]
