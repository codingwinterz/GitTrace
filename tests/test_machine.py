"""
tests/test_machine.py — `gittrace doctor` and `gittrace up` (gittrace.cli.machine)
against a fake machine: no GPU or Ollama needed, nothing started.
"""

from __future__ import annotations

import io

import pytest
from rich.console import Console
from typer.testing import CliRunner

from gittrace.cli import app, machine

runner = CliRunner()
GIB = 1024 ** 3
TAGS = {"models": [{"name": "llama3.1:8b"}, {"name": "qwen2.5-coder:7b"}]}
POWERCFG_SLEEP = ("Power Setting GUID: 29f6c1db-86da-48c5-9fdb-f2b67b1f44da  (Sleep after)\n"
                  "    Minimum Possible Setting: 0x00000000\n    Maximum Possible Setting: 0xffffffff\n"
                  "    Current AC Power Setting Index: 0x00000708\n    Current DC Power Setting Index: 0x000000b4\n")
POWERCFG_NEVER = POWERCFG_SLEEP.replace("0x00000708", "0x00000000")


class FakeSystem(machine.System):
    def __init__(self, *, platform="linux", tools=("nvidia-smi",), cmds=None, http=None):
        self.platform = platform
        self.tools = set(tools)
        self.cmds = {"nvidia-smi --query-gpu=name,memory.total,memory.used --format=csv,noheader,nounits":
                         (0, "Test GPU, 8192, 1024"),
                     **(cmds or {})}
        self.http = {"/api/version": {"version": "0.40.11"}, "/api/tags": TAGS, "/api/ps": {"models": []},
                     **(http or {})}
        self.ran: list[list[str]] = []
        self.streamed: list[list[str]] = []

    def run(self, args, timeout=15):
        self.ran.append(args)
        return self.cmds.get(" ".join(args), (0, ""))

    def stream(self, args):
        self.streamed.append(args)
        return 0

    def which(self, name):
        return f"/usr/bin/{name}" if name in self.tools else None

    def http_json(self, url, timeout=3.0):
        for suffix, value in self.http.items():
            if url.endswith(suffix):
                return value
        return None

@pytest.fixture(autouse=True)
def _default_models(monkeypatch):
    for var in ("GITTRACE_MODEL", "GITTRACE_EXPLAIN_MODEL", "OLLAMA_API_BASE"):
        monkeypatch.delenv(var, raising=False)


def by_name(checks):
    return {c.name: c for c in checks}


class TestDoctor:
    def test_all_ready(self):
        checks = by_name(machine.run_checks(FakeSystem()))
        for name in ("python", "ollama", "model:scan", "model:explain", "vram"):
            assert checks[name].status == "ok", (name, checks[name])
        assert not {"docker", "falkordb", "database"} & set(checks)       # no database to check
        assert checks["power"].status == "info"                          # not Windows
        assert not any(c.status == "fail" for c in checks.values())

    def test_ollama_down_and_models_missing(self):
        down = by_name(machine.run_checks(FakeSystem(http={"/api/version": None})))
        assert down["ollama"].status == "fail" and "ollama.com" in down["ollama"].fix
        missing = by_name(machine.run_checks(FakeSystem(http={"/api/tags": {"models": [{"name": "llama3.1:8b"}]}})))
        assert missing["model:scan"].status == "ok"
        assert missing["model:explain"].status == "fail"
        assert missing["model:explain"].fix.startswith("ollama pull qwen2.5-coder:7b")

    def test_non_ollama_models_skip_ollama(self, monkeypatch):
        monkeypatch.setenv("GITTRACE_MODEL", "gemini/flash")
        monkeypatch.setenv("GITTRACE_EXPLAIN_MODEL", "gemini/flash")
        checks = by_name(machine.run_checks(FakeSystem(http={"/api/version": None})))
        assert checks["ollama"].status == "info" and "model:scan" not in checks

    def test_vram_counts_memory_held_by_loaded_models(self):
        tight = FakeSystem(cmds={"nvidia-smi --query-gpu=name,memory.total,memory.used --format=csv,noheader,nounits":
                                 (0, "Test GPU, 8192, 6144")})                        # 2 GiB free
        assert by_name(machine.run_checks(tight))["vram"].status == "warn"
        tight.http["/api/ps"] = {"models": [{"name": "llama3.1:8b", "size_vram": 5 * GIB}]}
        vram = by_name(machine.run_checks(tight))["vram"]
        assert vram.status == "ok" and "7.0 of 8.0 GiB" in vram.detail

    def test_no_nvidia_is_not_checked(self):
        assert by_name(machine.run_checks(FakeSystem(tools=())))["vram"].status == "info"

    def test_windows_power_and_sleep(self):
        cmds = {"powershell.exe -NoProfile -Command (Get-CimInstance -Namespace root/wmi -ClassName "
                "BatteryStatus).PowerOnline": (0, "False\n"),
                "powercfg /getactivescheme": (0, "Power Scheme GUID: 381b4222-f694  (Balanced)"),
                "powercfg /query SCHEME_CURRENT SUB_SLEEP STANDBYIDLE": (0, POWERCFG_SLEEP),
                "powercfg /query SCHEME_CURRENT SUB_VIDEO VIDEOIDLE": (0, POWERCFG_NEVER),
                "powercfg /a": (0, "Standby (S0 Low Power Idle) Network Connected\n")}
        checks = by_name(machine.run_checks(FakeSystem(platform="win32", cmds=cmds)))
        assert checks["power"].status == "warn" and checks["power"].detail == "battery; power plan Balanced"
        assert checks["sleep"].status == "warn"
        assert "sleep after 30 min on AC, 3 min on battery" in checks["sleep"].detail
        assert "powercfg /change standby-timeout-ac 0" in checks["sleep"].fix

        cmds["powershell.exe -NoProfile -Command (Get-CimInstance -Namespace root/wmi -ClassName "
             "BatteryStatus).PowerOnline"] = (0, "True\n")
        cmds["powercfg /query SCHEME_CURRENT SUB_SLEEP STANDBYIDLE"] = (0, POWERCFG_NEVER)
        checks = by_name(machine.run_checks(FakeSystem(platform="win32", cmds=cmds)))
        assert checks["power"].status == "ok" and checks["sleep"].status == "ok"
        assert "sleep after never on AC" in checks["sleep"].detail

    def test_cli_exit_code(self, monkeypatch):
        monkeypatch.setattr(machine, "System", lambda: FakeSystem(http={"/api/version": None}))
        out = runner.invoke(app, ["doctor"], env={"COLUMNS": "200"})
        assert out.exit_code == 1 and "failed" in out.output
        monkeypatch.setattr(machine, "System", lambda: FakeSystem())
        out = runner.invoke(app, ["doctor", "--format", "json"])
        assert out.exit_code == 0 and '"ok": true' in out.stdout


def _up(system, pull=False):
    console = Console(file=io.StringIO(), width=200, color_system=None)
    code = machine.up(console, pull=pull, system=system)
    return code, console.file.getvalue()


class TestUp:
    def test_ready(self):
        system = FakeSystem()
        code, out = _up(system)
        assert code == 0 and "Ready" in out
        assert not any(a[0] == "docker" for a in system.ran + system.streamed)

    def test_models_missing_without_and_with_pull(self):
        tags = {"/api/tags": {"models": [{"name": "llama3.1:8b"}]}}
        code, out = _up(FakeSystem(http=tags))
        assert code == 1 and "ollama pull qwen2.5-coder:7b" in out
        system = FakeSystem(http=tags)
        code, out = _up(system, pull=True)
        assert code == 0 and system.streamed == [["ollama", "pull", "qwen2.5-coder:7b"]]

    def test_ollama_down(self):
        code, out = _up(FakeSystem(http={"/api/version": None}))
        assert code == 1 and "Ollama" in out
