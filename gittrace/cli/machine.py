"""
gittrace.cli.machine — is this machine ready to run GitTrace? (`gittrace doctor`)
and start what can be started (`gittrace up`).

doctor checks, without changing anything:
  python        a supported version
  settings      which .env file is used (gittrace.config), or the defaults
  docker        installed and running (needed for the default local FalkorDB)
  falkordb      a real round trip (GRAPH.LIST, 3 s timeout); "local" or "remote" only
  database      a warning when the configured FalkorDB is not on this machine
  ollama        answering, when a model is an Ollama model
  model:<task>  the triage and explain models are pulled
  vram          free GPU memory against what the models need (NVIDIA only)
  power, sleep  Windows: AC or battery, power plan, sleep and display timers,
                Modern Standby (long model runs were paused by it in evaluation)

up starts local FalkorDB in Docker (the `gittrace-falkordb` container, or
the docker compose one if it exists), waits for it, checks Ollama and, with
--pull, pulls missing models. It never starts or changes a remote database.

Everything that touches the machine goes through System, so tests can
replace it. Nothing here prints a database host, port or password.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
from dataclasses import asdict, dataclass

from rich.console import Console
from rich.table import Table
from rich.text import Text

from gittrace.cli import render

FALKORDB_IMAGE = "falkordb/falkordb:v4.22.1"   # same tag as docker-compose.yml and CI; bump together
CONTAINER = "gittrace-falkordb"
COMPOSE_CONTAINER = "gittrace-falkordb-1"
OLLAMA_DEFAULT = "http://localhost:11434"
MIN_PYTHON = (3, 11)
# GiB of VRAM at num_ctx 8192, measured on the evaluation laptop (README, "Model triage").
VRAM_GIB = {"llama3.1:8b": 5.6, "qwen2.5-coder:7b": 4.7}
STYLE = {"ok": render.TEAL, "warn": render.AMBER, "fail": render.RED, "info": render.LAVENDER}
KEEP_AWAKE = ("powercfg /change standby-timeout-ac 0 and powercfg /change monitor-timeout-ac 0 "
              "(or a keep-awake tool) before a long run")


@dataclass
class Check:
    name: str
    status: str             # ok | warn | fail | info
    detail: str
    fix: str = ""


class System:
    """The machine as the doctor sees it."""

    platform = sys.platform

    def run(self, args: list[str], timeout: float = 15) -> tuple[int, str]:
        try:
            p = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace",
                               timeout=timeout)
        except (OSError, subprocess.SubprocessError):
            return 127, ""
        return p.returncode, (p.stdout or "") + (p.stderr or "" if p.returncode else "")

    def stream(self, args: list[str]) -> int:
        """Run with the terminal attached (docker pull / ollama pull progress)."""
        try:
            return subprocess.run(args).returncode
        except OSError:
            return 127

    def which(self, name: str) -> str | None:
        return shutil.which(name)

    def http_json(self, url: str, timeout: float = 3.0):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as response:      # noqa: S310 - local Ollama
                return json.loads(response.read().decode("utf-8"))
        except Exception:  # noqa: BLE001 - unreachable, refused, not JSON: all "down"
            return None

    def falkordb(self, local_default: bool = False) -> tuple[bool, str]:
        from gittrace.graph import connection
        return connection.check(local_default=local_default)

    def location(self) -> str:
        from gittrace.graph import connection
        return connection.location()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


def _ollama_base() -> str:
    return (os.environ.get("OLLAMA_API_BASE") or OLLAMA_DEFAULT).rstrip("/")


def _ollama_where(base: str) -> str:
    host = re.sub(r"^\w+://", "", base).split("/")[0].rsplit(":", 1)[0].strip("[]").lower()
    return "local" if host in ("localhost", "127.0.0.1", "::1") else "remote"


def models() -> dict[str, str]:
    """{task: model} for the two tasks that call a model."""
    from gittrace.llm.client import resolve_explain_model, resolve_model
    return {"scan": resolve_model(), "explain": resolve_explain_model()}


def _ollama_name(model: str) -> str | None:
    return model.split("/", 1)[1] if model.startswith("ollama/") else None


def _pulled(name: str, tags: list[str]) -> bool:
    return name in tags or f"{name}:latest" in tags or (":" not in name and f"{name}:latest" in tags)


# -- checks -----------------------------------------------------------------------


def check_python(version=sys.version_info) -> Check:
    v = ".".join(map(str, version[:3]))
    if tuple(version[:2]) >= MIN_PYTHON:
        return Check("python", "ok", v)
    return Check("python", "fail", f"{v}; GitTrace needs {'.'.join(map(str, MIN_PYTHON))} or newer",
                 "install a newer Python and reinstall GitTrace (pipx install gittrace)")


def check_settings() -> Check:
    from gittrace import config
    loaded = config.load()
    if loaded is None:
        return Check("settings", "info", "no .env: defaults (local Docker FalkorDB, local Ollama)")
    return Check("settings", "info", f"from {loaded}")


def check_docker(system: System, needed: bool) -> Check:
    if system.which("docker") is None:
        if not needed:
            return Check("docker", "info", "not installed (not needed: the configured FalkorDB is remote)")
        return Check("docker", "fail", "not installed", "install Docker Desktop (or Docker Engine on Linux)")
    rc, out = system.run(["docker", "info", "--format", "{{.ServerVersion}}"])
    if rc != 0:
        return Check("docker", "fail" if needed else "info", "installed but not running",
                     "start Docker Desktop (or the docker service)")
    return Check("docker", "ok", f"engine {out.strip() or 'running'}")


def check_falkordb(system: System) -> list[Check]:
    where = system.location()
    ok, _reason = system.falkordb()
    checks = [Check("falkordb", "ok", f"up ({where})") if ok else
              Check("falkordb", "fail", f"down ({where})",
                    "gittrace up" if where == "local" else "check the remote instance, or unset FALKORDB_HOST "
                                                           "for local Docker; scan --offline needs no database")]
    if where == "local":
        checks.append(Check("database", "ok", "local: graphs stay on this machine"))
    else:
        checks.append(Check("database", "warn", "remote: FALKORDB_HOST is not this machine; graphs include your "
                                                "source code, so scan refuses to write there without --allow-remote",
                            "unset FALKORDB_HOST (or set it to localhost) to use local Docker"))
    return checks


def check_ollama(system: System) -> tuple[list[Check], list[str], list[dict]]:
    """(checks, pulled model names, loaded models from /api/ps)."""
    wanted = {task: _ollama_name(m) for task, m in models().items()}
    if not any(wanted.values()):
        return [Check("ollama", "info", "not used (no Ollama model configured)")], [], []
    base = _ollama_base()
    version = system.http_json(f"{base}/api/version")
    if version is None:
        return ([Check("ollama", "fail", f"not answering ({_ollama_where(base)})",
                       "install Ollama (https://ollama.com) and start it (the app, or `ollama serve`); "
                       "or use --no-llm")], [], [])
    tags = [m.get("name", "") for m in (system.http_json(f"{base}/api/tags") or {}).get("models", [])]
    loaded = (system.http_json(f"{base}/api/ps") or {}).get("models", [])
    checks = [Check("ollama", "ok", f"version {version.get('version', '?')} ({_ollama_where(base)})")]
    for task, name in wanted.items():
        if name is None:
            checks.append(Check(f"model:{task}", "info", f"{models()[task]} (not an Ollama model)"))
        elif _pulled(name, tags):
            checks.append(Check(f"model:{task}", "ok", f"{name} pulled"))
        else:
            checks.append(Check(f"model:{task}", "fail", f"{name} not pulled",
                                f"ollama pull {name}   (or: gittrace up --pull)"))
    return checks, tags, loaded


def check_vram(system: System, loaded: list[dict]) -> Check:
    if system.which("nvidia-smi") is None:
        return Check("vram", "info", "no NVIDIA GPU tools found: not checked (Ollama may use the CPU, which is slower)")
    rc, out = system.run(["nvidia-smi", "--query-gpu=name,memory.total,memory.used",
                          "--format=csv,noheader,nounits"])
    try:
        name, total, used = [x.strip() for x in out.strip().splitlines()[0].split(",")]
        total_gib, used_gib = float(total) / 1024, float(used) / 1024
    except (IndexError, ValueError):
        return Check("vram", "info", "nvidia-smi gave no reading: not checked")
    held = sum(m.get("size_vram", 0) for m in loaded) / 1024 ** 3
    available = total_gib - used_gib + held
    need = {n: VRAM_GIB[n] for n in (_ollama_name(m) for m in models().values()) if n in VRAM_GIB}
    detail = (f"{available:.1f} of {total_gib:.1f} GiB available to Ollama on {name} "
              f"({total_gib - used_gib:.1f} free + {held:.1f} held by loaded models)")
    if need:
        detail += "; needs " + ", ".join(f"{n} {g} GiB" for n, g in need.items())
    short = [n for n, g in need.items() if g > available]
    if short:
        return Check("vram", "warn", detail,
                     "close GPU-heavy apps; Ollama will otherwise run part of " + ", ".join(short) +
                     " on the CPU (slower), and GitTrace retries out-of-memory errors once")
    return Check("vram", "ok", detail)


def _hex_settings(out: str) -> tuple[int, int] | None:
    """powercfg /query: the last two 0x values are the AC and the DC setting (locale-independent)."""
    values = re.findall(r"0x([0-9a-fA-F]+)", out)
    return (int(values[-2], 16), int(values[-1], 16)) if len(values) >= 2 else None


def _minutes(seconds: int) -> str:
    return "never" if seconds == 0 else f"{seconds // 60} min"


def check_power(system: System) -> list[Check]:
    if not system.platform.startswith("win"):
        return [Check("power", "info", "not checked on this OS (sleep can still pause long model runs)")]
    checks = []
    rc, out = system.run(["powershell.exe", "-NoProfile", "-Command",
                          "(Get-CimInstance -Namespace root/wmi -ClassName BatteryStatus).PowerOnline"], timeout=20)
    online = out.strip().splitlines()[0].strip() if rc == 0 and out.strip() else ""
    power = {"True": "AC", "False": "battery"}.get(online, "AC (no battery)" if rc == 0 else "unknown")
    rc, out = system.run(["powercfg", "/getactivescheme"])
    plan = re.search(r"\(([^)]+)\)\s*$", out.strip())
    plan_name = plan.group(1) if plan else "unknown"
    checks.append(Check("power", "warn" if power == "battery" else "ok",
                        f"{power}; power plan {plan_name}",
                        "plug in for long runs (model calls were several times slower on a low battery)"
                        if power == "battery" else ""))
    _, sleep = system.run(["powercfg", "/query", "SCHEME_CURRENT", "SUB_SLEEP", "STANDBYIDLE"])
    _, video = system.run(["powercfg", "/query", "SCHEME_CURRENT", "SUB_VIDEO", "VIDEOIDLE"])
    _, states = system.run(["powercfg", "/a"])
    modern = "S0" in states
    sleep_ac, display_ac = _hex_settings(sleep), _hex_settings(video)
    parts = []
    if sleep_ac:
        parts.append(f"sleep after {_minutes(sleep_ac[0])} on AC, {_minutes(sleep_ac[1])} on battery")
    if display_ac:
        parts.append(f"display off after {_minutes(display_ac[0])} on AC")
    parts.append("Modern Standby (also entered on closing the lid or pressing the power button, "
                 "whatever the timers say)" if modern else "no Modern Standby")
    risky = bool(sleep_ac and sleep_ac[0]) or (modern and bool(display_ac and display_ac[0]))
    checks.append(Check("sleep", "warn" if risky else "ok", "; ".join(parts),
                        ("the machine can sleep during a long explain or triage run (in GitTrace's own "
                         "evaluation, Modern Standby paused single model calls for up to 25 minutes); "
                         + KEEP_AWAKE) if risky else ""))
    return checks


def run_checks(system: System | None = None) -> list[Check]:
    system = system or System()
    checks = [check_python(), check_settings()]
    local = system.location() == "local"
    checks.append(check_docker(system, needed=local))
    checks.extend(check_falkordb(system))
    ollama, _tags, loaded = check_ollama(system)
    checks.extend(ollama)
    checks.append(check_vram(system, loaded))
    checks.extend(check_power(system))
    return checks


def render_checks(console: Console, checks: list[Check]) -> None:
    table = Table(title=Text("gittrace doctor", style=f"bold {render.LAVENDER}"), title_justify="left",
                  show_header=True, header_style="bold", box=None, padding=(0, 2, 0, 0))
    table.add_column("Check", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Detail")
    for c in checks:
        table.add_row(c.name, Text(c.status.upper(), style=STYLE[c.status]), c.detail)
    console.print(table)
    todo = [c for c in checks if c.fix and c.status in ("fail", "warn")]
    if todo:
        console.print()
        console.print(Text("To fix:", style="bold"))
        for c in todo:
            console.print(Text.assemble(("  " + c.name + ": ", STYLE[c.status]), c.fix))
    failed = sum(c.status == "fail" for c in checks)
    console.print()
    console.print(Text("Ready." if not failed else f"{failed} check(s) failed.",
                       style=render.TEAL if not failed else render.RED))


def to_json(checks: list[Check]) -> dict:
    return {"ok": not any(c.status == "fail" for c in checks), "checks": [asdict(c) for c in checks]}


# -- up ---------------------------------------------------------------------------


def up(console: Console, pull: bool = False, system: System | None = None, wait_s: float = 60) -> int:
    """0 ready; 1 something is left to the user (Ollama, models); 2 FalkorDB could not be started."""
    system = system or System()
    say = lambda style, text: console.print(Text(text, style=style))          # noqa: E731
    if system.location() != "local":
        say(render.AMBER, "note: FALKORDB_HOST points to a remote FalkorDB; `up` starts a local one, which "
                          "GitTrace uses only when FALKORDB_HOST is unset or localhost")
    if system.falkordb(local_default=True)[0]:
        say(render.TEAL, "FalkorDB: already running (local)")
    else:
        if system.which("docker") is None:
            say(render.RED, "Docker is not installed: install Docker Desktop (or Docker Engine), then run "
                            "`gittrace up` again")
            return 2
        if system.run(["docker", "info", "--format", "{{.ServerVersion}}"])[0] != 0:
            say(render.RED, "Docker is not running: start Docker Desktop (or the docker service), then run "
                            "`gittrace up` again")
            return 2
        rc, out = system.run(["docker", "ps", "-a", "--filter", f"name={CONTAINER}", "--format", "{{.Names}}"])
        existing = [n.strip() for n in out.splitlines() if n.strip() in (CONTAINER, COMPOSE_CONTAINER)]
        if existing:
            name = CONTAINER if CONTAINER in existing else existing[0]
            say(render.LAVENDER, f"FalkorDB: starting the existing container {name}")
            rc, out = system.run(["docker", "start", name], timeout=60)
        else:
            say(render.LAVENDER, f"FalkorDB: starting {FALKORDB_IMAGE} as {CONTAINER} (the first time pulls the "
                                 "image, about 200 MB)")
            rc = system.stream(["docker", "run", "-d", "--name", CONTAINER, "-p", "6379:6379", "-p", "3000:3000",
                                FALKORDB_IMAGE])
            out = ""
        if rc != 0:
            say(render.RED, "FalkorDB: docker could not start it" + (f": {out.strip()[:300]}" if out.strip() else "")
                + " (is port 6379 already taken by another Redis?)")
            return 2
        deadline = time.monotonic() + wait_s
        while not system.falkordb(local_default=True)[0]:
            if time.monotonic() > deadline:
                say(render.RED, f"FalkorDB: started but not answering after {wait_s:.0f} s "
                                f"(docker logs {existing[0] if existing else CONTAINER})")
                return 2
            system.sleep(1)
        say(render.TEAL, "FalkorDB: up (local)")

    left = 0
    checks, tags, _ = check_ollama(system)
    for c in checks:
        if c.name == "ollama" and c.status == "fail":
            say(render.AMBER, f"Ollama: {c.detail}. {c.fix}")
            return 1
        if c.name.startswith("model:") and c.status == "fail":
            name = c.detail.split()[0]
            if pull:
                say(render.LAVENDER, f"{c.name}: pulling {name}")
                if system.stream(["ollama", "pull", name]) != 0:
                    say(render.RED, f"{c.name}: `ollama pull {name}` failed")
                    left += 1
                    continue
                say(render.TEAL, f"{c.name}: {name} pulled")
            else:
                say(render.AMBER, f"{c.name}: {name} not pulled; run `ollama pull {name}` "
                                  "(or `gittrace up --pull`)")
                left += 1
        elif c.status in ("ok", "info"):
            say(STYLE[c.status], f"{c.name}: {c.detail}")
    if not left:
        say(render.TEAL, "Ready: try `gittrace scan <path>`, or `gittrace` for the interactive mode.")
    return 1 if left else 0
