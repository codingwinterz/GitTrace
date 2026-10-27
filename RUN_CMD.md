# Using GitTrace in the Windows Command Prompt (cmd)

A step-by-step guide for running GitTrace from `cmd.exe` (on its own or as a tab in
Windows Terminal). Every command below is written for cmd. In PowerShell most of them
work unchanged; the differences are noted where they matter. For what the rules and the
model do, see [README.md](README.md); for the short version for any shell, see
[RUN.md](RUN.md).

## 1. Open a Command Prompt

- Press **Win + R**, type `cmd`, press Enter, **or**
- open **Windows Terminal** and choose *Command Prompt* from the tab menu (recommended:
  better colours, Unicode and resizing for the interactive mode).

Check that Python is there (use 3.12, 3.13 or 3.14; see README "Install" for why not 3.15):

```bat
py --list
py -3.14 --version
```

## 2. Install GitTrace

Pick **one** of the two ways.

### A. As a tool (pipx): `gittrace` works in every folder

```bat
py -3.14 -m pip install --user pipx
py -3.14 -m pipx ensurepath
```

Close cmd and open a new one (so the PATH change takes effect), then:

```bat
pipx install --python 3.14 git+https://github.com/codingwinterz/GitTrace@v2.0.0
gittrace --version
```

### B. From a clone of the repository (for development)

```bat
git clone https://github.com/codingwinterz/GitTrace.git
cd GitTrace
git checkout v2.0.0
py -3.14 -m venv .venv
.venv\Scripts\activate.bat
pip install -r requirements.txt
gittrace --version
```

`activate.bat` is the cmd version; in PowerShell it is `.venv\Scripts\Activate.ps1`.
The prompt shows `(.venv)` while the environment is active. In every new cmd window, run
`.venv\Scripts\activate.bat` again from the repository folder before using `gittrace`.
Without activating, call it by its full path: `.venv\Scripts\gittrace.exe`.

If cmd says `'gittrace' is not recognized as an internal or external command`, either the
virtual environment is not active (B) or the PATH change from `pipx ensurepath` needs a new
cmd window (A). `where gittrace` shows which `gittrace.exe` cmd finds.

## 3. Start Docker and Ollama (only for a full scan)

A full `gittrace scan` uses **Docker Desktop** (for the FalkorDB graph database) and
**Ollama** (for the local model). Start both from the Start menu, then:

```bat
gittrace up --pull
gittrace doctor
```

- `up --pull` starts FalkorDB in Docker and downloads the two models (about 9.6 GB the
  first time).
- `doctor` checks Docker, FalkorDB, Ollama, the models, free GPU memory, and Windows power
  and sleep settings. It exits with code 1 when something is not ready (`echo %ERRORLEVEL%`
  shows it).

**Without Docker or Ollama** you can still use GitTrace: add `--offline --no-llm` to `scan`
and `--no-llm` to `explain` (see below).

## 4. Open the interactive mode

Type `gittrace` with nothing after it:

```bat
gittrace
```

This opens a full-screen view with the logo, the current project, the models and the
FalkorDB status, and a prompt at the bottom. Type commands starting with `/`:

| Type this | What it does |
|---|---|
| `/help` | list the commands |
| `/scan tests\fixtures\sample_app` | scan a project (`--offline`, `--no-llm`, `--fix`, ... also work) |
| `/explain .` | explain the project in the current folder in plain language |
| `/trace app/db.py:17` | attack paths to the finding at that file and line (after a `/scan`) |
| `/blast-radius app/db.py::Repo.get_user` | every caller of a function and every endpoint that reaches it |
| `/model` | show the models; `/model ollama/qwen2.5-coder:7b` uses one model for both; `/model default` goes back |
| `/quit` or **Ctrl+Q** | leave |

Keys: **Up / Down** recall earlier commands, **Right arrow** accepts the suggested command
name. Scroll the output with the mouse wheel.

Good to know in cmd:

- The window should be at least **80 columns by 24 rows**; smaller, the logo stops turning
  (everything else still works). In the classic cmd window you can resize with
  `mode con: cols=120 lines=40`; in Windows Terminal just drag the window.
- `gittrace --no-anim` opens it with a still logo; setting `NO_COLOR` does the same
  (`set NO_COLOR=1`).
- The interactive mode opens only when cmd is a real terminal. With redirected input or
  output (`gittrace > out.txt`, or in a pipe) you get the normal command-line help instead.

## 5. The same from the command line (no interactive mode)

Paths can use backslashes. Quote paths that contain spaces: `"C:\My Projects\app"`.

```bat
gittrace scan tests\fixtures\sample_app
gittrace scan C:\path\to\project --offline --no-llm
gittrace scan C:\path\to\project --no-llm
gittrace scan C:\path\to\project --fix
gittrace scan C:\path\to\project --format json > findings.json

gittrace trace app/db.py:17 -p tests\fixtures\sample_app
gittrace blast-radius app/db.py::Repo.get_user -p tests\fixtures\sample_app

gittrace explain C:\path\to\project
gittrace explain C:\path\to\project --no-llm
gittrace explain C:\path\to\project --out EXPLAIN.md
gittrace explain C:\path\to\project --file app/db.py
gittrace explain C:\path\to\project --function app/db.py::Repo.get_user
```

- `--offline` scans in memory without FalkorDB; `--no-llm` skips the model.
- `--fix` adds a suggested fix as a diff. GitTrace never changes your files.
- File and function ids inside a project (`app/db.py`, `app/db.py::Repo.get_user`) always
  use forward slashes, as GitTrace prints them.
- `gittrace scan` exits with code 1 when a finding is at or above `--fail-on` (default
  `high`), which is useful in batch files: `gittrace scan . --no-llm || echo issues found`.
- `gittrace <command> --help` lists every option of a command.

Saving output to a file works with `>`; GitTrace writes UTF-8, so open the file in an
editor that reads UTF-8 (Notepad, VS Code). Use `--format json` (or `--out` for `explain`)
for files meant to be read by other programs.

## 6. Settings in cmd

No settings file is needed for local Docker and Ollama. To change something for the
current window only, use `set` (no spaces around `=`):

```bat
set GITTRACE_MODEL=ollama/qwen2.5-coder:7b
set GITTRACE_EXPLAIN_MODEL=ollama/llama3.1:8b
set GITTRACE_LLM_TIMEOUT=300
gittrace scan .
```

To keep a setting for new windows, use `setx GITTRACE_MODEL ollama/qwen2.5-coder:7b`
(it takes effect in the *next* cmd window, not the current one). The full list of
settings is in `.env.example` and README "Settings". In PowerShell the same is
`$env:GITTRACE_MODEL = "ollama/qwen2.5-coder:7b"`.

## 7. Long multi-line commands

cmd continues a line with `^` at the end (PowerShell uses a backtick, bash `\`):

```bat
gittrace scan C:\path\to\project ^
  --no-llm ^
  --min-severity medium
```
