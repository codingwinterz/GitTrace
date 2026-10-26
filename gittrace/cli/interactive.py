"""
gittrace.cli.interactive — the interactive mode (Textual), opened by running
`gittrace` with no arguments in a terminal (gittrace.cli.main).

    +-----------------------------------------------------------------+
    |  logo    GitTrace  version                                       |
    |  (12     project, model(s), FalkorDB status                      |
    |  rows)   /help, ctrl+q                                           |
    +-----------------------------------------------------------------+
      output: the same Rich rendering as the CLI commands, scrollable
      status line
    > /scan . (history: up / down; suggestions: right arrow)

Commands are parsed and run by gittrace.cli.session. Each one runs on a
daemon thread, so quitting never waits for a scan, and draws on a Rich
console captured as ANSI text, which the output area shows unchanged. One
command runs at a time. Log warnings raised while it runs go to the output
(on the command line they go to stderr).

The logo (gittrace.cli.logo) turns once at launch and then once after every
HOLD_SECONDS at rest. It holds still while a command runs, and is a static
frame with --no-anim, when NO_COLOR is set, or in a terminal smaller than
MIN_COLS x MIN_ROWS.
"""

from __future__ import annotations

import io
import logging
import os
import threading
import time

from rich.console import Console
from rich.text import Text
from textual import events
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.suggester import SuggestFromList
from textual.widgets import Input, RichLog, Static

from gittrace import __version__
from gittrace.cli import logo, render
from gittrace.cli.session import NAMES, Command, CommandError, Session, falkordb_status, first_hint, parse

MIN_COLS, MIN_ROWS = 80, 24
DIM_HEX = "#9e9e9e"                    # render.DIM (grey62); Textual CSS has no grey62
INSTANT = ("/help", "/model")          # run on the UI thread: no I/O, nothing slow


def animation_allowed(no_anim: bool, environ=os.environ) -> bool:
    return not no_anim and not environ.get("NO_COLOR")


def capture_console(width: int) -> tuple[Console, io.StringIO]:
    """A console like the CLI's (gittrace.cli._console) that records ANSI text."""
    buffer = io.StringIO()
    return Console(file=buffer, width=width, force_terminal=True, color_system="truecolor",
                   legacy_windows=False, highlight=False, soft_wrap=False), buffer


class _ConsoleLog(logging.Handler):
    """Log warnings into the command's output, formatted as the CLI's stderr."""

    def __init__(self, console: Console):
        super().__init__(logging.WARNING)
        self.console = console
        self.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        self.console.print(Text(self.format(record), style=render.AMBER))


class Logo(Static):
    """The turning node cluster: precomputed frames, swapped by a timer that
    runs only during a turn (paused while the logo holds still)."""

    def __init__(self, animate: bool, **kwargs):
        super().__init__(**kwargs)
        self.allowed = animate
        self.fits = True
        self.busy = False
        self.spinning = False
        self.index = 0
        rows = logo.frames() if animate else (logo.static_frame(),)
        self._frames = [Text("\n".join(r), style=render.LAVENDER, no_wrap=True, end="") for r in rows]
        self._spin = None
        self._hold = None

    @property
    def active(self) -> bool:
        return self.allowed and self.fits and not self.busy

    def on_mount(self) -> None:
        self.update(self._frames[0])
        if self.allowed:
            self._spin = self.set_interval(1 / logo.FPS, self._tick, pause=True)
            self._sync(turn_now=True)

    def set_fits(self, fits: bool) -> None:
        if fits != self.fits:
            self.fits = fits
            self._sync()

    def set_busy(self, busy: bool) -> None:
        if busy != self.busy:
            self.busy = busy
            self._sync()

    def _sync(self, turn_now: bool = False) -> None:
        if self._spin is None:
            return
        if self.active:
            if turn_now or self.index:          # at launch, or finish a turn that was interrupted
                self._resume()
            elif self._hold is None:
                self._hold = self.set_timer(logo.HOLD_SECONDS, self._turn)
            return
        self._pause()
        if not self.fits:                       # too small: the static frame
            self.index = 0
            self.update(self._frames[0])

    def _turn(self) -> None:
        self._hold = None
        if self.active:
            self._resume()

    def _resume(self) -> None:
        self._spin.resume()
        self.spinning = True

    def _pause(self) -> None:
        self._spin.pause()
        self.spinning = False
        if self._hold is not None:
            self._hold.stop()
            self._hold = None

    def _tick(self) -> None:
        if not self.spinning:
            return
        self.index = (self.index + 1) % len(self._frames)
        self.update(self._frames[self.index])
        if self.index == 0:                     # a full turn: rest
            self._pause()
            self._hold = self.set_timer(logo.HOLD_SECONDS, self._turn)


class HistoryInput(Input):
    """The prompt, with earlier commands on the up and down arrows."""

    BINDINGS = [Binding("up", "history(-1)", show=False), Binding("down", "history(1)", show=False)]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.history: list[str] = []
        self._position: int | None = None
        self._draft = ""

    def remember(self, line: str) -> None:
        if line.strip() and (not self.history or self.history[-1] != line):
            self.history.append(line)
        self._position = None

    def action_history(self, step: int) -> None:
        if not self.history:
            return
        if self._position is None:
            if step > 0:
                return
            self._draft, self._position = self.value, len(self.history)
        self._position = max(0, self._position + step)
        if self._position >= len(self.history):
            self._position, self.value = None, self._draft
        else:
            self.value = self.history[self._position]
        self.cursor_position = len(self.value)


class GitTraceApp(App):
    TITLE = "GitTrace"
    CSS = f"""
    #header {{ height: {logo.ROWS + 2}; border: round {render.LAVENDER}; padding: 0 1; }}
    #logo {{ width: {logo.COLS}; height: {logo.ROWS}; }}
    #info {{ width: 1fr; height: {logo.ROWS}; padding: 1 0 0 3; }}
    #output {{ height: 1fr; padding: 0 1; background: $background; }}
    #status {{ height: 1; padding: 0 2; color: {DIM_HEX}; }}
    #prompt {{ border: round {DIM_HEX}; }}
    #prompt:focus {{ border: round {render.LAVENDER}; }}
    """
    BINDINGS = [Binding("ctrl+q", "quit", "Quit", priority=True)]

    def __init__(self, session: Session | None = None, animate: bool = True, falkordb=falkordb_status):
        super().__init__()
        self.session = session or Session()
        self.animate_logo = animate         # not `animate`: App.animate is Textual's
        self.busy = False
        self.falkordb: tuple[str, str] | None = None
        self._falkordb_check = falkordb

    def compose(self) -> ComposeResult:
        with Horizontal(id="header"):
            yield Logo(self.animate_logo, id="logo")
            yield Static(id="info")
        yield RichLog(id="output", wrap=False, highlight=False, markup=False, min_width=40)
        yield Static(id="status")
        yield HistoryInput(id="prompt", placeholder="Type a command, e.g. /scan .  (/help lists them)",
                           suggester=SuggestFromList(NAMES, case_sensitive=False))

    def on_mount(self) -> None:
        self._fit(self.size.width, self.size.height)
        self.refresh_info()
        self.check_falkordb()
        output = self.query_one(RichLog)
        if not output.lines:                    # an empty output area: say what to type first
            output.write(Text(first_hint(self.session.project), style=render.DIM))
        self.query_one(HistoryInput).focus()

    def on_resize(self, event: events.Resize) -> None:
        self._fit(event.size.width, event.size.height)

    def _fit(self, width: int, height: int) -> None:
        self.query_one(Logo).set_fits(width >= MIN_COLS and height >= MIN_ROWS)

    # -- header ---------------------------------------------------------------

    def info_text(self) -> Text:
        s = self.session
        text = Text.assemble(("GitTrace", f"bold {render.LAVENDER}"), (f"  v{__version__}", render.DIM), "\n\n")
        text.append("project   ", render.DIM)
        text.append(f"{s.project}\n")
        text.append("model     ", render.DIM)
        if s.model:
            text.append(f"{s.model}\n")
        else:                                   # each command's own default, one per line
            text.append("scan     ", render.DIM)
            text.append(f"{s.scan_model()}\n")
            text.append(" " * 10 + "explain  ", render.DIM)
            text.append(f"{s.explain_model()}\n")
        text.append("FalkorDB  ", render.DIM)
        if self.falkordb is None:
            text.append("checking…", render.DIM)
        else:
            state, where = self.falkordb       # "local" / "remote": never the host
            text.append(f"● {state}", render.TEAL if state == "up" else render.AMBER)
            text.append(f"  {where}", render.DIM if where == "local" else render.AMBER)
            if state == "down" and where == "local":
                text.append("  (docker compose up -d falkordb, or /scan --offline)", render.DIM)
        text.append("\n\n/help for commands · ctrl+q to quit", render.DIM)
        return text

    def refresh_info(self) -> None:
        self.query_one("#info", Static).update(self.info_text())

    def check_falkordb(self) -> None:
        def check() -> None:
            self._from_thread(self._set_falkordb, self._falkordb_check())
        threading.Thread(target=check, name="gittrace-falkordb", daemon=True).start()

    def _set_falkordb(self, status: tuple[str, str]) -> None:
        self.falkordb = status
        self.refresh_info()

    # -- commands -------------------------------------------------------------

    def on_input_submitted(self, event: Input.Submitted) -> None:
        prompt = self.query_one(HistoryInput)
        line = event.value
        if not line.strip():
            return
        if self.busy:
            self.set_status("a command is still running; wait for it to finish (ctrl+q quits)")
            return
        prompt.value = ""
        prompt.remember(line)
        output = self.query_one(RichLog)
        output.write(Text(f"› {line.strip()}", style=f"bold {render.LAVENDER}"))
        try:
            cmd = parse(line)
        except CommandError as exc:
            self._error(str(exc))
            return
        if cmd is None:
            return
        if cmd.name == "/quit":
            self.exit()
        elif cmd.name in INSTANT:
            console, buffer = capture_console(self._width())
            self.session.run(cmd, console)
            output.write(Text.from_ansi(buffer.getvalue()))
            self.refresh_info()
        else:
            self._start(cmd, line.strip())

    def _start(self, cmd: Command, line: str) -> None:
        self.busy = True
        self.query_one(Logo).set_busy(True)
        self.set_status(f"running {line}")
        threading.Thread(target=self._work, args=(cmd, self._width()), name="gittrace-command",
                         daemon=True).start()

    def _work(self, cmd: Command, width: int) -> None:
        """On the command thread: run it, then hand the output to the UI thread."""
        console, buffer = capture_console(width)
        handler = _ConsoleLog(console)
        logging.getLogger().addHandler(handler)
        started, error = time.perf_counter(), None
        try:
            self.session.run(cmd, console, status=lambda s: self._from_thread(self.set_status, s))
        except CommandError as exc:
            error = str(exc)
        except Exception as exc:        # noqa: BLE001 - show it rather than lose it
            error = f"{type(exc).__name__}: {exc}"
        finally:
            logging.getLogger().removeHandler(handler)
        self._from_thread(self._finish, cmd, buffer.getvalue(), error, time.perf_counter() - started)

    def _finish(self, cmd: Command, ansi: str, error: str | None, seconds: float) -> None:
        if ansi:
            self.query_one(RichLog).write(Text.from_ansi(ansi))
        if error:
            self._error(error)
        self.busy = False
        self.query_one(Logo).set_busy(False)
        self.set_status(f"{cmd.name} {'failed' if error else 'done'} in {seconds:.1f} s")
        self.refresh_info()
        if cmd.name in ("/scan", "/trace", "/blast-radius"):
            self.check_falkordb()

    def _from_thread(self, fn, *args) -> None:
        try:
            self.call_from_thread(fn, *args)
        except RuntimeError:            # the app has closed
            pass

    def _error(self, message: str) -> None:
        self.query_one(RichLog).write(Text.assemble(("error: ", "bold red"), message))

    def set_status(self, message: str) -> None:
        self.query_one("#status", Static).update(Text(message, no_wrap=True, overflow="ellipsis"))

    def _width(self) -> int:
        return max(40, self.query_one(RichLog).scrollable_content_region.width - 1)


def run(no_anim: bool = False) -> int:
    GitTraceApp(animate=animation_allowed(no_anim)).run()
    return 0
