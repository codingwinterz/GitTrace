"""Terminal-width regression tests for Rich CLI views."""

from __future__ import annotations

import io
import re

import pytest
from rich.console import Console

from gittrace.cli import machine, render

WIDTHS = (80, 100, 110, 120, 200)
REASON = (
    "The configured constant is used only in test setup and cannot contain user-controlled data. "
    "The finding does not interpolate values supplied by a request."
)


def _finding(verdict: str = "likely_harmless") -> dict:
    return {
        "severity": "low",
        "rule_id": "GT-SQLI-001",
        "location": {"file": "src/api.py", "line": 143},
        "reachability": {
            "applies": True,
            "routes": [{"method": "GET", "path": "/api/reports/{id}"}],
            "uncertain": False,
            "unauthenticated": True,
        },
        "triage": {
            "verdict": verdict,
            "error": None,
            "severity_adjustment": 0,
            "reason": REASON,
        },
    }


def _console(width: int, file: io.StringIO) -> Console:
    return Console(file=file, width=width, color_system=None, highlight=False)


def _assert_fits_width(text: str, width: int) -> None:
    assert max((len(line) for line in text.splitlines()), default=0) <= width


def _without_whitespace(text: str) -> str:
    return re.sub(r"\s+", "", text)


@pytest.mark.parametrize("width", WIDTHS)
def test_findings_tables_keep_minimum_column_width_and_content(width, monkeypatch):
    monkeypatch.setenv("COLUMNS", str(width))
    finding = _finding("likely_real")
    compact = width < render._WIDE_FINDINGS_WIDTH
    table = render.findings_table([finding], compact=compact)
    output = io.StringIO()
    console = _console(width, output)
    widths = table._calculate_column_widths(console, console.options)

    assert all(actual >= (column.min_width or 1)
               for column, actual in zip(table.columns, widths))
    assert ("Model's reason" not in [str(column.header) for column in table.columns])
    if not compact:
        assert "Finding" not in [str(column.header) for column in table.columns]

    render._render_findings_table(console, [finding])
    text = output.getvalue()
    _assert_fits_width(text, width)
    for value in ("GT-SQLI-001", "src/api.py:143", "/api/reports/{id}", "likely real"):
        assert value in text


@pytest.mark.parametrize("width", WIDTHS)
def test_likely_harmless_reason_is_wrapped_below_row_not_squeezed(width, monkeypatch):
    monkeypatch.setenv("COLUMNS", str(width))
    output = io.StringIO()
    console = _console(width, output)
    render._render_findings_table(console, [_finding()], reasons=True)
    text = output.getvalue()

    _assert_fits_width(text, width)
    assert "Model's reason:" in text
    assert _without_whitespace(REASON) in _without_whitespace(text)
    # A regression to one character per line creates well over 100 rows here.
    assert len(text.splitlines()) < 30
    assert text.index("GT-SQLI-001") < text.index("Model's reason:")

    table = render.findings_table([_finding()], compact=True)
    table_widths = table._calculate_column_widths(console, console.options)
    assert all(actual >= (column.min_width or 1)
               for column, actual in zip(table.columns, table_widths))
    assert "Model's reason" not in [str(column.header) for column in table.columns]


@pytest.mark.parametrize("width", WIDTHS)
def test_summary_panel_and_attack_path_tree_wrap_without_losing_text(width, monkeypatch):
    monkeypatch.setenv("COLUMNS", str(width))
    data = {
        "summary": {
            "total": 13,
            "by_severity": {"critical": 7, "high": 1, "medium": 5, "low": 0, "info": 0},
            "reachable": 8,
            "unauthenticated": 7,
            "test_findings": 0,
        },
        "scanned": {"files": 25, "functions": 120, "endpoints": 18, "parse_failures": 0},
        "project": "sample_app",
        "llm": {
            "enabled": True,
            "model": "ollama/llama3.1:8b",
            "by_verdict": {"likely_real": 7, "uncertain": 4, "likely_harmless": 2},
            "cached": 0,
            "errors": 0,
        },
    }
    summary_output = io.StringIO()
    _console(width, summary_output).print(render.headline(data))
    summary = summary_output.getvalue()
    _assert_fits_width(summary, width)
    for value in ("sample_app", "25", "120", "18", "reachable from an endpoint"):
        assert value in summary

    long_route = "/" + "very-long-route-segment/" * 6
    long_handler = "handler::" + "very_long_function_name_" * 4
    long_sink = "callee::" + "another_long_function_name_" * 4
    routes = [{
        "method": "GET",
        "path": long_route,
        "auth_required": False,
        "prefix_resolved": False,
        "path_nodes": [long_handler, long_sink],
    }]
    tree_output = io.StringIO()
    _console(width, tree_output).print(render.path_tree("Attack paths", routes))
    tree = tree_output.getvalue()
    _assert_fits_width(tree, width)
    flattened = _without_whitespace(tree)
    assert "very-long-route-segment/" in tree
    assert _without_whitespace(long_route) in flattened
    # The route label is the tree root; path_nodes[0] is represented by it,
    # and only subsequent path nodes are emitted as descendants.
    assert _without_whitespace(long_sink) in flattened


@pytest.mark.parametrize("width", WIDTHS)
def test_doctor_table_wraps_long_detail_without_cutting_text(width, monkeypatch):
    monkeypatch.setenv("COLUMNS", str(width))
    detail = "Diagnostic detail with a meaningful continuation. " * 5
    checks = [machine.Check("settings", "info", detail)]
    output = io.StringIO()
    machine.render_checks(_console(width, output), checks)
    text = output.getvalue()

    _assert_fits_width(text, width)
    assert _without_whitespace(detail) in _without_whitespace(text)
    assert "settings" in text and "INFO" in text
