"""
tests/test_config.py — where settings come from (gittrace.config): environment
variables first, then the first .env of $GITTRACE_ENV_FILE / the checkout / the
user config directory; never the current directory (the scanned project).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from gittrace import config

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture
def fresh(monkeypatch):
    monkeypatch.setattr(config, "_done", False)
    monkeypatch.setattr(config, "_loaded", None)
    for var in ("GITTRACE_TEST_FROM_FILE", "GITTRACE_TEST_WINS"):
        monkeypatch.setenv(var, "placeholder")
        monkeypatch.delenv(var)                 # restored (removed) after the test


def test_env_file_variable_comes_first(tmp_path, monkeypatch, fresh):
    env = tmp_path / "custom.env"
    env.write_text("GITTRACE_TEST_FROM_FILE=from-file\nGITTRACE_TEST_WINS=from-file\n", encoding="utf-8")
    monkeypatch.setenv(config.ENV_FILE_VAR, str(env))
    monkeypatch.setenv("GITTRACE_TEST_WINS", "from-environment")
    assert config.candidates()[0] == env
    assert config.load() == env
    assert os.environ["GITTRACE_TEST_FROM_FILE"] == "from-file"
    assert os.environ["GITTRACE_TEST_WINS"] == "from-environment"      # variables win over files


def test_a_checkout_uses_its_own_env(monkeypatch):
    monkeypatch.delenv(config.ENV_FILE_VAR, raising=False)
    assert REPO / ".env" in config.candidates()


def test_the_current_directory_is_never_read(tmp_path, monkeypatch, fresh):
    (tmp_path / ".env").write_text("GITTRACE_TEST_FROM_FILE=from-scanned-project\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(config.ENV_FILE_VAR, raising=False)
    assert all(p.parent.resolve() != tmp_path.resolve() for p in config.candidates())
    monkeypatch.setattr(config, "candidates", lambda: [tmp_path / "missing.env"])
    assert config.load() is None and "GITTRACE_TEST_FROM_FILE" not in os.environ


def test_user_config_directory_is_a_candidate(monkeypatch):
    from platformdirs import user_config_dir

    monkeypatch.delenv(config.ENV_FILE_VAR, raising=False)
    assert Path(user_config_dir("gittrace", appauthor=False)) / ".env" in config.candidates()
