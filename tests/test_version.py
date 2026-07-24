"""`sigwood --version` / `-V` and the single-sourced package version.

The version subsystem has two parts:
  A. the version is single-sourced in ``sigwood/__init__.py`` (pyproject reads it
     dynamically), and
  B. ``--version`` / ``-V`` is a global leading-token short-circuit in ``cli._main``
     that prints ``sigwood <version>`` and exits 0 BEFORE config load / dispatch.
"""

from __future__ import annotations

import importlib.metadata
import tomllib
from pathlib import Path

import pytest

import sigwood
from sigwood import cli
from sigwood.common import config as cfg
from sigwood.common.display import version_string
from sigwood.common.errors import UsageError

_PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


# ── the --version / -V flag ───────────────────────────────────────────────────


def test_version_long(capsys):
    rc = cli._main(["--version"])
    assert rc == 0
    assert capsys.readouterr().out == f"sigwood {sigwood.__version__}\n"


def test_version_string_is_canonical_human_label() -> None:
    assert version_string() == f"sigwood {sigwood.__version__}"


def test_version_short(capsys):
    rc = cli._main(["-V"])
    assert rc == 0
    assert capsys.readouterr().out == f"sigwood {sigwood.__version__}\n"


def test_version_precedes_config(capsys, monkeypatch):
    """The version short-circuit does NOT touch the config layer on the success path.

    Monkeypatch both config seams (``cfg._find_config_file``, ``cfg.load``) to raise;
    ``--version`` / ``-V`` must still print and return 0 - so the branch returns without
    invoking config. This is a PLACEMENT guard (it would catch the short-circuit being
    relocated to AFTER a config call); it does NOT by itself prove the branch precedes
    config in general - a removed short-circuit instead raises ``UsageError`` at parse
    time, before ``cfg.load``.
    """
    def _explode(*args, **kwargs):  # pragma: no cover - must never be reached
        raise AssertionError("config layer reached before --version short-circuit")

    monkeypatch.setattr(cfg, "_find_config_file", _explode)
    monkeypatch.setattr(cfg, "load", _explode)

    for tok in ("--version", "-V"):
        rc = cli._main([tok])
        assert rc == 0
        assert capsys.readouterr().out == f"sigwood {sigwood.__version__}\n"


@pytest.mark.parametrize("argv", [["--version=x"], ["-V=x"]])
def test_version_equals_form_not_version(capsys, argv):
    """`--version=x` / `-V=x` are NOT a version request - they fall through to the
    strict parser (known-but-wrong-verb). Assert the version line is NOT printed;
    do not couple to the error wording."""
    with pytest.raises(UsageError):
        cli._main(argv)
    assert f"sigwood {sigwood.__version__}" not in capsys.readouterr().out


@pytest.mark.parametrize("verb", ["hunt", "digest"])
def test_version_after_verb_not_shortcircuited(capsys, verb):
    """Global-leading-only: `version` after a verb is NOT short-circuited - it
    falls through to that verb's strict parsing. Assert no version output; do not
    couple to the error wording."""
    with pytest.raises(UsageError):
        cli._main([verb, "--version"])
    assert f"sigwood {sigwood.__version__}" not in capsys.readouterr().out


def test_usage_advertises_version():
    usage = cli._global_usage_text()
    assert "--version" in usage
    assert "-V" in usage


def test_short_flag_map_case_distinct():
    """`-V` (version) stays case-distinct from `-v` (verbose) in the case-sensitive
    short-flag map - the no-collision invariant for the first capital short flag."""
    assert cli._FLAGS_BY_SHORT["v"].key == "verbose"
    assert cli._FLAGS_BY_SHORT["V"].key == "version"


def test_version_not_in_any_verb_allowed():
    """Global-leading-only: `version` is in no verb's `allowed` set - so it never leaks
    into per-verb parsing or per-verb help."""
    for verb, vs in cli._VERBS.items():
        assert "version" not in vs.allowed, verb


# ── single-sourced version ────────────────────────────────────────────────────


def test_version_single_sourced():
    """Drift sentinel: installed distribution metadata equals the in-package literal.

    Catches a future divergence between ``sigwood/__init__.py`` and the built dist
    metadata (regenerated on a fresh editable reinstall). It does NOT by itself prove
    the dynamic ``{attr = ...}`` wiring - both sides read the same value today, so a
    regressed attr path would not turn this red; ``test_pyproject_version_is_dynamic``
    carries that structural proof.
    """
    assert importlib.metadata.version("sigwood") == sigwood.__version__


def test_pyproject_version_is_dynamic():
    """Structural proof of the single-source dedup, independent of installed
    metadata: pyproject declares version dynamically off ``sigwood.__version__``
    and carries no second literal."""
    data = tomllib.loads(_PYPROJECT.read_text())
    project = data["project"]
    assert "version" not in project
    assert "version" in project["dynamic"]
    assert data["tool"]["setuptools"]["dynamic"]["version"]["attr"] == "sigwood.__version__"
