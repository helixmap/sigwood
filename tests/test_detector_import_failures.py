"""Detector import failures are disclosed, never silently swallowed.

A detector whose module-level import raises ImportError must not vanish from
the run: discovery records the failure, the run plan skips the detector with
an ``import failed - <reason>`` entry on the existing skip surfaces, and the
``detect=`` spec treats the failed name as known - includable and excludable,
never misreported as an unknown detector (which sends the operator hunting a
typo instead of reinstalling a dependency).

The synthetic broken module is named ``dns.py`` because dns is a registered
single-detector verb, which makes the verb-shape CLI surface testable; its
real-world counterpart is a broken hdbscan install failing dns's clustering
import.
"""

from __future__ import annotations

import importlib
import sys
import textwrap
from pathlib import Path
from types import ModuleType

import pytest

from sigwood import cli, runner
from sigwood.runner import build_run_plan, discover_detectors, resolve_detect

_IMPORT_ERROR_LINE = "No module named 'nonexistent_dep'"
_SKIP_REASON = f"import failed - {_IMPORT_ERROR_LINE}"

_PULSE_SOURCE = textwrap.dedent(
    '''
    """Minimal runnable detector for discovery tests."""

    DETECTOR_NAME = "pulse"
    STATUS = "available"
    REQUIRED_LOGS = []
    OPTIONAL_LOGS = []
    DEFAULT_CONFIG = {}


    def run(context):
        return []
    '''
).lstrip()


def _purge_modules(pkg_name: str) -> None:
    for key in [k for k in sys.modules if k == pkg_name or k.startswith(f"{pkg_name}.")]:
        del sys.modules[key]


def _build_pkg(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pkg_name: str,
    modules: dict[str, str],
) -> ModuleType:
    """Materialize a synthetic detectors package and point discovery at it.

    The purge-before-import is required: package names repeat across tests
    in one pytest process, and a cached module from an earlier tmp_path would
    shadow this test's files.
    """
    pkg_dir = tmp_path / pkg_name
    pkg_dir.mkdir()
    (pkg_dir / "__init__.py").write_text("", encoding="utf-8")
    for filename, source in modules.items():
        (pkg_dir / filename).write_text(source, encoding="utf-8")
    _purge_modules(pkg_name)
    importlib.invalidate_caches()
    monkeypatch.syspath_prepend(str(tmp_path))
    pkg = importlib.import_module(pkg_name)
    monkeypatch.setattr(runner, "_detectors_pkg", pkg)
    return pkg


@pytest.fixture
def broken_pkg(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> ModuleType:
    """One well-formed runnable detector (pulse) + one ImportError module (dns)."""
    pkg = _build_pkg(
        tmp_path,
        monkeypatch,
        "fakedetectors",
        {
            "pulse.py": _PULSE_SOURCE,
            "dns.py": f'raise ImportError("{_IMPORT_ERROR_LINE}")\n',
        },
    )
    yield pkg
    _purge_modules("fakedetectors")


def _probe_config(tmp_path: Path) -> Path:
    """Minimal isolated config: tmp root, empty source dirs."""
    (tmp_path / "zeek_empty").mkdir(exist_ok=True)
    (tmp_path / "syslog_empty").mkdir(exist_ok=True)
    probe = tmp_path / "probe.toml"
    probe.write_text(
        "\n".join(
            [
                "[sigwood]",
                f'root = "{tmp_path / "root"}"',
                f'zeek_dir = "{tmp_path / "zeek_empty"}"',
                f'syslog_dir = "{tmp_path / "syslog_empty"}"',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return probe


# ── discovery ────────────────────────────────────────────────────────────────


def test_discover_records_failure_and_returns_good_sibling(
    broken_pkg: ModuleType,
) -> None:
    """The sink records ONLY the broken module; the good sibling really imports.

    Exact-dict assertions on both sides prove the fixture is honest: pulse
    importing under the temp package's own name shows discovery is
    package-relative (a hardcoded production package path would fail every
    synthetic module), and a dns-only sink shows nothing else was recorded.
    """
    failures: dict[str, str] = {}
    detectors = discover_detectors(_failures=failures)

    assert failures == {"dns": _IMPORT_ERROR_LINE}
    assert sorted(detectors) == ["pulse"]
    assert detectors["pulse"].DETECTOR_NAME == "pulse"


def test_discover_sinkless_is_silent_and_safe(broken_pkg: ModuleType) -> None:
    """Without a sink, discovery neither raises nor returns the broken module."""
    detectors = discover_detectors()

    assert sorted(detectors) == ["pulse"]


def test_discover_syntax_error_stays_loud(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The catch is ImportError-only - a corrupt module still crashes loudly.

    Widening the catch would turn discovery into a quiet detector quarantine.
    """
    _build_pkg(
        tmp_path,
        monkeypatch,
        "fakedet_syntax",
        {"corrupt.py": "def (:\n"},
    )
    try:
        with pytest.raises(SyntaxError):
            discover_detectors(_failures={})
    finally:
        _purge_modules("fakedet_syntax")


def test_discover_empty_message_falls_back_to_type_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An ImportError with no message records the exception type name."""
    _build_pkg(
        tmp_path,
        monkeypatch,
        "fakedet_mute",
        {"mute.py": 'raise ImportError("")\n'},
    )
    try:
        failures: dict[str, str] = {}
        discover_detectors(_failures=failures)
        assert failures == {"mute": "ImportError"}
    finally:
        _purge_modules("fakedet_mute")


def test_discover_multiline_message_records_first_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A multi-line ImportError message is truncated to its first line."""
    _build_pkg(
        tmp_path,
        monkeypatch,
        "fakedet_tall",
        {"tall.py": 'raise ImportError("dependency broken\\ndetail line two")\n'},
    )
    try:
        failures: dict[str, str] = {}
        discover_detectors(_failures=failures)
        assert failures == {"tall": "dependency broken"}
    finally:
        _purge_modules("fakedet_tall")


# ── resolve_detect ───────────────────────────────────────────────────────────


def test_resolve_detect_all_appends_failed_names() -> None:
    assert resolve_detect(
        "all", ["beacon", "pulse"], import_failed=["dns"],
    ) == ["beacon", "pulse", "dns"]


def test_resolve_detect_default_appends_failed_names() -> None:
    """Unreadable membership is disclosed under the default keyword."""
    assert resolve_detect(
        "default",
        ["beacon", "pulse"],
        import_failed=["dns"],
        default_members=["beacon"],
    ) == ["beacon", "dns"]


def test_resolve_detect_failed_inclusion_legal() -> None:
    """An explicit inclusion of a broken detector selects it for disclosure."""
    assert resolve_detect("dns", ["pulse"], import_failed=["dns"]) == ["dns"]


def test_resolve_detect_failed_exclusion_legal() -> None:
    """Excluding a broken detector is the natural workaround - never a raise."""
    assert resolve_detect(
        "all,!dns", ["beacon", "pulse"], import_failed=["dns"],
    ) == ["beacon", "pulse"]


def test_resolve_detect_unknown_raises_alongside_failed() -> None:
    """A genuinely-unknown token still raises; the failed sibling stays legal.

    The error lists only available names - a typo report, not a failure report.
    """
    with pytest.raises(ValueError) as exc:
        resolve_detect("beacn,dns", ["beacon", "pulse"], import_failed=["dns"])

    assert str(exc.value) == "unknown detector 'beacn' - available: beacon, pulse"


def test_resolve_detect_no_failures_byte_parity() -> None:
    """With no failures the new keyword is inert for every spec shape."""
    available = ["beacon", "dns", "scan"]
    for spec in ["all", "beacon", "all,!beacon", " "]:
        assert resolve_detect(spec, available) == resolve_detect(
            spec, available, import_failed=(),
        )


# ── build_run_plan ───────────────────────────────────────────────────────────


def test_build_run_plan_skips_import_failed_before_required_logs(
    broken_pkg: ModuleType,
) -> None:
    """The failed detector lands in plan.skipped, never in will_run/needed_logs."""
    plan = build_run_plan("all")

    assert plan.skipped == {"dns": _SKIP_REASON}
    assert plan.will_run == ["pulse"]
    assert plan.selected == ["pulse", "dns"]
    assert plan.needed_logs == {}


def test_build_run_plan_default_discloses_import_failed_membership(
    broken_pkg: ModuleType,
) -> None:
    """A failed module cannot reveal membership, so default selects its skip."""
    plan = build_run_plan("default")

    assert plan.selected == ["dns"]
    assert plan.skipped == {"dns": _SKIP_REASON}
    assert plan.will_run == []


# ── CLI surfaces (real cli.main, real runner.run) ────────────────────────────


def test_cli_hunt_all_discloses_and_siblings_run(
    broken_pkg: ModuleType,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """detect=all with a broken detector: siblings run, the skip is disclosed."""
    probe = _probe_config(tmp_path)
    cli.main(["hunt", "--detect=all", f"--config={probe}"])

    captured = capsys.readouterr()
    # Exact line pins the voice too: lowercase-led, no `sigwood:` self-prefix.
    assert f"{_SKIP_REASON} - skipping dns detection" in captured.err.splitlines()
    assert f"dns - {_SKIP_REASON}" in captured.out
    assert "pulse" in captured.out


def test_cli_hunt_detect_flag_broken_name_skips_not_unknown(
    broken_pkg: ModuleType,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--detect=<broken> is a disclosed skip, not `unknown detector`."""
    probe = _probe_config(tmp_path)
    with pytest.raises(SystemExit) as exc:
        cli.main(["hunt", "--detect=dns", f"--config={probe}"])

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert f"{_SKIP_REASON} - skipping dns detection" in err
    assert (
        "no detectors could run - check required log source paths in config "
        "or CLI overrides"
    ) in err
    assert "unknown detector" not in err


def test_cli_single_detector_verb_broken_skips_not_unknown(
    broken_pkg: ModuleType,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The `sigwood dns <path>` verb shape matches the flag shape's outcome."""
    logfile = tmp_path / "dns.log"
    logfile.write_text(
        '{"_path":"dns","ts":1.0,"id.orig_h":"192.0.2.1",'
        '"query":"example.com","qclass":1}\n',
        encoding="utf-8",
    )
    probe = _probe_config(tmp_path)
    with pytest.raises(SystemExit) as exc:
        cli.main(["dns", str(logfile), f"--config={probe}"])

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert f"{_SKIP_REASON} - skipping dns detection" in err
    assert "no detectors could run" in err
    assert "unknown detector" not in err


def test_cli_exclusion_workaround_accepted(
    broken_pkg: ModuleType,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--detect=all,!<broken> runs the siblings; excluded is excluded (no entry)."""
    probe = _probe_config(tmp_path)
    cli.main(["hunt", "--detect=all,!dns", f"--config={probe}"])

    captured = capsys.readouterr()
    assert "skipping dns" not in captured.err
    assert "unknown detector" not in captured.err
    assert "pulse" in captured.out


def test_cli_dry_run_banner_discloses_import_failure(
    broken_pkg: ModuleType,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A dry run must disclose the import failure on its skipped: line."""
    probe = _probe_config(tmp_path)
    cli.main(["hunt", "--detect=all", "--dry-run", f"--config={probe}"])

    out = capsys.readouterr().out
    assert "skipped:" in out
    assert f"dns - {_SKIP_REASON}" in out
    assert "pulse" in out
