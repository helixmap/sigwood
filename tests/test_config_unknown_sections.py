"""Unknown config names are disclosed, never swallowed.

A name no reader looks up voids its setting while the run continues on what was
understood.  The disclosure is a warning, not a new validation or stop path.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from sigwood import cli
from sigwood import runner
from sigwood.common import config as cfg

EXAMPLE_PATH = Path("sigwood/data/config_example.toml")


def _dry_run(conf: Path) -> None:
    cli.main(["hunt", f"--config={conf}", "--dry-run"])


def test_known_sections_and_provenance_sidecar_are_not_unknown() -> None:
    """A merged config carries every known section plus the ``__user_set__``
    sidecar the loader attaches; neither is a user-facing section."""
    assert cfg.unknown_sections(cfg.load(None)) == []
    assert cfg.unknown_sections({"sigwood": {}, "__user_set__": {}}) == []
    assert cfg.config_disclosure_lines(cfg.load(None)) == []


def test_unknown_sections_preserve_first_seen_order() -> None:
    assert cfg.unknown_sections({"zzz": 1, "sigwood": {}, "aaa": 2}) == ["zzz", "aaa"]


def test_known_sections_derive_from_defaults() -> None:
    """Sourcing the set from ``_DEFAULTS`` is what keeps a new section from
    drifting into the unknown set."""
    assert cfg.KNOWN_SECTIONS == frozenset(cfg._DEFAULTS)


def test_shipped_example_declares_no_unknown_section() -> None:
    """The shipped template must not trip the tool's own disclosure after init."""
    assert cfg.unknown_sections(cfg.load(EXAMPLE_PATH)) == []
    assert cfg.config_disclosure_lines(cfg.load(EXAMPLE_PATH)) == []


def test_stale_section_name_is_disclosed_not_silently_ignored(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A mistyped or stale section reads as absent; the run says so on stderr."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    conf = tmp_path / "c.toml"
    conf.write_text('[sigwod]\nzeek_dir = "/nonexistent"\n', encoding="utf-8")

    _dry_run(conf)

    assert "config: ignoring unknown section [sigwod]" in capsys.readouterr().err


def test_known_sections_emit_no_disclosure(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    conf = tmp_path / "c.toml"
    conf.write_text(
        '[sigwood]\nzeek_dir = "/nonexistent"\n\n[allowlist]\nenabled = false\n',
        encoding="utf-8",
    )

    _dry_run(conf)

    assert "config:" not in capsys.readouterr().err


def test_two_unknown_sections_emit_one_line_each_and_keep_order(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    conf = tmp_path / "c.toml"
    conf.write_text("[foo]\nx = 1\n\n[bar]\ny = 2\n", encoding="utf-8")

    _dry_run(conf)

    err = capsys.readouterr().err
    assert err.splitlines()[:2] == [
        "config: ignoring unknown section [foo]",
        "config: ignoring unknown section [bar]",
    ]


def test_disclosure_does_not_stop_the_run(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unrecognized section is an advisory, not an error: the run proceeds on
    defaults and the banner still renders to stdout."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    conf = tmp_path / "c.toml"
    conf.write_text("[foo]\nx = 1\n", encoding="utf-8")

    _dry_run(conf)

    captured = capsys.readouterr()
    assert "config: ignoring unknown section [foo]" in captured.err
    assert "dry run" in captured.out


def test_control_bytes_in_a_quoted_section_name_are_stripped(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A TOML quoted key carries arbitrary code points into a terminal sink.

    The probe token reassembles - proving the value reaches the sink - and no
    C0 / DEL / C1 code point survives, proving it is neutralized there.
    """
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    conf = tmp_path / "c.toml"
    # TOML basic strings forbid raw control characters, so the file carries the
    # escapes and tomllib decodes them into real code points.
    conf.write_text(
        '["PROBE\\u001BTOKEN\\u0007SEEN\\u009B\\u007F\\u0001"]\nx = 1\n',
        encoding="utf-8",
    )

    _dry_run(conf)

    err = capsys.readouterr().err
    assert "config: ignoring unknown section [PROBETOKENSEEN]" in err
    assert not [
        ch
        for ch in err
        if (ord(ch) < 0x20 and ch != "\n") or ord(ch) == 0x7F or 0x80 <= ord(ch) <= 0x9F
    ]


def test_config_disclosure_exact_messages_and_declaration_scope_order() -> None:
    config = {
        "sigwood": {"zeek_dri": "/placeholder", "mystery": True},
        "graph": {"top_hsots": 5},
        "detectors": {},
        "allowlist": {},
        "export": {
            "splnk": {"host": "192.0.2.20", "child": "ignored"},
            "splunk": {
                "query": {
                    "nightly": {"outputbase": "syslog"},
                },
            },
        },
        "sigwod": {"zeek_dir": "/placeholder"},
        "__user_set__": {"sigwood": {"zeek_dri"}},
    }

    assert cfg.config_disclosure_lines(config) == [
        "config: ignoring unknown section [sigwod] (did you mean sigwood?)",
        "config: ignoring unknown section [export.splnk] (did you mean splunk?)",
        "config: ignoring unknown setting [sigwood].zeek_dri (did you mean zeek_dir?)",
        "config: ignoring unknown setting [sigwood].mystery",
        "config: ignoring unknown setting [graph].top_hsots (did you mean top_hosts?)",
        "config: ignoring unknown setting [export.splunk.query.nightly].outputbase "
        "(did you mean output_basename?)",
    ]


def test_config_disclosure_open_and_value_shape_arms_are_neutral() -> None:
    config = {
        "sigwood": {"root": {"wrong": "shape"}},
        "graph": "wrong shape",
        "allowlist": {
            "lists": {"future-list": True},
            "entry": [{"future_stanza_key": "open"}],
        },
        "export": {"splunk": "wrong shape"},
    }

    assert cfg.config_disclosure_lines(config) == []


def test_config_disclosure_strips_hostile_quoted_key_fragments() -> None:
    lines = cfg.config_disclosure_lines({
        "sigwood": {"ZEEK\x1b\x07\x9b\x7f_DIR": "/placeholder"},
    })
    assert lines == ["config: ignoring unknown setting [sigwood].ZEEK_DIR"]
    assert not [
        ch
        for ch in lines[0]
        if ord(ch) < 0x20 or ord(ch) == 0x7F or 0x80 <= ord(ch) <= 0x9F
    ]


def test_detector_disclosure_recursive_unknown_and_unreadable_arms() -> None:
    vocab = {
        "beacon": {"threshold": 0.5},
        "dns": {"pihole": {"min_samples": 10}},
        "broken": None,
    }
    configured = {
        "beacn": {"threshold": 0.4},
        "beacon": {"thresold": 0.4},
        "dns": {"pihole": {"min_sampels": 8}},
        "broken": {"anything": "accepted because unreadable"},
    }

    assert cfg.detector_disclosure_lines(configured, vocab) == [
        "config: ignoring unknown detector section [detectors.beacn] "
        "(did you mean beacon?)",
        "config: ignoring unknown setting [detectors.beacon].thresold "
        "(did you mean threshold?)",
        "config: ignoring unknown setting [detectors.dns.pihole].min_sampels "
        "(did you mean min_samples?)",
    ]


def test_detector_disclosure_runs_once_for_selected_unselected_nested_and_dry_run(
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = {
        "sigwood": {"detect": "beacon"},
        "detectors": {
            "beacn": {"threshold": 0.4},
            "beacon": {"thresold": 0.4},
            "duration": {"min_duration_seconds": 10},
            "dns": {"pihole": {"min_sampels": 8}},
        },
    }

    assert runner.run(config=config, dry_run=True, quiet=True) == 0

    err = capsys.readouterr().err
    expected = [
        "config: ignoring unknown detector section [detectors.beacn] "
        "(did you mean beacon?)",
        "config: [detectors.duration] is retired; use [detectors.exfil] "
        "- retired keys: min_duration_seconds",
        "config: ignoring unknown setting [detectors.beacon].thresold "
        "(did you mean threshold?)",
        "config: ignoring unknown setting [detectors.dns.pihole].min_sampels "
        "(did you mean min_samples?)",
    ]
    assert err.splitlines() == expected
    assert all(err.count(line) == 1 for line in expected)


def test_detector_disclosure_also_runs_on_the_live_path(
    capsys: pytest.CaptureFixture[str],
) -> None:
    detector = SimpleNamespace(
        DEFAULT_CONFIG={"threshold": 0.5},
        REQUIRED_LOGS=[],
        OPTIONAL_LOGS=[],
        run=lambda _context: [],
    )
    selection = runner.select_detectors("alpha", {"alpha": detector})

    assert runner.run(
        config={
            "sigwood": {"detect": "alpha"},
            "detectors": {"alpha": {"thresold": 0.4}},
        },
        quiet=True,
        _detector_selection=selection,
    ) == 0

    assert capsys.readouterr().err.splitlines() == [
        "config: ignoring unknown setting [detectors.alpha].thresold "
        "(did you mean threshold?)",
    ]


def test_real_cli_discloses_every_non_detector_scope_in_contract_order(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    conf = tmp_path / "all-scopes.toml"
    conf.write_text(
        f"[sigwood]\nroot = '{tmp_path}'\nzeek_dri = '/placeholder'\n"
        "[graph]\ntop_hsots = 3\n"
        "[allowlist]\nallowlist_dri = 'lists/'\n"
        "[export.splnk]\nhost = '192.0.2.20'\nchild = 'not walked'\n"
        "[export.splunk]\nusernme = 'operator'\n"
        "[export.splunk.query.nightly]\noutputbase = 'syslog'\n",
        encoding="utf-8",
    )

    cli.main(["hunt", f"--config={conf}", "--dry-run", "-q"])

    assert capsys.readouterr().err.splitlines() == [
        "config: ignoring unknown section [export.splnk] (did you mean splunk?)",
        "config: ignoring unknown setting [sigwood].zeek_dri "
        "(did you mean zeek_dir?)",
        "config: ignoring unknown setting [graph].top_hsots "
        "(did you mean top_hosts?)",
        "config: ignoring unknown setting [allowlist].allowlist_dri "
        "(did you mean allowlist_dir?)",
        "config: ignoring unknown setting [export.splunk].usernme "
        "(did you mean username?)",
        "config: ignoring unknown setting [export.splunk.query.nightly].outputbase "
        "(did you mean output_basename?)",
    ]


def test_cli_disclosure_is_not_quiet_gated_and_keeps_success_exit(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    conf = tmp_path / "c.toml"
    conf.write_text(
        "[sigwood]\nzeek_dri = '/nonexistent'\n"
        "[detectors.beacon]\nthresold = 0.4\n",
        encoding="utf-8",
    )

    cli.main(["hunt", f"--config={conf}", "--dry-run", "-q"])

    captured = capsys.readouterr()
    assert captured.err.splitlines() == [
        "config: ignoring unknown setting [sigwood].zeek_dri "
        "(did you mean zeek_dir?)",
        "config: ignoring unknown setting [detectors.beacon].thresold "
        "(did you mean threshold?)",
    ]
    assert "dry run" in captured.out


def test_cli_precomputed_selection_carries_detector_vocabulary(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    conf = tmp_path / "preselected.toml"
    conf.write_text(
        "[detectors.beacon]\nthresold = 0.4\n",
        encoding="utf-8",
    )

    cli.main([
        "hunt",
        f"--config={conf}",
        "--syslog-source=off",
        "--dry-run",
        "-q",
    ])

    assert capsys.readouterr().err.splitlines() == [
        "config: ignoring unknown setting [detectors.beacon].thresold "
        "(did you mean threshold?)",
    ]
