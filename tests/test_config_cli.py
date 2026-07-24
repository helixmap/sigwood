"""Tests for config defaults and CLI user-facing errors."""

from __future__ import annotations

import subprocess
import sys
import textwrap

import pytest
import tomllib
from pathlib import Path

from sigwood import cli
from sigwood.cli import _runner_kwargs
from sigwood.common import config as cfg
from sigwood.detectors import dns, syslog


def test_detector_defaults_are_owned_by_detector_modules(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    config = cfg.load(config_file=None)

    assert config["detectors"] == {}
    assert cfg.get_detector_config(config, "dns", dns.DEFAULT_CONFIG) == dns.DEFAULT_CONFIG


def test_detector_config_overrides_detector_defaults() -> None:
    config = {"detectors": {"dns": {"min_cluster_size": 42}}}

    merged = cfg.get_detector_config(config, "dns", dns.DEFAULT_CONFIG)

    assert merged["min_cluster_size"] == 42
    assert merged["min_samples"] == dns.DEFAULT_CONFIG["min_samples"]


def test_syslog_privileged_roster_overlay_replaces_and_cannot_mutate_default() -> None:
    operator_roster = ["custom-auth"]
    config = {"detectors": {"syslog": {"privileged_programs": operator_roster}}}

    merged = cfg.get_detector_config(config, "syslog", syslog.DEFAULT_CONFIG)

    assert merged["privileged_programs"] == ["custom-auth"]
    assert merged["privileged_programs"] is not operator_roster
    assert merged["privileged_programs"] is not syslog.DEFAULT_CONFIG["privileged_programs"]
    merged["privileged_programs"].append("mutated")
    assert syslog.DEFAULT_CONFIG["privileged_programs"] == list(syslog.PRIVILEGED_PROGRAMS)


def test_cli_formats_missing_config_file_as_actionable_error(
    capsys: pytest.CaptureFixture[str],
    tmp_path,
) -> None:
    missing = tmp_path / "missing.toml"
    with pytest.raises(SystemExit) as exc:
        cli.main(["hunt", f"--config={missing}", "--dry-run"])

    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "sigwood: config file not found" in captured.err
    assert "run: sigwood init" in captured.err
    # config-file-not-found is an operational error, not a usage error - no pointer.
    assert "run 'sigwood --help' for usage" not in captured.err


def test_cli_formats_bad_warn_above_config_as_operational_error(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    bad = tmp_path / "bad.toml"
    bad.write_text('[sigwood]\nwarn_above = "5"\n', encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        cli.main(["hunt", f"--config={bad}", "--dry-run"])

    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert captured.err.startswith("sigwood: [sigwood].warn_above")
    assert "Traceback" not in captured.err
    assert "run 'sigwood --help' for usage" not in captured.err


def test_cli_formats_bad_since_as_usage_error(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    with pytest.raises(SystemExit) as exc:
        cli.main(["hunt", "--since=tomorrow", "--dry-run"])

    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "sigwood: --since expects a date like 2026-05-01" in captured.err
    assert "run 'sigwood --help' for usage" in captured.err


def test_cli_formats_bad_days_as_usage_error(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    with pytest.raises(SystemExit) as exc:
        cli.main(["hunt", "--days=soon", "--dry-run"])

    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "sigwood: --days expects a range like 3-5" in captured.err


def test_cli_formats_unknown_output_as_usage_error(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    (zeek_dir / "conn.log").write_text("", encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        cli.main(["hunt", f"--zeek-dir={zeek_dir}", "--format=bogus"])

    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "sigwood: unknown output format 'bogus'" in captured.err
    assert "available:" in captured.err
    # unknown output format is an operational error now, not a usage error - no pointer.
    assert "run 'sigwood --help' for usage" not in captured.err


def test_runner_kwargs_pihole_dir_arg(tmp_path: Path) -> None:
    """--pihole-dir=PATH (parsed as pihole_dir key) flows through as the raw
    string. The CLI does NOT resolve source-dir strings - that's the
    resolver's job (covered by tests/test_sources.py). _runner_kwargs is
    pure pass-through here."""
    pihole = tmp_path / "pihole"
    pihole.mkdir()
    parsed = {"pihole_dir": str(pihole)}
    kwargs = _runner_kwargs(parsed, config={})
    assert kwargs["pihole_dir"] == str(pihole)


def test_runner_kwargs_cloudtrail_dir_arg(tmp_path: Path) -> None:
    """--cloudtrail-dir=PATH flows through as the raw string."""
    cloudtrail = tmp_path / "ct"
    cloudtrail.mkdir()
    parsed = {"cloudtrail_dir": str(cloudtrail)}
    kwargs = _runner_kwargs(parsed, config={})
    assert kwargs["cloudtrail_dir"] == str(cloudtrail)


def test_runner_kwargs_none_when_flag_absent() -> None:
    """No flag → None override; the resolver decides whether to config-fill.
    That logic lives in resolve_sources (covered by tests/test_sources.py)."""
    kwargs = _runner_kwargs({}, config={"sigwood": {"cloudtrail_dir": "/cfg/ct"}})
    # CLI seam passes None for absent flags regardless of config - the runner
    # routes the override+config into resolve_sources.
    assert kwargs["cloudtrail_dir"] is None
    assert kwargs["zeek_dir"] is None
    assert kwargs["syslog_dir"] is None
    assert kwargs["pihole_dir"] is None


def test_usage_advertises_cloudtrail_dir(capsys) -> None:
    """First-run / --help usage must mention --cloudtrail-dir alongside the other
    source-dir flags."""
    cli._print_usage()
    out = capsys.readouterr().out
    assert "--cloudtrail-dir" in out


# ── Bare source-dir flag (no =value) → actionable CLI error ──────────────────
#
# _parse_args records a bare ``--zeek-dir`` (no =value) as
# parsed["zeek_dir"] = True. ``Path(True)`` downstream must not raise a raw
# TypeError that escapes the CLI error boundary as a traceback, so
# _coerce_source_dir catches the boolean at the seam and raises an actionable
# ``sigwood:`` ValueError with exit 1.

@pytest.mark.parametrize(
    "flag", ["--zeek-dir", "--syslog-dir", "--pihole-dir", "--cloudtrail-dir"],
)
def test_bare_source_dir_flag_in_detect_raises_actionable_error(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    flag: str,
) -> None:
    """Bare ``--<source>-dir`` (no =value) on the detect route produces an
    actionable ``sigwood:`` message and exit 1 - no raw TypeError."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    with pytest.raises(SystemExit) as exc:
        cli.main([flag, "--dry-run"])

    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert f"sigwood: {flag} needs a value: {flag}=…" in captured.err
    assert "run 'sigwood --help' for usage" in captured.err


def test_bare_zeek_dir_flag_in_bare_digest_raises_actionable_error(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bare ``digest --zeek-dir`` (no positional) takes the bare-digest path
    where ``--zeek-dir`` is the only source-dir flag in
    _DIGEST_ALLOWED_LONG_FLAGS. Same actionable shape as the detect route.

    The other three source-dir flags (--pihole-dir, --syslog-dir,
    --cloudtrail-dir) are intentionally NOT in the digest allow-list - they
    raise "unknown digest flag --…" via the existing _validate_digest_flags
    rail and that behaviour is preserved (the digest CLI surface stays
    narrow).
    """
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    with pytest.raises(SystemExit) as exc:
        cli.main(["digest", "--zeek-dir"])

    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "sigwood: --zeek-dir needs a value: --zeek-dir=…" in captured.err


def test_bare_value_flag_with_short_form_mentions_short(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A value-taking flag that has a short form mentions both spellings."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    with pytest.raises(SystemExit) as exc:
        cli.main(["--out"])

    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "sigwood: --out (-o) needs a value: -o=… or --out=…" in captured.err


# The dns routing intent (content-sniff routes Zeek dns → zeek_dir, Pi-hole →
# pihole_dir) lives in tests/test_sources.py:
#   - test_router_dns_pihole_content_under_neutral_name (the key locking
#     content-not-name routing - fixture name does NOT match pihole*.log*)
#   - test_router_dns_zeek_content_routes_to_zeek_dir
# The end-to-end scope rail (sibling source-dirs stay unloaded across the
# CLI ↔ runner seam) is locked by tests/test_source_resolution_seam.py.


def test_config_example_is_valid_toml() -> None:
    path = Path("sigwood/data/config_example.toml")

    with path.open("rb") as fh:
        parsed = tomllib.load(fh)

    # allowlist.d auto-discovers drop-ins by filename convention; the explicit
    # keys default to empty (escape hatch for files outside allowlist.d).
    assert parsed["allowlist"]["domain_patterns"] == []
    assert parsed["allowlist"]["connection_rules"] == []
    assert parsed["allowlist"]["allowlist_dir"] == "allowlist.d/"


# ── Stage 4: default_window + --all ───────────────────────────────────────────

from datetime import timedelta

from sigwood.common.config import parse_window_span


def test_default_window_in_config_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    config = cfg.load(None)
    assert config["sigwood"]["default_window"] == "7d"


def test_invalid_default_window_raises_at_load(tmp_path: Path) -> None:
    cfg_file = tmp_path / "sigwood.toml"
    cfg_file.write_text('[sigwood]\ndefault_window = "1week"\n', encoding="utf-8")
    with pytest.raises(cfg.ConfigError, match="not a valid duration"):
        cfg.load(cfg_file)


def test_zero_default_window_raises_at_load(tmp_path: Path) -> None:
    cfg_file = tmp_path / "sigwood.toml"
    cfg_file.write_text('[sigwood]\ndefault_window = "0d"\n', encoding="utf-8")
    with pytest.raises(cfg.ConfigError):
        cfg.load(cfg_file)


def test_empty_string_default_window_loads_cleanly(tmp_path: Path) -> None:
    cfg_file = tmp_path / "sigwood.toml"
    cfg_file.write_text('[sigwood]\ndefault_window = ""\n', encoding="utf-8")
    config = cfg.load(cfg_file)
    assert config["sigwood"]["default_window"] == ""


def test_all_keyword_default_window_loads_cleanly(tmp_path: Path) -> None:
    cfg_file = tmp_path / "sigwood.toml"
    cfg_file.write_text('[sigwood]\ndefault_window = "all"\n', encoding="utf-8")
    config = cfg.load(cfg_file)
    assert config["sigwood"]["default_window"] == "all"


def test_string_warn_above_raises_at_load(tmp_path: Path) -> None:
    cfg_file = tmp_path / "sigwood.toml"
    cfg_file.write_text('[sigwood]\nwarn_above = "5"\n', encoding="utf-8")
    with pytest.raises(cfg.ConfigError, match=r"\[sigwood\]\.warn_above"):
        cfg.load(cfg_file)


def test_integer_warn_above_loads_cleanly(tmp_path: Path) -> None:
    cfg_file = tmp_path / "sigwood.toml"
    cfg_file.write_text("[sigwood]\nwarn_above = 5\n", encoding="utf-8")
    config = cfg.load(cfg_file)
    assert config["sigwood"]["warn_above"] == 5


def test_zero_warn_above_loads_cleanly(tmp_path: Path) -> None:
    cfg_file = tmp_path / "sigwood.toml"
    cfg_file.write_text("[sigwood]\nwarn_above = 0\n", encoding="utf-8")
    config = cfg.load(cfg_file)
    assert config["sigwood"]["warn_above"] == 0


def test_negative_warn_above_raises_at_load(tmp_path: Path) -> None:
    cfg_file = tmp_path / "sigwood.toml"
    cfg_file.write_text("[sigwood]\nwarn_above = -1\n", encoding="utf-8")
    with pytest.raises(cfg.ConfigError, match=r"\[sigwood\]\.warn_above"):
        cfg.load(cfg_file)


def test_bool_warn_above_raises_at_load(tmp_path: Path) -> None:
    cfg_file = tmp_path / "sigwood.toml"
    cfg_file.write_text("[sigwood]\nwarn_above = true\n", encoding="utf-8")
    with pytest.raises(cfg.ConfigError, match=r"\[sigwood\]\.warn_above"):
        cfg.load(cfg_file)


def test_parse_window_span_days() -> None:
    assert parse_window_span("1d") == timedelta(days=1)
    assert parse_window_span("7d") == timedelta(days=7)


def test_parse_window_span_hours() -> None:
    assert parse_window_span("24h") == timedelta(hours=24)
    assert parse_window_span("12h") == timedelta(hours=12)


def test_parse_window_span_empty_and_all_disable() -> None:
    assert parse_window_span(None) is None
    assert parse_window_span("") is None
    assert parse_window_span("all") is None
    assert parse_window_span("ALL") is None


def test_parse_window_span_invalid_raises() -> None:
    with pytest.raises(cfg.ConfigError):
        parse_window_span("nonsense")
    with pytest.raises(cfg.ConfigError):
        parse_window_span("7days")
    with pytest.raises(cfg.ConfigError):
        parse_window_span("-1d")


def test_runner_kwargs_all_with_since_raises() -> None:
    with pytest.raises(ValueError, match="--all cannot be combined"):
        _runner_kwargs({"all": True, "since": "7d"}, config={})


def test_runner_kwargs_all_with_until_raises() -> None:
    with pytest.raises(ValueError, match="--all cannot be combined"):
        _runner_kwargs({"all": True, "until": "2026-01-01"}, config={})


def test_runner_kwargs_all_with_days_raises() -> None:
    with pytest.raises(ValueError, match="--all cannot be combined"):
        _runner_kwargs({"all": True, "days": "3-5"}, config={})


def test_runner_kwargs_all_with_hours_raises() -> None:
    with pytest.raises(ValueError, match="--all cannot be combined"):
        _runner_kwargs({"all": True, "hours": "2-6"}, config={})


def test_runner_kwargs_all_flag_sets_load_all() -> None:
    kwargs = _runner_kwargs({"all": True}, config={})
    assert kwargs["load_all"] is True


def test_runner_kwargs_no_all_flag_sets_load_all_false() -> None:
    kwargs = _runner_kwargs({}, config={})
    assert kwargs["load_all"] is False


# ── --yes / -y wiring ─────────────────────────────────────────────────────────


def test_parse_args_recognizes_long_yes() -> None:
    """--yes is a bool flag on every verb that allows it (analyze allows it)."""
    result = cli._parse_args(["--yes"], "hunt")
    assert result.get("yes") is True


def test_parse_args_recognizes_short_y() -> None:
    """-y is the canonical short for --yes (allowed on analyze)."""
    result = cli._parse_args(["-y"], "hunt")
    assert result.get("yes") is True


def test_parse_args_rejects_unknown_short_flag() -> None:
    """Unknown short flags RAISE - never silently ignored."""
    with pytest.raises(ValueError, match="unknown flag -x"):
        cli._parse_args(["-x", "PATH"], "hunt")


def test_parse_args_rejects_unknown_long_flag() -> None:
    with pytest.raises(ValueError, match="unknown flag --foo"):
        cli._parse_args(["--foo", "PATH"], "hunt")


def test_parse_args_captures_path_and_paths() -> None:
    """Both ``path`` (first positional) and ``paths`` (full list) populate."""
    result = cli._parse_args(["a.log", "b.log"], "digest")
    assert result["path"] == "a.log"
    assert result["paths"] == ["a.log", "b.log"]


def test_parse_args_wrong_verb_long_form_lead_spelling() -> None:
    """``digest --detect`` reports wrong-verb with the long-form lead."""
    with pytest.raises(ValueError, match=r"--detect \(-d\) is not valid for digest"):
        cli._parse_args(["--detect=all"], "digest")


def test_parse_args_wrong_verb_short_form_lead_spelling() -> None:
    """``digest -d`` reports wrong-verb with the short-form lead."""
    with pytest.raises(ValueError, match=r"-d \(--detect\) is not valid for digest"):
        cli._parse_args(["-d=all"], "digest")


def test_parse_args_wrong_verb_beats_value_shape_for_bare_short() -> None:
    """Validation order: wrong-verb wins over needs-a-value for ``digest -d``."""
    with pytest.raises(ValueError, match=r"-d \(--detect\) is not valid for digest"):
        cli._parse_args(["-d"], "digest")


def test_parse_args_wrong_verb_beats_value_shape_for_bare_long() -> None:
    """Same as above for ``digest --detect``."""
    with pytest.raises(ValueError, match=r"--detect \(-d\) is not valid for digest"):
        cli._parse_args(["--detect"], "digest")


def test_parse_args_value_on_bool_raises_long() -> None:
    with pytest.raises(ValueError, match=r"--verbose \(-v\) takes no value"):
        cli._parse_args(["--verbose=1"], "hunt")


def test_parse_args_value_on_bool_raises_short() -> None:
    with pytest.raises(ValueError, match=r"--verbose \(-v\) takes no value"):
        cli._parse_args(["-v=1"], "hunt")


def test_parse_args_bundling_known_shorts_suggests_separation() -> None:
    with pytest.raises(ValueError, match="short flags can't be combined"):
        cli._parse_args(["-vy"], "hunt")


def test_parse_args_bundling_unknown_short_is_plain_unknown() -> None:
    # `-vz` mixes a known short (-v) with an unknown one (-z) → plain unknown.
    # (Was `-vq` before -q was registered; -q is now a real short, so see
    # test_parse_args_bundling_vq_known_shorts_suggests_separation below.)
    with pytest.raises(ValueError, match="unknown flag -vz"):
        cli._parse_args(["-vz"], "hunt")


def test_parse_args_bundling_vq_known_shorts_suggests_separation() -> None:
    """Registering -q flips `-vq` from the unknown-flag path to the
    bundling-refusal path (both -v and -q are now known shorts)."""
    with pytest.raises(ValueError, match="short flags can't be combined"):
        cli._parse_args(["-vq"], "hunt")


def test_parse_args_help_eq_value_is_takes_no_value() -> None:
    """``--help=foo`` is NOT a help short-circuit - strict parser rejects it."""
    with pytest.raises(ValueError, match=r"--help \(-h\) takes no value"):
        cli._parse_args(["--help=foo"], "hunt")


def test_parse_args_duplicate_flag_last_wins() -> None:
    """A repeated value flag stays single-valued; last write wins."""
    result = cli._parse_args(["--out=a", "--out=b"], "hunt")
    assert result["out"] == "b"


# ── -vv literal token + verbose-level resolution ─────────────────────────────


def test_parse_args_short_v_sets_verbose_true() -> None:
    result = cli._parse_args(["-v"], "hunt")
    assert result.get("verbose") is True
    assert "verbose_level" not in result


def test_parse_args_long_verbose_sets_verbose_true() -> None:
    result = cli._parse_args(["--verbose"], "hunt")
    assert result.get("verbose") is True


def test_parse_args_literal_vv_sets_verbose_level_two() -> None:
    """`-vv` is recognized as an explicit literal token BEFORE the bundling
    refusal fires (regression: it must not hit the `pass separately` error)."""
    result = cli._parse_args(["-vv"], "hunt")
    assert result.get("verbose_level") == 2


def test_parse_args_combined_v_and_vv_resolves_to_level_two() -> None:
    """Last-wins duplication: `-v -vv` resolves to 2 via _resolve_verbose_level."""
    parsed = cli._parse_args(["-v", "-vv"], "hunt")
    assert cli._resolve_verbose_level(parsed) == 2


def test_parse_args_vvv_still_rejected_as_bundling() -> None:
    """`-vvv` is not a registered literal - falls through to the bundling
    refusal lattice with the existing pass-separately message."""
    with pytest.raises(ValueError, match="short flags can't be combined"):
        cli._parse_args(["-vvv"], "hunt")


def test_parse_args_vy_still_rejected_as_bundling() -> None:
    """`-vy` is not the literal `-vv` and still hits bundling refusal."""
    with pytest.raises(ValueError, match="short flags can't be combined"):
        cli._parse_args(["-vy"], "hunt")


def test_parse_args_vv_wrong_verb_matches_v_error_shape() -> None:
    """`init` disallows verbose; `-vv` raises the SAME wrong-verb error shape
    as `-v` would. Validation order: identity → verb-membership → value-shape."""
    with pytest.raises(ValueError, match=r"-v \(--verbose\) is not valid for init"):
        cli._parse_args(["-vv"], "init")
    # And the parity check on -v:
    with pytest.raises(ValueError, match=r"-v \(--verbose\) is not valid for init"):
        cli._parse_args(["-v"], "init")


def test_resolve_verbose_level_collapses_states() -> None:
    """none → 0; -v → 1; -vv → 2; combined → 2."""
    assert cli._resolve_verbose_level({}) == 0
    assert cli._resolve_verbose_level({"verbose": True}) == 1
    assert cli._resolve_verbose_level({"verbose_level": 2}) == 2
    assert cli._resolve_verbose_level({"verbose": True, "verbose_level": 2}) == 2


def test_runner_kwargs_yes_flag_sets_skip_confirm() -> None:
    kwargs = _runner_kwargs({"yes": True}, config={})
    assert kwargs.get("skip_confirm") is True


def test_runner_kwargs_no_yes_flag_skip_confirm_false() -> None:
    kwargs = _runner_kwargs({}, config={})
    assert kwargs.get("skip_confirm") is False


def test_usage_includes_yes_flag(capsys) -> None:
    """--help / first-run usage must advertise --yes and -y."""
    cli._print_usage()
    out = capsys.readouterr().out
    assert "--yes" in out
    assert "-y" in out


def test_yes_threads_to_run_export(monkeypatch, tmp_path: Path) -> None:
    """`sigwood export <backend> --yes` must reach run_export with skip_confirm=True."""
    captured: dict = {}

    def _fake_run_export(*args, **kwargs):
        captured.update(kwargs)

    # _run_export does `from sigwood.exporters import run_export` inside the
    # function - re-binding the attribute on the package is what it picks up.
    monkeypatch.setattr("sigwood.exporters.run_export", _fake_run_export)
    monkeypatch.setattr(
        cfg, "load", lambda _=None: {
            "export": {"splunk": {"host": "192.0.2.20", "port": 8089,
                                  "query": {"default": {"spl": "x"}}}},
        },
    )
    cli.main(["export", "splunk", "--yes"])
    assert captured.get("skip_confirm") is True


def test_yes_threads_to_runner_run(monkeypatch, tmp_path: Path) -> None:
    """A detector invocation with --yes must reach runner.run with skip_confirm=True."""
    captured: dict = {}

    def _fake_run(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr("sigwood.runner.run", _fake_run)
    # Use a single-detector subcommand path that already takes a zeek_dir.
    cli.main(["beacon", f"--zeek-dir={tmp_path}", "--yes"])
    assert captured.get("skip_confirm") is True


# ── CLI flag rename: --output-dir → --out (user-facing contract) ─────────────


def test_usage_advertises_out_not_output_dir(capsys) -> None:
    """Usage text mentions --out (the new flag) and not --output-dir (the dropped name).

    We deliberately do NOT test runtime rejection of --output-dir - the generic
    --flag=value parser would still produce an inert `output_dir` key, which is
    harmless dead state. The user-facing contract is the help text.
    """
    cli._print_usage()
    out = capsys.readouterr().out
    assert "--out" in out
    assert "--output-dir" not in out


# ── CLI polish for the aws detector ───────────────────────────────────────────

# aws subcommand + usage

def test_aws_is_a_single_detector_command() -> None:
    """sigwood aws PATH must be recognized as a single-detector subcommand."""
    assert "aws" in cli._SINGLE_DETECTOR_COMMANDS


def test_usage_lists_aws_subcommand(capsys) -> None:
    cli._print_usage()
    out = capsys.readouterr().out
    assert "sigwood aws " in out


def test_usage_lists_duration_subcommand(capsys) -> None:
    """Regression: catch any future stale-usage drift on duration."""
    cli._print_usage()
    out = capsys.readouterr().out
    assert "sigwood duration " in out


# positional PATH → cloudtrail_dir in single-detector mode

def test_aws_positional_path_routes_to_cloudtrail_dir(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """sigwood aws PATH routes the positional to cloudtrail_dir, not zeek_dir,
    and the positional scopes the run so siblings stay None."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    captured: dict[str, object] = {}

    def fake_run(**kwargs: object) -> None:
        captured.update(kwargs)

    monkeypatch.setattr("sigwood.runner.run", fake_run)
    ct_file = tmp_path / "cloudtrail_2026.json.log"
    ct_file.write_text("", encoding="utf-8")

    cli._run_single_detector("aws", [str(ct_file)])

    assert captured["detect"] == "aws"
    # CLI now passes raw strings; the resolver owns Path conversion.
    assert captured["cloudtrail_dir"] == str(ct_file)
    assert captured["zeek_dir"] is None
    assert captured["syslog_dir"] is None
    assert captured["pihole_dir"] is None
    # scope rail: positional scopes the run to its routed source.
    assert captured["scope"] == frozenset({"cloudtrail_dir"})


# ~-expansion of explicit overrides happens inside common.sources._resolve_one
# (the sole site for string→Path conversion), tested directly at
# tests/test_sources.py:test_resolve_sources_tilde_override_expands.
#
# The end-to-end `aws ~/path` CLI test is preserved as a seam-style
# dry-run test in tests/test_source_resolution_seam.py (stage 5).


def test_runner_kwargs_out_tilde_expands_and_preserves_trailing_slash(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """--out=~/reports/ must expand ~ AND preserve the trailing slash that
    be_like_water needs to fire the directory-intent gate."""
    monkeypatch.setenv("HOME", str(tmp_path))

    captured: dict[str, str] = {}

    def fake_be_like_water(target: str):
        captured["target"] = target
        from types import SimpleNamespace
        return SimpleNamespace(is_file=False, path=Path(target))

    monkeypatch.setattr("sigwood.cli.be_like_water", fake_be_like_water)

    _runner_kwargs({"out": "~/reports/"}, config={})

    assert captured["target"] == f"{tmp_path}/reports/"
    assert captured["target"].endswith("/")
    assert "~" not in captured["target"]


# The end-to-end ``aws ~/path`` CLI test (~-positional routes to
# cloudtrail_dir AND expands ~) moved to tests/test_source_resolution_seam.py
# as a real CLI dry-run seam test. ~-expansion now happens inside
# common.sources._resolve_one, not at the CLI seam.


# Analyze positional → named-detector-source routing.
#
# `route_positional_source` does the right thing on its own. The router
# itself is unit-tested in
# tests/test_sources.py - this test pins the CLI seam wiring: the positional
# lands on the detector's REQUIRED_LOGS source and the scope rail keeps
# siblings unloaded.

def test_analyze_positional_reroutes_to_named_detector_source(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """``sigwood --detect=aws PATH`` routes the positional to cloudtrail_dir
    (the detector's REQUIRED_LOGS source) and the scope rail keeps siblings
    None - even with a config that sets zeek_dir."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    captured: dict[str, object] = {}
    monkeypatch.setattr("sigwood.runner.run", lambda **kw: captured.update(kw))
    monkeypatch.setattr(cfg, "load", lambda _=None: {
        "sigwood": {"zeek_dir": str(tmp_path / "should-not-be-loaded")},
    })

    fake_path = tmp_path / "events.json.log"
    fake_path.write_text("", encoding="utf-8")
    cli._run_hunt([f"--detect=aws", str(fake_path)])

    assert captured["cloudtrail_dir"] == str(fake_path)
    assert captured["zeek_dir"] is None
    assert captured["scope"] == frozenset({"cloudtrail_dir"})


# ── top-level KeyboardInterrupt handler ──────────────────────────────────────
#
# Two Ctrl-C moments coexist:
#   1. mid-run (load, detect, digest, export compute) → cli.main()'s new arm
#      prints "Stopped." to stderr and exits 130.
#   2. at the records-found "Continue? [y/N]" prompt in runner.py → the
#      existing (EOFError, KeyboardInterrupt) handler raises ExportAborted,
#      which cli.main() catches and exits 0 with the "aborted by user"
#      message on stdout. Locking both halves prevents a future refactor
#      from collapsing them.


def _write_tiny_zeek_dir(tmp_path: Path) -> Path:
    """Write a two-row flat Zeek conn.log just rich enough to load.

    Kept local to this module so test_config_cli stays independent of
    test_runner's fixture helpers.
    """
    import json
    from datetime import datetime, timezone

    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    rows = [
        {
            "ts": datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp(),
            "id.orig_h": "192.0.2.10",
            "id.resp_h": "198.51.100.20",
            "id.resp_p": 443,
            "proto": "tcp",
        },
        {
            "ts": datetime(2026, 1, 5, tzinfo=timezone.utc).timestamp(),
            "id.orig_h": "192.0.2.10",
            "id.resp_h": "198.51.100.20",
            "id.resp_p": 443,
            "proto": "tcp",
        },
    ]
    (zeek_dir / "conn.log").write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8"
    )
    return zeek_dir


def test_cli_top_level_keyboard_interrupt_exits_cleanly(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Ctrl-C during compute work → 'Stopped.' on stderr, exit 130, no traceback.

    Non-TTY stderr (capsys's captured stream) - byte-exact "Stopped.\\n", no
    leading blank line. Script/log capture must see the same string today and
    after the TTY-only blank-line polish.
    """
    def _raise_kbd(_argv=None):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "_main", _raise_kbd)

    with pytest.raises(SystemExit) as exc_info:
        cli.main([])

    assert exc_info.value.code == 130
    captured = capsys.readouterr()
    assert captured.err == "Stopped.\n"
    assert "Traceback" not in captured.err
    assert "Traceback" not in captured.out
    # Sanity: this is the new path, not the prompt-cancel path.
    assert "aborted by user" not in captured.err
    assert "aborted by user" not in captured.out


def test_cli_top_level_keyboard_interrupt_prepends_blank_line_on_tty(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Ctrl-C on a TTY → leading blank line so terminal '^C' echo does not
    glue to 'Stopped.' on one row. The cli is the only place that sees this
    discipline; runner liveness narration handles its own clears."""
    def _raise_kbd(_argv=None):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "_main", _raise_kbd)
    # capsys swaps sys.stderr; force its isatty() to True for this run.
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)

    with pytest.raises(SystemExit) as exc_info:
        cli.main([])

    assert exc_info.value.code == 130
    captured = capsys.readouterr()
    assert captured.err == "\nStopped.\n"


def test_cli_top_level_eof_prints_backstop_exit_1(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Closed stdin reaching the boundary → one actionable line, exit 1.

    A SEPARATE arm from KeyboardInterrupt: EOF is not a signal, so the
    128+SIGINT exit 130 would be wrong. This is the backstop for any prompt
    without a local EOF guard - never a raw traceback at the boundary."""
    def _raise_eof(_argv=None):
        raise EOFError

    monkeypatch.setattr(cli, "_main", _raise_eof)

    with pytest.raises(SystemExit) as exc_info:
        cli.main([])

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert captured.err == "sigwood: unexpected end of input\n"
    assert "Stopped." not in captured.err


def test_cli_keyboard_interrupt_at_confirm_prompt_still_exit_zero(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Ctrl-C AT the records-found prompt → ExportAborted → exit 0, NOT Stopped./130.

    Drives cli.main() end-to-end to lock the user-visible CLI behavior:
    --warn-above is not threaded by _runner_kwargs, so we inject it via
    cfg.load() the same way test_cloudtrail_exporter.py:794 does.
    """
    zeek_dir = _write_tiny_zeek_dir(tmp_path)

    def _fake_load(_path=None):
        return {
            "sigwood": {
                "detect": "beacon",
                "warn_above": 1,
                "default_window": "all",
            }
        }

    monkeypatch.setattr(cfg, "load", _fake_load)

    def _kbd(*_a, **_kw):
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", _kbd)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["beacon", f"--zeek-dir={zeek_dir}"])

    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    # ExportAborted prints to stdout via cli.main()'s existing arm.
    assert "aborted by user" in captured.out
    # The new top-level path must NOT have fired here.
    assert "Stopped." not in captured.err
    assert "Stopped." not in captured.out


# ── Single-detector positional routing: syslog ───────────────────────────────
#
# syslog's REQUIRED_LOGS is empty (dns shape), so a positional routes through
# OPTIONAL_LOGS matching, where `syslog.log` matches BOTH `*.log*` and
# `syslog*.log*`. Flat syslog MUST reach syslog_dir, not the zeek_dir default:
# a directory positional routes to syslog_dir (the /var/log convention), a
# file content-sniffs (Zeek-origin → zeek_dir, anything else → syslog_dir).

def test_syslog_positional_flat_file_routes_to_syslog_dir(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A flat RFC 3164 syslog file routes to syslog_dir via content-sniff."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    captured: dict[str, object] = {}

    def fake_run(**kwargs: object) -> None:
        captured.update(kwargs)

    monkeypatch.setattr("sigwood.runner.run", fake_run)
    flat_file = tmp_path / "auth.log"
    flat_file.write_text(
        "<134>Jun 11 12:00:00 host1 sshd[1234]: Accepted publickey for user\n",
        encoding="utf-8",
    )

    cli._run_single_detector("syslog", [str(flat_file)])

    assert captured["detect"] == "syslog"
    assert captured["syslog_dir"] == str(flat_file)
    # Scope rail: positional routes ONE source; siblings stay None.
    assert captured["zeek_dir"] is None
    assert captured["scope"] == frozenset({"syslog_dir"})


def test_syslog_positional_directory_routes_to_syslog_dir(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A directory positional preserves the /var/log flat-syslog convention.

    A directory positional MUST route to syslog_dir, not the zeek_dir
    default - the /var/log flat-syslog convention.
    """
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    captured: dict[str, object] = {}

    def fake_run(**kwargs: object) -> None:
        captured.update(kwargs)

    monkeypatch.setattr("sigwood.runner.run", fake_run)
    log_dir = tmp_path / "log"
    log_dir.mkdir()
    (log_dir / "auth.log").write_text(
        "<134>Jun 11 12:00:00 host1 sshd[1234]: ok\n",
        encoding="utf-8",
    )

    cli._run_single_detector("syslog", [str(log_dir)])

    assert captured["syslog_dir"] == str(log_dir)
    assert captured["zeek_dir"] is None
    assert captured["scope"] == frozenset({"syslog_dir"})


def test_syslog_positional_zeek_tsv_file_routes_to_zeek_dir(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A Zeek-TSV syslog.log positional content-sniffs to zeek_dir.

    Filename `syslog.log` matches BOTH OPTIONAL_LOGS patterns - disambiguation
    happens via content sniff (sniff_format_detailed), the same machinery the
    digest verb uses. Zeek-origin → zeek_dir.
    """
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    captured: dict[str, object] = {}

    def fake_run(**kwargs: object) -> None:
        captured.update(kwargs)

    monkeypatch.setattr("sigwood.runner.run", fake_run)
    zeek_file = tmp_path / "syslog.log"
    zeek_file.write_text(
        "#separator \\x09\n"
        "#set_separator\t,\n"
        "#empty_field\t(empty)\n"
        "#unset_field\t-\n"
        "#path\tsyslog\n"
        "#fields\tts\tuid\tid.orig_h\tmessage\n"
        "#types\ttime\tstring\taddr\tstring\n"
        "1779750000.000000\tCSL01\t192.0.2.10\thello\n",
        encoding="utf-8",
    )

    cli._run_single_detector("syslog", [str(zeek_file)])

    assert captured["zeek_dir"] == str(zeek_file)
    assert captured["syslog_dir"] is None
    assert captured["scope"] == frozenset({"zeek_dir"})


def test_syslog_positional_zeek_ndjson_file_routes_to_zeek_dir(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The NDJSON Zeek front-end also content-sniffs to zeek_dir."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    captured: dict[str, object] = {}

    def fake_run(**kwargs: object) -> None:
        captured.update(kwargs)

    monkeypatch.setattr("sigwood.runner.run", fake_run)
    zeek_file = tmp_path / "syslog.log"
    zeek_file.write_text(
        '{"_path":"syslog","ts":1779750000.0,"uid":"CSL01",'
        '"id.orig_h":"192.0.2.10","id.resp_h":"198.51.100.20",'
        '"id.resp_p":514,"proto":"udp","facility":"DAEMON","severity":"INFO",'
        '"message":"Jun 11 12:00:00 host1 sshd[1234]: ok"}\n',
        encoding="utf-8",
    )

    cli._run_single_detector("syslog", [str(zeek_file)])

    assert captured["zeek_dir"] == str(zeek_file)
    assert captured["syslog_dir"] is None
    assert captured["scope"] == frozenset({"zeek_dir"})


def test_syslog_positional_unrecognized_file_routes_to_syslog_dir(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A file the sniffer cannot identify as a Zeek syslog.log falls to the
    flat-syslog default (syslog_dir). Mirrors the "directory defaults to
    flat" convention."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    captured: dict[str, object] = {}

    def fake_run(**kwargs: object) -> None:
        captured.update(kwargs)

    monkeypatch.setattr("sigwood.runner.run", fake_run)
    mystery = tmp_path / "mystery.log"
    mystery.write_text("lorem ipsum dolor\nsit amet\n", encoding="utf-8")

    cli._run_single_detector("syslog", [str(mystery)])

    assert captured["syslog_dir"] == str(mystery)
    assert captured["zeek_dir"] is None
    assert captured["scope"] == frozenset({"syslog_dir"})


def test_syslog_positional_missing_file_fails_fast(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """An explicit positional that doesn't exist FAILS FAST with a clean
    ``ValueError("<path>: not found")`` before sniff-routing - no raw OSError
    traceback, and the runner (with its source-discovery cascade) is never
    reached."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])

    def fake_run(**kwargs: object) -> None:
        raise AssertionError("runner.run must not be reached on a missing positional")

    monkeypatch.setattr("sigwood.runner.run", fake_run)
    ghost = tmp_path / "does-not-exist.log"

    with pytest.raises(ValueError, match="not found"):
        cli._run_single_detector("syslog", [str(ghost)])


def test_syslog_positional_zeek_ndjson_without_path_routes_to_zeek_dir(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A Zeek-NDJSON syslog.log emitted without the `_path` directive must
    still content-sniff to Zeek and route to zeek_dir. The conn field-set
    fallback must not grab it and land the positional at syslog_dir, which
    would leave load_syslog with an empty frame."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    captured: dict[str, object] = {}

    def fake_run(**kwargs: object) -> None:
        captured.update(kwargs)

    monkeypatch.setattr("sigwood.runner.run", fake_run)
    zeek_file = tmp_path / "syslog.log"
    zeek_file.write_text(
        # Note: NO _path directive - exactly the upstream-agent shape that
        # triggered the original misroute.
        '{"ts":1779750000.0,"uid":"CSL01",'
        '"id.orig_h":"192.0.2.10","id.orig_p":41514,'
        '"id.resp_h":"198.51.100.20","id.resp_p":514,'
        '"proto":"udp","facility":"DAEMON","severity":"INFO",'
        '"message":"Jun 11 12:00:00 host1 sshd[1234]: placeholder"}\n',
        encoding="utf-8",
    )

    cli._run_single_detector("syslog", [str(zeek_file)])

    assert captured["zeek_dir"] == str(zeek_file)
    assert captured["syslog_dir"] is None
    assert captured["scope"] == frozenset({"zeek_dir"})


# ─── -q / --quiet membership + resolution ────────────────────────────────────


@pytest.mark.parametrize(
    "verb", ["hunt", "beacon", "dns", "syslog", "scan", "duration", "aws", "digest"]
)
def test_parse_args_quiet_accepted_on_analyze_detectors_and_digest(verb: str) -> None:
    """-q/--quiet is in the allowed set for analyze, the six single-detector
    verbs, and digest."""
    assert cli._parse_args(["-q"], verb).get("quiet") is True
    assert cli._parse_args(["--quiet"], verb).get("quiet") is True


@pytest.mark.parametrize("verb", ["export", "init", "allowlist"])
def test_parse_args_quiet_rejected_on_export_init_allowlist(verb: str) -> None:
    """-q/--quiet is NOT in export/init/allowlist allowed sets → wrong-verb."""
    with pytest.raises(ValueError, match="is not valid for"):
        cli._parse_args(["-q"], verb)
    with pytest.raises(ValueError, match="is not valid for"):
        cli._parse_args(["--quiet"], verb)


def test_runner_kwargs_quiet_from_config_when_flag_absent() -> None:
    """[sigwood].quiet = true with no -q → run() receives quiet=True."""
    kwargs = _runner_kwargs({}, {"sigwood": {"quiet": True}})
    assert kwargs["quiet"] is True


def test_runner_kwargs_quiet_cli_overrides_config_false() -> None:
    """CLI -q wins over a config quiet=false (there is no un-quiet flag)."""
    kwargs = _runner_kwargs({"quiet": True}, {"sigwood": {"quiet": False}})
    assert kwargs["quiet"] is True


def test_runner_kwargs_quiet_defaults_false() -> None:
    """No -q, no config quiet → quiet=False."""
    kwargs = _runner_kwargs({}, {"sigwood": {}})
    assert kwargs["quiet"] is False


# ── --utc / use_utc: timeframe input follows the knob ─────────────────────────

from datetime import datetime, timezone  # noqa: E402


def test_naive_since_follows_the_knob(pin_tz) -> None:
    """A naive --since date reads as display-tz wall-clock: local midnight
    (06:00Z under Etc/GMT+6 - manual arithmetic) with the knob off, UTC
    midnight with it on. Both returns carry timezone.utc."""
    pin_tz("Etc/GMT+6")
    since, until = cli._resolve_timeframe({"since": "2026-05-01"}, use_utc=False)
    assert since == datetime(2026, 5, 1, 6, 0, tzinfo=timezone.utc)
    assert since.tzinfo == timezone.utc
    assert until is None

    since, _ = cli._resolve_timeframe({"since": "2026-05-01"}, use_utc=True)
    assert since == datetime(2026, 5, 1, 0, 0, tzinfo=timezone.utc)
    assert since.tzinfo == timezone.utc


def test_explicit_offset_honored_under_both_knob_states() -> None:
    """An explicit UTC offset in the value is honored - never rewritten -
    regardless of the knob. Guards the offset-clobber failure mode (a +02:00
    value silently re-stamped as UTC skewed the window by the offset)."""
    expected = datetime(2026, 5, 1, 7, 0, tzinfo=timezone.utc)
    for use_utc in (False, True):
        since, _ = cli._resolve_timeframe(
            {"since": "2026-05-01T09:00+02:00"}, use_utc=use_utc
        )
        assert since == expected
        assert since.tzinfo == timezone.utc


def test_days_snap_follows_the_knob_and_is_representation_independent(pin_tz) -> None:
    """--days midnights snap in the display timezone (local off / UTC on), and
    the result is independent of the representation the caller's ``now``
    arrived in - the same instant as a UTC-aware vs local-aware datetime
    yields identical returns. Expected instants by manual -6h arithmetic."""
    pin_tz("Etc/GMT+6")
    # One fixed instant: 2026-06-18 15:00Z == 2026-06-18 09:00 local (UTC-6).
    now_utc = datetime(2026, 6, 18, 15, 0, tzinfo=timezone.utc)
    now_local = now_utc.astimezone()

    # Knob off → local midnights: 2026-06-17 00:00-06:00 == 06:00Z.
    since, until = cli._resolve_timeframe({"days": "1-1"}, now=now_utc, use_utc=False)
    assert since == datetime(2026, 6, 17, 6, 0, tzinfo=timezone.utc)
    assert until == datetime(2026, 6, 18, 5, 59, 59, tzinfo=timezone.utc)
    assert (since, until) == cli._resolve_timeframe(
        {"days": "1-1"}, now=now_local, use_utc=False
    )

    # Knob on → UTC midnights.
    since, until = cli._resolve_timeframe({"days": "1-1"}, now=now_utc, use_utc=True)
    assert since == datetime(2026, 6, 17, 0, 0, tzinfo=timezone.utc)
    assert until == datetime(2026, 6, 17, 23, 59, 59, tzinfo=timezone.utc)
    assert (since, until) == cli._resolve_timeframe(
        {"days": "1-1"}, now=now_local, use_utc=True
    )


def test_runner_kwargs_use_utc_or_shape() -> None:
    """use_utc = CLI --utc OR [sigwood].use_utc - the flag wins per run,
    config supplies the standing default, there is no un-flag."""
    assert _runner_kwargs({}, config={})["use_utc"] is False
    assert _runner_kwargs({"utc": True}, config={})["use_utc"] is True
    assert (
        _runner_kwargs({}, config={"sigwood": {"use_utc": True}})["use_utc"]
        is True
    )
    assert (
        _runner_kwargs({"utc": True}, config={"sigwood": {"use_utc": False}})[
            "use_utc"
        ]
        is True
    )


def test_parse_args_utc_wrong_verb_for_init_and_allowlist() -> None:
    """--utc is not part of init's or allowlist's surface - the standard
    known-but-wrong-verb error protects the public flag surface."""
    with pytest.raises(ValueError, match=r"--utc is not valid for init"):
        cli._parse_args(["--utc"], "init")
    with pytest.raises(ValueError, match=r"--utc is not valid for allowlist"):
        cli._parse_args(["--utc"], "allowlist")


# ── detect-spec validation at the CLI seam ────────────────────────────────────
#
# Real cli.main → runner.run, never a mocked seam. Every run passes an isolated
# --config (empty tmp source dirs) so nothing on the developer's box is read.

_DETECT_AVAILABLE = "available: aws, beacon, dns, duration, scan, syslog"


def _write_probe_config(tmp_path: Path, *, detect: str | None = None) -> Path:
    """Minimal isolated config: tmp root, empty source dirs, optional detect."""
    (tmp_path / "zeek_empty").mkdir(exist_ok=True)
    (tmp_path / "syslog_empty").mkdir(exist_ok=True)
    lines = [
        "[sigwood]",
        f'root = "{tmp_path / "root"}"',
        f'zeek_dir = "{tmp_path / "zeek_empty"}"',
        f'syslog_dir = "{tmp_path / "syslog_empty"}"',
        'syslog_source = "files"',
    ]
    if detect is not None:
        lines.append(f'detect = "{detect}"')
    probe = tmp_path / "probe.toml"
    probe.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return probe


def test_unknown_detect_flag_exits_1_without_usage_pointer(
    capsys: pytest.CaptureFixture[str], tmp_path: Path,
) -> None:
    probe = _write_probe_config(tmp_path)
    with pytest.raises(SystemExit) as exc:
        cli.main(["hunt", "--detect=beacn", f"--config={probe}"])

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert f"sigwood: unknown detector 'beacn' - {_DETECT_AVAILABLE}" in err
    # Operational error (spec can come from config) - no usage pointer.
    assert "run 'sigwood --help' for usage" not in err


def test_unknown_detect_config_key_same_raise(
    capsys: pytest.CaptureFixture[str], tmp_path: Path,
) -> None:
    """The runner is the single validation owner, so a config-sourced spec hits
    the same raise as the CLI flag."""
    probe = _write_probe_config(tmp_path, detect="beacn")
    with pytest.raises(SystemExit) as exc:
        cli.main(["hunt", f"--config={probe}"])

    assert exc.value.code == 1
    assert f"sigwood: unknown detector 'beacn' - {_DETECT_AVAILABLE}" in (
        capsys.readouterr().err
    )


def test_unknown_detect_dry_run_raises_no_banner(
    capsys: pytest.CaptureFixture[str], tmp_path: Path,
) -> None:
    """A dry run that validates the spec is a feature: it raises on the typo
    instead of printing a wrong zero-detector banner."""
    probe = _write_probe_config(tmp_path)
    with pytest.raises(SystemExit) as exc:
        cli.main(["hunt", "--detect=beacn", "--dry-run", f"--config={probe}"])

    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "dry run" not in captured.out
    assert f"unknown detector 'beacn' - {_DETECT_AVAILABLE}" in captured.err


def test_exclude_everything_live_selected_none_exit_0(
    capsys: pytest.CaptureFixture[str], tmp_path: Path,
) -> None:
    """A legally-empty selection is a disclosed no-op, not an error - and not
    the misleading log-paths message."""
    probe = _write_probe_config(tmp_path)
    cli.main([
        "hunt",
        "--detect=all,!aws,!beacon,!dns,!duration,!scan,!syslog",
        f"--config={probe}",
    ])

    err = capsys.readouterr().err
    assert "no detectors to run - the detect spec selected none" in err
    assert "no detectors could run" not in err


def test_exclude_everything_dry_run_banner_selected_none(
    capsys: pytest.CaptureFixture[str], tmp_path: Path,
) -> None:
    probe = _write_probe_config(tmp_path)
    cli.main([
        "hunt",
        "--detect=all,!aws,!beacon,!dns,!duration,!scan,!syslog",
        "--dry-run",
        f"--config={probe}",
    ])

    out = capsys.readouterr().out
    assert "(none - detect spec selected none)" in out
    assert "skipped:" not in out


def test_detect_empty_string_is_absent_falls_back_to_default(
    capsys: pytest.CaptureFixture[str], tmp_path: Path,
) -> None:
    """Compatibility pin: `--detect=` (EMPTY string) means absent - the
    two-step fallback lands on the curated default. With every source dir
    empty that is the all-skipped arm, WITH skipped: lines, but the opt-in
    duration detector is not selected."""
    probe = _write_probe_config(tmp_path)
    cli.main(["hunt", "--detect=", "--dry-run", f"--config={probe}"])

    out = capsys.readouterr().out
    assert "(none - required logs unavailable)" in out
    assert "skipped:" in out
    skipped_lines = [line for line in out.splitlines() if line.startswith("skipped:")]
    assert all("duration" not in line for line in skipped_lines)
    assert "opt-in:          duration" in out


def test_explicit_all_config_matches_explicit_all_cli(
    capsys: pytest.CaptureFixture[str], tmp_path: Path,
) -> None:
    """Existing detect=all configs retain the explicit-all dry-run exactly."""
    probe = _write_probe_config(tmp_path, detect="all")

    cli.main(["hunt", "--dry-run", f"--config={probe}"])
    from_config = capsys.readouterr()
    cli.main(["hunt", "--detect=all", "--dry-run", f"--config={probe}"])
    from_flag = capsys.readouterr()

    assert from_config == from_flag
    assert "duration" in from_config.out
    assert "opt-in:" not in from_config.out


def test_explicit_default_flag_discloses_opt_in_remainder(
    capsys: pytest.CaptureFixture[str], tmp_path: Path,
) -> None:
    probe = _write_probe_config(tmp_path, detect="all")

    cli.main([
        "hunt", "--detect=default", "--dry-run", f"--config={probe}",
    ])

    out = capsys.readouterr().out
    assert "opt-in:          duration" in out
    skipped_lines = [line for line in out.splitlines() if line.startswith("skipped:")]
    assert all("duration" not in line for line in skipped_lines)


def test_detect_whitespace_only_selects_none(
    capsys: pytest.CaptureFixture[str], tmp_path: Path,
) -> None:
    """Compatibility pin: a WHITESPACE-ONLY spec is non-empty, so it reaches
    resolve_detect, tokenises to nothing, and selects NONE - disclosed, never
    a raise, never a silent fall-through to `all`. Pinned for both spec
    sources (flag and config)."""
    probe = _write_probe_config(tmp_path)
    cli.main(["hunt", "--detect= ", "--dry-run", f"--config={probe}"])

    out = capsys.readouterr().out
    assert "(none - detect spec selected none)" in out
    assert "skipped:" not in out

    probe_cfg = _write_probe_config(tmp_path, detect=" ")
    cli.main(["hunt", f"--config={probe_cfg}"])

    err = capsys.readouterr().err
    assert "no detectors to run - the detect spec selected none" in err


def test_all_skipped_keeps_paths_message_lowercased(
    capsys: pytest.CaptureFixture[str], tmp_path: Path,
) -> None:
    """Detectors selected but sources missing stays the log-paths message
    (voice-aligned: lowercase lead, no terminal period)."""
    probe = _write_probe_config(tmp_path)
    with pytest.raises(SystemExit) as exc:
        cli.main(["hunt", "--detect=beacon", f"--config={probe}"])

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert (
        "no detectors could run - check required log source paths in config "
        "or CLI overrides" in err
    )
    assert "selected none" not in err


def test_all_permission_denied_hunt_exits_1_before_none_banner(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """All-discovered permission-denied data exits 1, not clean `none`."""
    import sigwood.common.loader as loader_mod

    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    (pihole_dir / "pihole.log").write_text("unreadable placeholder\n", encoding="utf-8")
    probe = _write_probe_config(tmp_path)

    def _deny(_path: Path):
        raise PermissionError("synthetic denied")

    monkeypatch.setattr(loader_mod, "_open_log", _deny)

    with pytest.raises(SystemExit) as exc:
        cli.main([
            "dns",
            f"--pihole-dir={pihole_dir}",
            "--all",
            f"--config={probe}",
        ])

    captured = capsys.readouterr()
    assert exc.value.code == 1
    assert "pihole.log: permission denied" in captured.err
    assert (
        "sigwood: Pi-hole: all 1 discovered file permission denied - "
        "grant your user read access and retry"
    ) in captured.err
    assert "[Errno" not in captured.err
    assert "PermissionError" not in captured.err
    assert "could not be read - could not be read" not in captured.err
    assert "data found:" not in captured.out


def test_unqualified_pihole_permission_denied_default_window_exits_1(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Default-window floor peek defers permission errors to load handling."""
    import sigwood.common.loader as loader_mod

    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    (pihole_dir / "pihole.log").write_text(
        "Jun  5 12:00:00 dnsmasq[1]: query[A] blocked.test from 192.0.2.10\n",
        encoding="utf-8",
    )
    probe = _write_probe_config(tmp_path)

    def _deny(_path: Path):
        raise PermissionError("synthetic denied")

    monkeypatch.setattr(loader_mod, "_open_log", _deny)

    with pytest.raises(SystemExit) as exc:
        cli.main([str(pihole_dir), f"--config={probe}"])

    captured = capsys.readouterr()
    assert exc.value.code == 1
    assert "pihole.log: permission denied" in captured.err
    assert (
        "sigwood: Pi-hole: all 1 discovered file permission denied - "
        "grant your user read access and retry"
    ) in captured.err
    assert "[Errno" not in captured.err
    assert "PermissionError" not in captured.err
    assert "Traceback" not in captured.err
    assert "run 'sigwood --help' for usage" not in captured.err
    assert "data found:" not in captured.out


# ── flags-before-verb hint (leading-flag implicit route) ─────────────────────


def test_leading_flag_then_verb_hints_corrected_command(
    capsys: pytest.CaptureFixture[str], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)  # no ./hunt on disk
    probe = _write_probe_config(tmp_path)
    with pytest.raises(SystemExit) as exc:
        cli.main([f"--config={probe}", "hunt"])

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert (
        f"sigwood: 'hunt' is a command - flags go after the verb: "
        f"sigwood hunt --config={probe}" in err
    )
    assert "run 'sigwood --help' for usage" in err
    assert "not found" not in err


def test_leading_flag_then_other_verb_same_shape(
    capsys: pytest.CaptureFixture[str], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    monkeypatch.chdir(tmp_path)  # no ./dns on disk
    with pytest.raises(SystemExit) as exc:
        cli.main(["--out=x", "dns"])

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert (
        "sigwood: 'dns' is a command - flags go after the verb: "
        "sigwood dns --out=x" in err
    )
    assert "run 'sigwood --help' for usage" in err


def test_real_file_named_like_verb_still_loads(
    capsys: pytest.CaptureFixture[str], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The hint tests existence exactly as the plain not-found owner does, so a
    REAL file that happens to be named like a command loads unchanged."""
    probe = _write_probe_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    Path("hunt").write_text(
        "Jul  4 12:00:01 probehost sshd[123]: Accepted password for alice "
        "from 192.0.2.10 port 51515 ssh2\n",
        encoding="utf-8",
    )

    cli.main([f"--config={probe}", "--dry-run", "hunt"])

    captured = capsys.readouterr()
    assert "dry run" in captured.out
    assert "is a command" not in captured.err
    assert "not found" not in captured.err


def test_leading_flag_missing_nonverb_keeps_plain_not_found(
    capsys: pytest.CaptureFixture[str], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    probe = _write_probe_config(tmp_path)
    with pytest.raises(SystemExit) as exc:
        cli.main([f"--config={probe}", "./missing.log"])

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "sigwood: missing.log: not found" in err
    assert "is a command" not in err
    assert "run 'sigwood --help' for usage" not in err


def test_leading_path_verb_named_missing_keeps_plain_not_found(
    capsys: pytest.CaptureFixture[str], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The hint never fires without a leading FLAG: a leading-PATH entry with a
    verb-named missing positional keeps the plain not-found."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    monkeypatch.chdir(tmp_path)  # no ./digest on disk
    Path("existing.log").write_text(
        "Jul  4 12:00:01 probehost sshd[123]: Accepted password for alice "
        "from 192.0.2.10 port 51515 ssh2\n",
        encoding="utf-8",
    )
    with pytest.raises(SystemExit) as exc:
        cli.main(["./existing.log", "digest"])

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "sigwood: digest: not found" in err
    assert "is a command" not in err


def test_broken_pipe_exits_141_silently(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A closed downstream pipe exits 141 silently - no message, no traceback.

    Pins the arm ordering: BrokenPipeError (an OSError subclass) is caught before
    the generic OSError arm, which would otherwise print
    `sigwood: [Errno 32] Broken pipe` and exit 1.
    """

    def _raise_broken_pipe(argv: list[str] | None = None) -> int:
        raise BrokenPipeError(32, "Broken pipe")

    monkeypatch.setattr(cli, "_main", _raise_broken_pipe)
    with pytest.raises(SystemExit) as exc:
        cli.main([])

    assert exc.value.code == 141
    captured = capsys.readouterr()
    # capsys's stdout has no real fileno, so the arm's dup2 no-ops via except
    # OSError and the close stays silent.
    assert captured.err == ""
    assert "Traceback" not in captured.err


def test_broken_pipe_smoke_exits_141_silently() -> None:
    """A real early pipe close over a full buffer exits 141 with empty stderr.

    Exercises the actual fileno/dup2 branch a capsys unit cannot: the child
    writes past the pipe buffer to a reader the parent has closed.
    """
    script = textwrap.dedent(
        """
        import sys
        import sigwood.cli as c

        def fake_main(argv=None):
            sys.stdout.write("x" * (4 * 1024 * 1024))
            sys.stdout.flush()
            return 0

        c._main = fake_main
        c.main([])
        """
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdout is not None
    proc.stdout.close()
    rc = proc.wait()
    err = proc.stderr.read()

    assert rc == 141
    assert err == b""
    assert b"Traceback" not in err
    assert b"Broken pipe" not in err
