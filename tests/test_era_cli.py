"""Public Era CLI boundary checks."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

import sigwood.cli as cli


def test_era_rejects_hunt_only_flags() -> None:
    for token in ("--all", "--since=7d", "--zeek-dir=/tmp", "--no-allowlist", "-vv"):
        with pytest.raises(cli.UsageError):
            cli._parse_args([token], "era")


@pytest.mark.parametrize(
    ("token", "key", "value"),
    [
        ("--config=era.toml", "config", "era.toml"),
        ("-c=era.toml", "config", "era.toml"),
        ("--out=result.txt", "out", "result.txt"),
        ("-o=result.txt", "out", "result.txt"),
        ("--format=text", "format", "text"),
        ("-f=text", "format", "text"),
    ],
)
def test_era_value_options_remain_equals_only(token: str, key: str, value: str) -> None:
    assert cli._parse_args([token], "era")[key] == value


@pytest.mark.parametrize("token", ("--config", "-c", "--out", "-o", "--format", "-f"))
def test_era_value_options_reject_space_separated_values(token: str) -> None:
    with pytest.raises(cli.UsageError, match="needs a value"):
        cli._parse_args([token], "era")


def test_era_rejects_multiple_roots() -> None:
    with pytest.raises(cli.UsageError, match="at most one"):
        cli._run_era(["one", "two"])


def test_era_dry_run_reaches_runner_without_an_output_file(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}
    monkeypatch.setattr(cli, "_load_config", lambda _parsed: {"sigwood": {"zeek_dir": "archive"}})

    def fake_run(_config: object, **kwargs: object) -> None:
        seen.update(kwargs)

    import sigwood.runner as runner
    monkeypatch.setattr(runner, "run_era", fake_run)
    assert cli._run_era(["--dry-run"]) == 0
    assert seen["dry_run"] is True
    assert str(seen["archive_root"]) == "archive"


def test_era_validates_text_format_before_loading_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "_load_config", lambda _parsed: pytest.fail("config loaded"))
    with pytest.raises(cli.UsageError, match="only --format=text"):
        cli._run_era(["--format=json"])


def test_era_positional_root_overrides_config_root(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}
    monkeypatch.setattr(cli, "_load_config", lambda _parsed: {"sigwood": {"zeek_dir": "configured"}})
    import sigwood.runner as runner

    def fake_run(_config: object, **kwargs: object) -> None:
        seen.update(kwargs)

    monkeypatch.setattr(runner, "run_era", fake_run)
    cli._run_era(["provided"])
    assert Path(seen["archive_root"]).name == "provided"


def test_era_needs_a_configured_or_positional_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "_load_config", lambda _parsed: {"sigwood": {}})
    with pytest.raises(cli.UsageError, match="zeek_dir"):
        cli._run_era([])


def test_era_omitted_and_dash_out_keep_stdout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "_load_config", lambda _parsed: {"sigwood": {"zeek_dir": "archive", "report_dir": "ignored"}})
    import sigwood.runner as runner
    monkeypatch.setattr(runner, "run_era", lambda _config, **kwargs: kwargs["stream"].write("deck\n"))
    assert cli._run_era([]) == 0
    assert cli._run_era(["--out=-"]) == 0


def test_era_explicit_file_writes_exact_target_and_always_reports_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    target = tmp_path / "exact.txt"
    monkeypatch.setattr(cli, "_load_config", lambda _parsed: {"sigwood": {"zeek_dir": "archive", "report_dir": str(tmp_path / "ignored")}})
    import sigwood.runner as runner
    monkeypatch.setattr(runner, "run_era", lambda _config, **kwargs: kwargs["stream"].write("deck\n"))
    cli._run_era([f"--out={target}", "--quiet"])
    assert target.read_text() == "deck\n"
    assert "wrote era to" in capsys.readouterr().err


def test_era_directory_target_autonames_and_avoids_collisions(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setattr(cli, "_load_config", lambda _parsed: {"sigwood": {"zeek_dir": "archive"}})
    import sigwood.runner as runner
    monkeypatch.setattr(runner, "run_era", lambda _config, **kwargs: kwargs["stream"].write("deck\n"))
    cli._run_era([f"--out={tmp_path}/"])
    cli._run_era([f"--out={tmp_path}/"])
    written = sorted(tmp_path.glob("sigwood-era_*.txt"))
    assert len(written) == 2
    assert written[0].read_text() == written[1].read_text() == "deck\n"


def test_era_dry_run_never_prompts_or_loads(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Planning-only mode returns before both confirmation and the U7 fold."""
    (tmp_path / "2026-01-01").mkdir()
    import sigwood.runner as runner
    monkeypatch.setattr(runner, "_confirm_era_work", lambda **_kwargs: pytest.fail("prompted"))
    monkeypatch.setattr(runner, "_run_era_harness", lambda *_args, **_kwargs: pytest.fail("loaded"))
    output = io.StringIO()
    assert runner.run_era({"sigwood": {}}, archive_root=tmp_path, stream=output, dry_run=True) is None
    assert "calendar: 1 canonical days" in output.getvalue()
    assert "would run: cards 1-10 (raw pre-allowlist)" in output.getvalue()


def test_era_short_calendar_preflight_is_quiet_gated(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "2026-01-01").mkdir()
    import sigwood.runner as runner
    runner.run_era({"sigwood": {}}, archive_root=tmp_path, stream=io.StringIO(), dry_run=True)
    assert "1 days" in capsys.readouterr().err
    runner.run_era({"sigwood": {}}, archive_root=tmp_path, stream=io.StringIO(), dry_run=True, quiet=True)
    assert capsys.readouterr().err == ""


def test_era_confirmation_uses_compressed_bytes_and_yes_bypasses(monkeypatch: pytest.MonkeyPatch) -> None:
    import sigwood.runner as runner
    asked: list[str] = []
    monkeypatch.setattr("builtins.input", lambda prompt: asked.append(prompt) or "yes")
    runner._confirm_era_work(runner._ERA_CONFIRM_COMPRESSED_BYTES, skip_confirm=False)
    assert asked and "compressed archive data" in asked[0] and "about an hour" in asked[0]
    runner._confirm_era_work(runner._ERA_CONFIRM_COMPRESSED_BYTES, skip_confirm=True)
    assert len(asked) == 1


def test_era_confirmation_decline_is_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    import sigwood.runner as runner
    monkeypatch.setattr("builtins.input", lambda _prompt: "no")
    with pytest.raises(cli.ExportAborted, match="aborted by user"):
        runner._confirm_era_work(runner._ERA_CONFIRM_COMPRESSED_BYTES, skip_confirm=False)


def test_era_help_advertises_only_its_supported_format() -> None:
    help_text = cli._render_verb_help("era")
    assert "output format (text; the only Era format)" in help_text
    assert "text, json, csv, html, pdf" not in help_text
    assert "without loading or writing output" in help_text
