"""Both value spellings share one grammar without changing argv boundaries."""

import pytest

from sigwood import cli


_VALUE_FORMS = [
    pytest.param(spec, form, id=form)
    for spec in cli._FLAG_LIST if spec.takes_value
    for form in ([spec.long, f"-{spec.short}"] if spec.short else [spec.long])
]
_OUT_NEEDS_VALUE = (
    "--out (-o) needs a value: --out=PATH, -o=PATH, or --out PATH; "
    "use = for values starting with -"
)


@pytest.mark.parametrize("spec,form", _VALUE_FORMS)
@pytest.mark.parametrize("value", ["value=with spaces", "", "-"])
def test_every_value_flag_accepts_both_forms(spec, form: str, value: str) -> None:
    # Choose from declared membership, so a new flag also inherits the matrix.
    verb = next(name for name, vs in cli._VERBS.items() if spec.key in vs.allowed)
    expected = {
        spec.key: value, "path": "first.log", "paths": ["first.log", "last.log"],
    }
    assert cli._parse_args(["first.log", f"{form}={value}", "last.log"], verb) == expected
    assert cli._parse_args(["first.log", form, value, "last.log"], verb) == expected


@pytest.mark.parametrize("flag", ["--out", "-o"])
@pytest.mark.parametrize("tail", [[], ["--quiet"], ["-q"], ["-1"], ["--"]])
def test_missing_value_does_not_swallow_flag(flag: str, tail: list[str]) -> None:
    with pytest.raises(cli.UsageError) as caught:
        cli._parse_args([flag, *tail], "hunt")
    assert str(caught.value) == _OUT_NEEDS_VALUE


@pytest.mark.parametrize("form", ["--out", "-o"])
def test_dash_leading_value_uses_equals(form: str) -> None:
    assert cli._parse_args([f"{form}=-report.txt"], "hunt") == {"out": "-report.txt"}


def test_needs_value_message_uses_the_flags_metavar() -> None:
    with pytest.raises(cli.UsageError) as caught:
        cli._parse_args(["--config"], "hunt")
    assert str(caught.value) == (
        "--config (-c) needs a value: --config=FILE, -c=FILE, or --config FILE; "
        "use = for values starting with -"
    )


@pytest.mark.parametrize("flag,key", [("-v", "verbose"), ("-q", "quiet"), ("--all", "all")])
def test_boolean_flag_keeps_following_path(flag: str, key: str) -> None:
    assert cli._parse_args([flag, "conn.log"], "hunt") == {
        key: True, "path": "conn.log", "paths": ["conn.log"],
    }


def test_boolean_does_not_consume_true() -> None:
    assert cli._parse_args(["--quiet", "true"], "hunt") == {
        "quiet": True, "path": "true", "paths": ["true"],
    }


@pytest.mark.parametrize("args", [
    ["--out=a", "--out", "b"], ["--out", "a", "--out=b"],
    ["-o=a", "-o", "b"], ["-o", "a", "-o=b"],
])
def test_mixed_value_spellings_are_last_wins(args: list[str]) -> None:
    assert cli._parse_args(args, "hunt") == {"out": "b"}


@pytest.mark.parametrize("args", [["-v", "-vv"], ["-vv", "-v"]])
def test_literal_vv_stays_distinct(args: list[str]) -> None:
    assert cli._resolve_verbose_level(cli._parse_args(args, "hunt")) == 2


@pytest.mark.parametrize("args,message", [
    (["-vy"], "short flags can't be combined (-vy); pass separately: -v -y"),
    (["-oreport.txt"], "unknown flag -oreport.txt"),
    (["-d", "beacon"], "-d (--detect) is not valid for digest"),
    (["--detect", "beacon"], "--detect (-d) is not valid for digest"),
    (["--not-a-flag", "value"], "unknown flag --not-a-flag"),
])
def test_identity_and_membership_errors_stay_first(args: list[str], message: str) -> None:
    with pytest.raises(cli.UsageError) as caught:
        cli._parse_args(args, "digest")
    assert str(caught.value) == message


@pytest.mark.parametrize("help_flag", ["--help", "-h"])
def test_help_short_circuits_before_value_consumption(help_flag, monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "_load_config", lambda _: pytest.fail("config loaded during help"))
    assert cli._main(["hunt", "--format", help_flag]) == 0
    assert capsys.readouterr().out.startswith("Usage: sigwood hunt ")


@pytest.mark.parametrize("space_form", [False, True])
def test_leading_config_value_keeps_flags_before_verb_hint(space_form, tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    config = tmp_path / "settings.toml"
    config.write_text('[sigwood]\nroot = ""\n', encoding="utf-8")
    args = ["--config", str(config)] if space_form else [f"--config={config}"]
    with pytest.raises(cli.UsageError, match="flags go after the verb"):
        cli._main([*args, "hunt"])


def test_implicit_hunt_accepts_space_format_on_real_dry_run(tmp_path, capsys) -> None:
    config = tmp_path / "settings.toml"
    config.write_text('[sigwood]\nroot = ""\n', encoding="utf-8")
    log = tmp_path / "syslog.log"
    log.write_text("Oct 19 12:00:01 fixture-host example[123]: sample event\n", encoding="utf-8")
    assert cli._main(["--format", "json", "--config", str(config), "--dry-run", str(log)]) == 0
    captured = capsys.readouterr()
    assert "dry run" in captured.out
    assert "needs a value" not in captured.err


@pytest.mark.parametrize("verb", list(cli._VERBS))
def test_each_help_has_one_value_syntax_sentence(verb: str) -> None:
    assert cli._render_verb_help(verb).count(
        "values follow the flag as --flag=value or --flag value"
    ) == 1


def test_global_help_has_one_value_syntax_sentence() -> None:
    assert cli._global_usage_text().count(
        "values follow the flag as --flag=value or --flag value"
    ) == 1
