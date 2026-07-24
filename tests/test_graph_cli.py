"""CLI and runner integration coverage for self-contained graph artifacts."""

from __future__ import annotations

import gzip
import io
import json
import os
import shlex
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import pytest

import sigwood.cli as cli
import sigwood.runner as runner
from sigwood.common import loader, sources
from sigwood.common.errors import GraphEmpty, GraphSourceUnreadable, UsageError
from sigwood.common.loader import LoadResult, LoadWindow, PermissionSkipInfo
from sigwood.common.sources import graph_kind_spec
from sigwood.common.display import _CURSOR_HIDE, _CURSOR_SHOW, default_window_advisory
from sigwood.graph._core import attach_hunt_hint, validate_config
from sigwood.graph.pihole import build as build_pihole


_CONN_LINE = (
    '{"_path":"conn","ts":1779750000.0,"uid":"C1",'
    '"id.orig_h":"192.0.2.10","id.resp_h":"198.51.100.20",'
    '"id.resp_p":443,"proto":"tcp","duration":1.0,"orig_bytes":128}\n'
)
_DNS_LINE = (
    '{"_path":"dns","ts":1779750000.0,"uid":"D1",'
    '"id.orig_h":"192.0.2.10","id.resp_h":"198.51.100.53",'
    '"query":"portal.example.com","qtype":1}\n'
)
_SYSLOG_LINE = (
    "Jun 11 12:00:00 host1 sshd[1234]: Accepted publickey for operator\n"
)
_PIHOLE_LINES = (
    "Jun  1 12:00:00 dnsmasq[1]: query[A] ads.example.com from 192.0.2.10\n"
    "Jun  1 12:00:01 dnsmasq[1]: cached ads.example.com is 203.0.113.20\n"
)


def _config(
    *,
    zeek_dir: Path | None = None,
    pihole_dir: Path | None = None,
    report_dir: str | None = None,
) -> dict[str, Any]:
    sigwood: dict[str, Any] = {
        "default_window": "all",
        "warn_above": 10_000_000,
    }
    if zeek_dir is not None:
        sigwood["zeek_dir"] = str(zeek_dir)
    if pihole_dir is not None:
        sigwood["pihole_dir"] = str(pihole_dir)
    if report_dir is not None:
        sigwood["report_dir"] = report_dir
    return {"sigwood": sigwood, "graph": {}}


def _stub_config(monkeypatch: pytest.MonkeyPatch, config: dict[str, Any]) -> None:
    monkeypatch.setattr(cli.cfg, "load", lambda _path: config)


def _two_kind_directory(tmp_path: Path) -> Path:
    source = tmp_path / "zeek"
    source.mkdir()
    (source / "conn.log").write_text(_CONN_LINE, encoding="utf-8")
    (source / "dns.log").write_text(_DNS_LINE, encoding="utf-8")
    return source


def _pihole_directory(tmp_path: Path) -> Path:
    source = tmp_path / "pihole"
    source.mkdir()
    (source / "pihole.log").write_text(_PIHOLE_LINES, encoding="utf-8")
    return source


def _pihole_rotation_directory(tmp_path: Path) -> Path:
    source = tmp_path / "pihole-rotations"
    source.mkdir()
    for name, day, domain, host in (
        ("pihole.log", 20, "recent.example.test", "192.0.2.20"),
        ("pihole.log.1", 18, "straddler.example.test", "192.0.2.18"),
        ("pihole.log.2", 15, "old.example.test", "192.0.2.15"),
    ):
        (source / name).write_text(
            f"Jul {day:2d} 12:00:00 dnsmasq[1]: "
            f"query[A] {domain} from {host}\n",
            encoding="utf-8",
        )
    return source


class _CursorTTY(io.StringIO):
    def isatty(self) -> bool:
        return True


@pytest.mark.parametrize("quiet", [False, True])
def test_run_graph_cursor_scope_restores_on_early_error_and_respects_quiet(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, quiet: bool,
) -> None:
    fake = _CursorTTY()
    monkeypatch.delenv("TERM", raising=False)
    monkeypatch.setattr("sys.stderr", fake)

    with pytest.raises(ValueError, match="mutually exclusive"):
        runner.run_graph(
            _config(),
            kind="conn",
            output_file=tmp_path / "graph.html",
            stream=io.StringIO(),
            quiet=quiet,
        )

    expected = "" if quiet else _CURSOR_HIDE + _CURSOR_SHOW
    assert fake.getvalue() == expected


def _trim_candidate_conn_frame() -> pd.DataFrame:
    dense_timestamps = [
        float(bin_index)
        for bin_index in range(6, 14)
        for _ in range(2_000)
    ]
    return pd.DataFrame({
        "ts": [0.0, *dense_timestamps],
        "src": ["192.0.2.250", *(["192.0.2.10"] * 16_000)],
        "dst": ["198.51.100.250", *(["198.51.100.10"] * 16_000)],
        "port": [161, *([443] * 16_000)],
        "proto": ["udp", *(["tcp"] * 16_000)],
        "bytes": [1, *([1] * 16_000)],
    })


def test_graph_arbitrary_named_sniffed_conn_file_writes_exact_html(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A sniff-approved explicit file bypasses filename discovery gates."""
    conn = tmp_path / "captured-input"
    conn.write_text(_CONN_LINE, encoding="utf-8")
    target = tmp_path / "exact.html"
    _stub_config(monkeypatch, _config())

    rc = cli._main(["graph", "--all", "-q", f"--out={target}", str(conn)])

    assert rc == 0
    html = target.read_text(encoding="utf-8")
    assert "const DATA = {" in html
    assert '"kind":"conn"' in html
    payload = json.loads(html.split("const DATA = ", 1)[1].split(";</script>", 1)[0])
    assert payload["meta"]["hunt_hint"] is None
    assert payload["meta"]["file_sample"] == "captured-input"
    assert payload["meta"]["file_count"] == 1
    assert payload["meta"]["common_dir"] == str(tmp_path.absolute())
    assert "__SIGWOOD_GRAPH_DATA__" not in html


def test_graph_cli_contains_an_oversized_optional_duration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    conn = tmp_path / "conn.log"
    conn.write_text(
        _CONN_LINE.replace('"duration":1.0', f'"duration":{10 ** 400}'),
        encoding="utf-8",
    )
    target = tmp_path / "graph.html"
    _stub_config(monkeypatch, _config())

    rc = cli._main(["graph", "--all", "-q", f"--out={target}", str(conn)])

    assert rc == 0
    assert target.exists()
    assert "traceback" not in capsys.readouterr().err.lower()


def test_graph_directory_fans_out_conn_and_dns_to_report_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One graphable directory produces one kind-specific artifact per feed."""
    source = _two_kind_directory(tmp_path)
    reports = tmp_path / "reports"
    reports.mkdir()
    _stub_config(monkeypatch, _config(report_dir=str(reports)))

    rc = cli._main(["graph", "--all", "-q", str(source)])

    assert rc == 0
    names = sorted(path.name for path in reports.glob("*.html"))
    assert len(names) == 2
    assert any(name.startswith("sigwood-graph_conn_") for name in names)
    assert any(name.startswith("sigwood-graph_dns_") for name in names)


def test_graph_kind_token_narrows_bare_config_to_conn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A kind token selects only that configured graph family member."""
    source = _two_kind_directory(tmp_path)
    reports = tmp_path / "reports"
    reports.mkdir()
    _stub_config(
        monkeypatch,
        _config(zeek_dir=source, report_dir=str(reports)),
    )

    assert cli._main(["graph", "conn", "--all", "-q"]) == 0

    artifacts = list(reports.glob("*.html"))
    assert len(artifacts) == 1
    assert artifacts[0].name.startswith("sigwood-graph_conn_")


def test_graph_kind_tokens_do_not_probe_unselected_denied_sibling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A denied unselected source cannot fail an explicitly narrowed run."""
    zeek = _two_kind_directory(tmp_path)
    pihole = _pihole_directory(tmp_path)
    reports = tmp_path / "reports"
    reports.mkdir()
    _stub_config(
        monkeypatch,
        _config(
            zeek_dir=zeek,
            pihole_dir=pihole,
            report_dir=str(reports),
        ),
    )
    pihole.chmod(0)
    try:
        rc = cli._main(["graph", "conn", "dns", "--all", "-q"])
    finally:
        pihole.chmod(0o700)

    captured = capsys.readouterr()
    assert rc == 0
    assert {
        path.name.split("_", 2)[1] for path in reports.glob("*.html")
    } == {"conn", "dns"}
    assert "permission" not in captured.err.lower()


@pytest.mark.parametrize(
    ("tokens", "expected"),
    [
        (["conn", "conn"], ["conn"]),
        (["conn", "dns"], ["conn", "dns"]),
    ],
)
def test_graph_kind_tokens_compose_dedupe_and_keep_declaration_order(
    tokens: list[str],
    expected: list[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _two_kind_directory(tmp_path)
    reports = tmp_path / "reports"
    reports.mkdir()
    _stub_config(
        monkeypatch,
        _config(zeek_dir=source, report_dir=str(reports)),
    )
    observed: list[str] = []

    def _run_graph(
        _config: dict[str, Any],
        *,
        kind: str,
        output_file: Path,
        **_kwargs: Any,
    ) -> Path:
        observed.append(kind)
        return output_file

    monkeypatch.setattr(runner, "run_graph", _run_graph)

    assert cli._main(["graph", *tokens, "--all", "-q"]) == 0
    assert observed == expected


@pytest.mark.parametrize(
    "positionals",
    [
        ["conn", "./conn.log"],
        ["./conn.log", "conn"],
    ],
)
def test_graph_kind_names_and_paths_cannot_mix_in_either_order(
    positionals: list[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "conn.log").write_text(_CONN_LINE, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    _stub_config(monkeypatch, _config())

    with pytest.raises(UsageError) as exc:
        cli._main(["graph", *positionals])

    assert str(exc.value) == (
        "kind names and paths cannot mix - pass one or the other "
        "(a file literally named conn is ./conn)"
    )


def test_graph_kind_token_intersects_with_matching_source_flag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _two_kind_directory(tmp_path)
    reports = tmp_path / "reports"
    reports.mkdir()
    _stub_config(monkeypatch, _config(report_dir=str(reports)))

    assert cli._main([
        "graph", "conn", "--all", "-q", f"--zeek-dir={source}",
    ]) == 0

    artifacts = list(reports.glob("*.html"))
    assert len(artifacts) == 1
    assert artifacts[0].name.startswith("sigwood-graph_conn_")


def test_graph_kind_token_rejects_disjoint_source_flag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _pihole_directory(tmp_path)
    _stub_config(monkeypatch, _config())

    with pytest.raises(UsageError) as exc:
        cli._main(["graph", "dns", f"--pihole-dir={source}"])

    assert str(exc.value) == (
        "--pihole-dir serves pihole, but this run selects dns - "
        "drop the flag or add its kind"
    )


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (
            ["graph", "conn", "./conn.log"],
            "kind names and paths cannot mix - pass one or the other "
            "(a file literally named conn is ./conn)",
        ),
        (
            ["graph", "dns", "--pihole-dir=unused"],
            "--pihole-dir serves pihole, but this run selects dns - "
            "drop the flag or add its kind",
        ),
    ],
)
def test_graph_kind_usage_errors_render_at_public_cli_boundary(
    args: list[str],
    message: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(args)

    assert exc.value.code == 1
    assert capsys.readouterr().err == (
        f"sigwood: {message}\nrun 'sigwood --help' for usage\n"
    )


def test_graph_kind_tokens_intersect_two_matching_source_flags(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    zeek = _two_kind_directory(tmp_path)
    pihole = _pihole_directory(tmp_path)
    reports = tmp_path / "reports"
    reports.mkdir()
    _stub_config(monkeypatch, _config(report_dir=str(reports)))

    assert cli._main([
        "graph", "conn", "pihole", "--all", "-q",
        f"--zeek-dir={zeek}", f"--pihole-dir={pihole}",
    ]) == 0

    assert {
        path.name.split("_", 2)[1] for path in reports.glob("*.html")
    } == {"conn", "pihole"}


def test_graph_kind_token_keeps_selected_wrong_shape_clean_empty(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "zeek"
    source.mkdir()
    (source / "dns.log").write_text(_DNS_LINE, encoding="utf-8")
    reports = tmp_path / "reports"
    reports.mkdir()
    _stub_config(
        monkeypatch,
        _config(zeek_dir=source, report_dir=str(reports)),
    )

    assert cli._main(["graph", "conn", "--all", "-q"]) == 0

    captured = capsys.readouterr()
    assert list(reports.glob("*.html")) == []
    assert "skipping" in captured.err
    assert "nothing to graph" not in captured.err


def test_graph_kind_token_is_exact_case_sensitive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    _stub_config(monkeypatch, _config())

    assert cli._main(["graph", "CONN", "-q"]) == 1

    captured = capsys.readouterr()
    assert "CONN: not found" in captured.err
    assert captured.err.rstrip().endswith("sigwood: nothing to graph")


def test_graph_kind_token_reserves_bare_name_but_dot_slash_reaches_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured = tmp_path / "configured"
    configured.mkdir()
    (configured / "conn.log").write_text(_CONN_LINE, encoding="utf-8")
    reserved = tmp_path / "conn"
    reserved.mkdir()
    (reserved / "pihole.log").write_text(_PIHOLE_LINES, encoding="utf-8")
    reports = tmp_path / "reports"
    reports.mkdir()
    monkeypatch.chdir(tmp_path)
    _stub_config(
        monkeypatch,
        _config(zeek_dir=configured, report_dir=str(reports)),
    )

    assert cli._main(["graph", "conn", "--all", "-q"]) == 0
    assert len(list(reports.glob("sigwood-graph_conn_*.html"))) == 1
    assert list(reports.glob("sigwood-graph_pihole_*.html")) == []

    assert cli._main(["graph", "./conn", "--all", "-q"]) == 0
    assert len(list(reports.glob("sigwood-graph_pihole_*.html"))) == 1


def test_graph_kind_token_narrows_dry_run_without_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = _two_kind_directory(tmp_path)
    reports = tmp_path / "reports"
    _stub_config(
        monkeypatch,
        _config(zeek_dir=source, report_dir=str(reports)),
    )

    assert cli._main(["graph", "conn", "--dry-run", "--all", "-q"]) == 0

    captured = capsys.readouterr()
    assert "sigwood  ·  graph  ·  dry run" in captured.out
    assert "\n  conn:" in captured.out
    assert "\n  dns:" not in captured.out
    assert not reports.exists()


def test_graph_one_kind_token_relaxes_stdout_and_exact_file_targets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = _two_kind_directory(tmp_path)
    _stub_config(monkeypatch, _config(zeek_dir=source))

    assert cli._main([
        "graph", "conn", "--all", "-q", "--out=-",
    ]) == 0
    streamed = capsys.readouterr().out
    assert '"kind":"conn"' in streamed
    assert '"kind":"dns"' not in streamed

    target = tmp_path / "exact.html"
    assert cli._main([
        "graph", "conn", "--all", "-q", f"--out={target}",
    ]) == 0
    assert target.exists()
    assert '"kind":"conn"' in target.read_text(encoding="utf-8")


@pytest.mark.parametrize("out_value", ["-", "exact.html"])
def test_graph_two_kind_tokens_keep_shared_target_guards(
    out_value: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _two_kind_directory(tmp_path)
    _stub_config(monkeypatch, _config(zeek_dir=source))
    target = out_value if out_value == "-" else str(tmp_path / out_value)

    with pytest.raises(UsageError, match="multiple kinds"):
        cli._main([
            "graph", "conn", "dns", "--all", "-q", f"--out={target}",
        ])


def test_graph_pihole_positional_file_writes_a_disposition_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A sniffed Pi-hole file selects its own graph builder and payload kind."""
    source = tmp_path / "captured-pihole"
    source.write_text(_PIHOLE_LINES, encoding="utf-8")
    target = tmp_path / "pihole.html"
    _stub_config(monkeypatch, _config())

    assert cli._main(["graph", "--all", "-q", f"--out={target}", str(source)]) == 0

    payload = json.loads(target.read_text(encoding="utf-8").split("const DATA = ", 1)[1].split(
        ";</script>", 1,
    )[0])
    assert payload["meta"]["kind"] == "pihole"
    assert payload["meta"]["rows"] == 1
    assert payload["svcNodes"] == ["cached"]
    assert payload["totC"][0] == 1.0
    assert all(value == 0.0 for value in payload["totC"][1:])
    hint = payload["meta"]["hunt_hint"]
    assert hint.startswith("sigwood hunt ")
    assert str(source.absolute()) in hint
    assert " --since=" in hint
    assert " --until=" in hint

    tokens = shlex.split(hint)
    since = cli._parse_iso_date(tokens[-2].split("=", 1)[1], "--since")
    until = cli._parse_iso_date(tokens[-1].split("=", 1)[1], "--until")
    replayed = build_pihole(
        loader.load_pihole(source, since=since, until=until, show_progress=False),
        config=validate_config({}),
        source_label=source.name,
    )
    assert replayed["svcNodes"] == payload["svcNodes"]


def test_graph_hunt_hint_quotes_inputs_and_gates_unrediscoverable_zeek_files(
    tmp_path: Path,
) -> None:
    """The footer command is paste-safe and never advertises a false Zeek replay."""
    payload = {"meta": {"t0": 10.1, "t1": 20.1, "hunt_hint": None}}
    hostile = tmp_path / "dir with space;$(touch no)\x1b" / "pihole.log"
    hint = runner._graph_hunt_hint(
        payload,
        spec=graph_kind_spec("pihole"),
        source_inputs=[hostile],
        has_explicit_inputs=True,
    )
    assert hint is not None
    assert "'" in hint
    attach_hunt_hint(payload, hint)
    rendered = payload["meta"]["hunt_hint"]
    assert "\x1b" not in rendered
    tokens = shlex.split(rendered)
    assert tokens[:2] == ["sigwood", "hunt"]
    assert tokens[2] == os.path.abspath(hostile).replace("\x1b", "")
    assert all(datetime.fromisoformat(token.split("=", 1)[1]).tzinfo is not None for token in tokens[-2:])

    odd = tmp_path / "captured-input"
    odd.write_text(_CONN_LINE, encoding="utf-8")
    assert runner._graph_hunt_hint(
        payload,
        spec=graph_kind_spec("conn"),
        source_inputs=[odd],
        has_explicit_inputs=True,
    ) is None

    matching = tmp_path / "conn.log"
    matching.write_text(_CONN_LINE, encoding="utf-8")
    assert runner._graph_hunt_hint(
        payload,
        spec=graph_kind_spec("conn"),
        source_inputs=[matching],
        has_explicit_inputs=True,
    ) is not None


def test_graph_discovered_file_meta_uses_deduped_loader_candidates(
    tmp_path: Path,
) -> None:
    source = tmp_path / "zeek"
    source.mkdir()
    primary = source / "conn.log"
    rotation = source / "conn.log.1"
    primary.write_text(_CONN_LINE, encoding="utf-8")
    rotation.write_text(_CONN_LINE, encoding="utf-8")

    meta = runner._graph_discovered_file_meta(
        graph_kind_spec("conn"), [source, primary], trusted_files=[],
    )

    assert meta == {
        "file_sample": "conn.log",
        "file_count": 2,
        "common_dir": str(source.absolute()),
    }


def test_graph_discovered_file_meta_cleans_trusted_file_provenance(
    tmp_path: Path,
) -> None:
    source = tmp_path / "odd\x1bdir"
    source.mkdir()
    trusted = source / "captured\x1binput"
    trusted.write_text(_CONN_LINE, encoding="utf-8")

    meta = runner._graph_discovered_file_meta(
        graph_kind_spec("conn"), [trusted], trusted_files=[trusted],
    )

    assert meta["file_sample"] == "capturedinput"
    assert meta["file_count"] == 1
    assert meta["common_dir"] == str(source.absolute()).replace("\x1b", "")
    assert "\x1b" not in "".join(str(value) for value in meta.values())


def test_graph_discovered_file_meta_omits_cross_root_common_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = tmp_path / "one" / "conn.log"
    second = tmp_path / "two" / "conn.log"
    monkeypatch.setattr(
        loader,
        "discover_for_source_key",
        lambda *_args, **_kwargs: [first, second],
    )
    monkeypatch.setattr(
        os.path,
        "commonpath",
        lambda _paths: (_ for _ in ()).throw(ValueError("different drives")),
    )

    meta = runner._graph_discovered_file_meta(
        graph_kind_spec("conn"), [tmp_path], trusted_files=[],
    )

    assert meta["file_count"] == 2
    assert meta["common_dir"] == ""


def test_graph_pihole_dir_flag_and_bare_config_route_to_pihole(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The declared pihole flag and config fallback both produce one artifact."""
    source = _pihole_directory(tmp_path)
    reports = tmp_path / "reports"
    reports.mkdir()
    _stub_config(monkeypatch, _config(report_dir=str(reports)))

    assert cli._main(["graph", "--all", "-q", f"--pihole-dir={source}"]) == 0
    assert len(list(reports.glob("sigwood-graph_pihole_*.html"))) == 1

    for path in reports.glob("*.html"):
        path.unlink()
    _stub_config(monkeypatch, _config(pihole_dir=source, report_dir=str(reports)))
    assert cli._main(["graph", "--all", "-q"]) == 0
    assert len(list(reports.glob("sigwood-graph_pihole_*.html"))) == 1


@pytest.mark.parametrize("flag", ["--zeek-dir", "--pihole-dir"])
def test_graph_rejects_each_source_flag_with_a_positional(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flag: str,
) -> None:
    """A family declaration cannot be mixed with a content-sniffed positional."""
    source = _pihole_directory(tmp_path)
    _stub_config(monkeypatch, _config())

    with pytest.raises(UsageError, match="not valid alongside a positional PATH"):
        cli._main(["graph", f"{flag}={source}", str(source / "pihole.log")])


def test_graph_two_source_flags_fan_out_only_their_declared_families(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Zeek and Pi-hole declarations reach conn/dns and pihole respectively."""
    zeek = _two_kind_directory(tmp_path)
    pihole = _pihole_directory(tmp_path)
    reports = tmp_path / "reports"
    reports.mkdir()
    _stub_config(monkeypatch, _config(report_dir=str(reports)))

    assert cli._main([
        "graph", "--all", "-q", f"--zeek-dir={zeek}", f"--pihole-dir={pihole}",
    ]) == 0

    names = {path.name.split("_", 2)[1] for path in reports.glob("*.html")}
    assert names == {"conn", "dns", "pihole"}


def test_graph_wrong_family_flag_is_a_clean_empty_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """A declared Zeek source does not content-route Pi-hole files to pihole."""
    source = _pihole_directory(tmp_path)
    _stub_config(monkeypatch, _config())

    assert cli._main(["graph", "--all", "-q", f"--zeek-dir={source}"]) == 0

    captured = capsys.readouterr()
    assert "as pihole" not in captured.err.lower()
    assert "conn" in captured.err and "dns" in captured.err


def test_graph_dry_run_plans_all_buckets_without_creating_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """Dry-run validates and names artifacts but never invokes loading or mkdir."""
    source = _two_kind_directory(tmp_path)
    target_dir = tmp_path / "would-create"
    _stub_config(monkeypatch, _config())

    rc = cli._main([
        "graph", "--dry-run", f"--out={target_dir}/", str(source),
    ])

    captured = capsys.readouterr()
    assert rc == 0
    assert "sigwood  ·  graph  ·  dry run" in captured.out
    assert "conn:" in captured.out and "dns:" in captured.out
    assert "stdout" not in captured.out
    assert not target_dir.exists()


def test_graph_rejects_multi_kind_stdout_before_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Multiple artifacts cannot collide on the one stdout stream."""
    source = _two_kind_directory(tmp_path)
    _stub_config(monkeypatch, _config())

    with pytest.raises(UsageError, match="multiple kinds.*stdout"):
        cli._main(["graph", "--out=-", str(source)])


def test_graph_artifact_wins_over_ordinary_sibling_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """A malformed kind does not erase a sibling graph artifact's success."""
    source = _two_kind_directory(tmp_path)
    reports = tmp_path / "reports"
    reports.mkdir()
    _stub_config(monkeypatch, _config(report_dir=str(reports)))

    def _fake_run_graph(_config: dict[str, Any], *, kind: str, **kwargs: Any) -> Path:
        if kind == "dns":
            raise ValueError("dns.log fields not found: query")
        return kwargs["output_file"]

    monkeypatch.setattr(runner, "run_graph", _fake_run_graph)
    rc = cli._main(["graph", str(source)])

    captured = capsys.readouterr()
    assert rc == 0
    assert "dns.log fields not found" in captured.err


def test_graph_keeps_a_valid_positional_sibling_when_another_is_unsupported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """A rejected positional input does not discard a graphable sibling."""
    conn = tmp_path / "conn.log"
    conn.write_text(_CONN_LINE, encoding="utf-8")
    syslog = tmp_path / "auth.log"
    syslog.write_text(_SYSLOG_LINE, encoding="utf-8")
    target = tmp_path / "conn.html"
    _stub_config(monkeypatch, _config())

    rc = cli._main([
        "graph", "--all", "-q", f"--out={target}", str(conn), str(syslog),
    ])

    captured = capsys.readouterr()
    assert rc == 0
    assert target.exists()
    assert "can't graph auth.log" in captured.err
    assert "nothing to graph" not in captured.err


def test_graph_probe_permission_outranks_a_written_sibling_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """A denied positional is recorded even when another source renders."""
    conn = tmp_path / "conn.log"
    conn.write_text(_CONN_LINE, encoding="utf-8")
    denied = tmp_path / "denied.log"
    denied.write_text("placeholder\n", encoding="utf-8")
    target = tmp_path / "conn.html"
    _stub_config(monkeypatch, _config())
    real_sniff = sources.sniff_format_detailed

    def _sniff(path: Path):
        if path == denied:
            raise PermissionError("synthetic denied")
        return real_sniff(path)

    monkeypatch.setattr(sources, "sniff_format_detailed", _sniff)

    rc = cli._main([
        "graph", "--all", "-q", f"--out={target}", str(conn), str(denied),
    ])

    captured = capsys.readouterr()
    assert rc == 1
    assert target.exists()
    assert "permission denied" in captured.err


def test_graph_dry_run_keeps_probe_permission_strict_without_creating_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """A dry run can show a valid plan but still fails a denied requested input."""
    conn = tmp_path / "conn.log"
    conn.write_text(_CONN_LINE, encoding="utf-8")
    denied = tmp_path / "denied.log"
    denied.write_text("placeholder\n", encoding="utf-8")
    target = tmp_path / "planned.html"
    _stub_config(monkeypatch, _config())
    real_sniff = sources.sniff_format_detailed

    def _sniff(path: Path):
        if path == denied:
            raise PermissionError("synthetic denied")
        return real_sniff(path)

    monkeypatch.setattr(sources, "sniff_format_detailed", _sniff)

    rc = cli._main([
        "graph", "--dry-run", "-q", f"--out={target}", str(conn), str(denied),
    ])

    captured = capsys.readouterr()
    assert rc == 1
    assert "dry run" in captured.out
    assert "permission denied" in captured.err
    assert not target.exists()


def test_graph_reports_only_unsupported_inputs_with_a_final_actionable_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """No accepted bucket leaves the operator with a final graph status."""
    syslog = tmp_path / "auth.log"
    syslog.write_text(_SYSLOG_LINE, encoding="utf-8")
    _stub_config(monkeypatch, _config())

    rc = cli._main(["graph", "-q", str(syslog)])

    captured = capsys.readouterr()
    assert rc == 1
    assert "can't graph auth.log" in captured.err
    assert captured.err.rstrip().endswith("sigwood: nothing to graph")


def test_graph_discloses_non_graphable_directory_votes_without_losing_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """A mixed directory keeps graphable files and names the skipped family."""
    source = tmp_path / "mixed"
    source.mkdir()
    (source / "conn.log").write_text(_CONN_LINE, encoding="utf-8")
    (source / "auth.log").write_text(_SYSLOG_LINE, encoding="utf-8")
    reports = tmp_path / "reports"
    reports.mkdir()
    _stub_config(monkeypatch, _config(report_dir=str(reports)))

    rc = cli._main(["graph", "--all", str(source)])

    captured = capsys.readouterr()
    assert rc == 0
    assert len(list(reports.glob("sigwood-graph_conn_*.html"))) == 1
    assert "mixed log types sampled" in captured.err
    assert "non-graphable files skipped" in captured.err


def test_graph_bare_configured_empty_directory_is_a_clean_noop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An existing configured directory with no graph rows is not a path error."""
    source = tmp_path / "empty"
    source.mkdir()
    reports = tmp_path / "reports"
    reports.mkdir()
    _stub_config(monkeypatch, _config(zeek_dir=source, report_dir=str(reports)))

    assert cli._main(["graph", "-q"]) == 0
    assert list(reports.glob("*.html")) == []


def test_graph_real_loader_skips_scalar_and_oversized_ndjson_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """Malformed NDJSON rows cannot escape the real graph loading path."""
    source = tmp_path / "conn.log"
    source.write_text(
        _CONN_LINE + "[]\nnull\n" + '{"_path":"conn","ts":' + ("1" * 4_095) + "}\n",
        encoding="utf-8",
    )
    target = tmp_path / "graph.html"
    _stub_config(monkeypatch, _config())

    rc = cli._main(["graph", "--all", "-q", f"--out={target}", str(source)])

    captured = capsys.readouterr()
    assert rc == 0
    assert target.exists()
    assert "traceback" not in captured.err.lower()


def test_graph_contains_recursion_limited_json_at_sniff_and_load_boundaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """Nested JSON cannot escape either graph parsing boundary as a traceback."""
    nested = "[" * 200_000 + "0" + "]" * 200_000
    hostile = (
        '{"_path":"conn","ts":1779750000.0,'
        '"id.orig_h":"192.0.2.10","id.resp_h":"198.51.100.20",'
        '"id.resp_p":443,"proto":"tcp","orig_bytes":1,"duration":1,'
        '"detail":' + nested + "}\n"
    )
    source = tmp_path / "conn.log"
    target = tmp_path / "graph.html"
    _stub_config(monkeypatch, _config())

    source.write_text(hostile, encoding="utf-8")
    assert cli._main(["graph", "-q", f"--out={target}", str(source)]) == 1
    first = capsys.readouterr()
    assert "can't graph conn.log" in first.err
    assert "traceback" not in first.err.lower()

    source.write_text(_CONN_LINE + hostile, encoding="utf-8")
    assert cli._main(["graph", "--all", "-q", f"--out={target}", str(source)]) == 0
    second = capsys.readouterr()
    assert target.exists()
    assert "traceback" not in second.err.lower()


def test_graph_contains_array_shaped_dns_qtype_without_pandas_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """A malformed optional qtype becomes an unknown graph label safely."""
    source = tmp_path / "dns.log"
    source.write_text(
        '{"_path":"dns","ts":1779750000.0,"uid":"D1",'
        '"id.orig_h":"192.0.2.10","query":"portal.example.com",'
        '"qtype":[1,2]}\n',
        encoding="utf-8",
    )
    target = tmp_path / "graph.html"
    _stub_config(monkeypatch, _config())

    assert cli._main(["graph", "--all", "-q", f"--out={target}", str(source)]) == 0
    captured = capsys.readouterr()
    blob = target.read_text(encoding="utf-8").split("const DATA = ", 1)[1].split(
        ";</script>", 1,
    )[0]

    assert json.loads(blob)["svcNodes"] == ["unknown"]
    assert "traceback" not in captured.err.lower()


def test_graph_contains_structured_identity_labels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """A parseable structured identity degrades before graph grouping."""
    nested = '[["not-an-address"]]'
    source = tmp_path / "conn.log"
    source.write_text(
        '{"_path":"conn","ts":1779750000.0,"uid":"C1",'
        '"id.orig_h":' + nested + ','
        '"id.resp_h":"198.51.100.20","id.resp_p":443,"proto":"tcp",'
        '"duration":1.0,"orig_bytes":1}\n',
        encoding="utf-8",
    )
    target = tmp_path / "graph.html"
    _stub_config(monkeypatch, _config())

    assert cli._main(["graph", "--all", "-q", f"--out={target}", str(source)]) == 0
    captured = capsys.readouterr()
    blob = target.read_text(encoding="utf-8").split("const DATA = ", 1)[1].split(
        ";</script>", 1,
    )[0]

    assert json.loads(blob)["srcNodes"][0]["id"] == "(unknown)"
    assert "traceback" not in captured.err.lower()


@pytest.mark.parametrize(
    ("replacement", "expected_rc", "expected_message", "expected_artifact"),
    [
        (('"ts":1779750000.0', '"ts":1e308'), 0, "no renderable records", False),
        (('"orig_bytes":128', '"orig_bytes":1e308'), 0, None, True),
    ],
)
def test_graph_real_loader_contains_hostile_finite_numbers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    replacement: tuple[str, str],
    expected_rc: int,
    expected_message: str | None,
    expected_artifact: bool,
) -> None:
    """Finite numeric extremes become graph outcomes rather than tracebacks."""
    source = tmp_path / "conn.log"
    source.write_text(_CONN_LINE.replace(*replacement), encoding="utf-8")
    target = tmp_path / "graph.html"
    _stub_config(monkeypatch, _config())

    rc = cli._main(["graph", "--all", "-q", f"--out={target}", str(source)])

    captured = capsys.readouterr()
    assert rc == expected_rc
    if expected_message is not None:
        assert expected_message in captured.err
    assert "traceback" not in captured.err.lower()
    assert target.exists() is expected_artifact
    if expected_artifact:
        payload = json.loads(
            target.read_text(encoding="utf-8")
            .split("const DATA = ", 1)[1]
            .split(";</script>", 1)[0]
        )
        assert payload["meta"]["altered_metric_cells"] == 1
        assert payload["meta"]["degrade_note"] == (
            "scaled 1 metric cells to the render ceiling"
        )
        assert payload["meta"]["degrade_note"] not in captured.err


def test_graph_real_loader_degrades_missing_conn_enrichment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "conn.log"
    line = _CONN_LINE.replace(
        '"id.resp_p":443,"proto":"tcp",', "",
    ).replace(',"orig_bytes":128', "")
    source.write_text(line, encoding="utf-8")
    target = tmp_path / "graph.html"
    _stub_config(monkeypatch, _config())

    assert cli._main([
        "graph", "--all", "-q", f"--out={target}", str(source),
    ]) == 0

    captured = capsys.readouterr()
    payload = json.loads(
        target.read_text(encoding="utf-8")
        .split("const DATA = ", 1)[1]
        .split(";</script>", 1)[0]
    )
    assert payload["meta"]["single_metric"] is True
    assert payload["meta"]["degrade_note"] == (
        "conn.log has no byte counts; showing connection counts only"
    )
    assert payload["svcNodes"] == ["unknown"]
    assert "fields not found" not in captured.err


def test_graph_permission_failure_outranks_sibling_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A denied requested source exits nonzero even when another kind rendered."""
    source = _two_kind_directory(tmp_path)
    reports = tmp_path / "reports"
    reports.mkdir()
    _stub_config(monkeypatch, _config(report_dir=str(reports)))

    def _fake_run_graph(_config: dict[str, Any], *, kind: str, **kwargs: Any) -> Path:
        if kind == "dns":
            raise GraphSourceUnreadable("dns", "dns.log", "permission denied")
        return kwargs["output_file"]

    monkeypatch.setattr(runner, "run_graph", _fake_run_graph)
    assert cli._main(["graph", "-q", str(source)]) == 1


def test_graph_all_recognized_empty_buckets_are_a_clean_noop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """All clean-empty buckets exit successfully without an artifact."""
    source = _two_kind_directory(tmp_path)
    reports = tmp_path / "reports"
    reports.mkdir()
    _stub_config(monkeypatch, _config(report_dir=str(reports)))

    def _empty(_config: dict[str, Any], *, kind: str, **_kwargs: Any) -> Path:
        raise GraphEmpty(kind, f"{kind}.log", "no parseable records")

    monkeypatch.setattr(runner, "run_graph", _empty)
    assert cli._main(["graph", "-q", str(source)]) == 0


def test_graph_parser_rejects_format_and_verbose_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Graph stays off the generic format and verbose flag surface."""
    conn = tmp_path / "conn.log"
    conn.write_text(_CONN_LINE, encoding="utf-8")
    _stub_config(monkeypatch, _config())

    with pytest.raises(UsageError, match="--format.*not valid for graph"):
        cli._main(["graph", "--format=text", str(conn)])
    with pytest.raises(UsageError, match="--verbose.*not valid for graph"):
        cli._main(["graph", "--verbose", str(conn)])


def test_graph_target_falls_back_to_cwd_and_uses_display_date(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, restore_display_utc,
) -> None:
    """No out/report_dir produces a graph artifact name in the current directory."""
    monkeypatch.chdir(tmp_path)
    cli.set_display_utc(True)

    target = cli._resolve_graph_output_target({}, _config(), "conn")

    assert target is not None
    assert target.parent == Path(".")
    assert target.name.startswith("sigwood-graph_conn_")
    assert target.suffix == ".html"


def test_graph_basename_uses_display_timezone_conversion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Artifact naming follows the display conversion rather than host UTC."""
    monkeypatch.setattr(
        cli, "to_display_timezone",
        lambda _value: datetime(2042, 3, 4, tzinfo=timezone.utc),
    )

    assert cli._graph_basename("dns") == "sigwood-graph_dns_20420304.html"


def test_run_graph_strict_permission_blocks_render_before_stream_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Strict loader accounting surfaces a typed denial before renderer output."""
    source = tmp_path / "trusted-file"
    source.write_text("placeholder\n", encoding="utf-8")
    frame = pd.DataFrame({
        "ts": [1779750000.0],
        "src": ["192.0.2.10"],
        "dst": ["198.51.100.20"],
        "port": [443],
        "proto": ["tcp"],
        "bytes": [1],
    })
    result = LoadResult(
        logs={"conn*.log*": frame},
        record_counts={"conn*.log*": 1},
        permission_skips={
            "conn*.log*": PermissionSkipInfo(
                discovered=2, denied=1, paths=(source,),
            )
        },
    )
    from sigwood.common import loader

    monkeypatch.setattr(loader, "resolve_load_windows", lambda *args, **kwargs: [])
    monkeypatch.setattr(loader, "load_required_logs", lambda *args, **kwargs: result)
    stream = io.StringIO()

    with pytest.raises(GraphSourceUnreadable, match="1 of 2"):
        runner.run_graph(
            _config(), kind="conn", inputs=source, stream=stream, quiet=True,
        )
    assert stream.getvalue() == ""


def test_run_graph_date_retry_rechecks_strict_permission_accounting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, restore_display_utc,
) -> None:
    source = tmp_path / "2026-05-25"
    source.mkdir()
    denied = source / "conn.log"
    denied.write_text(_CONN_LINE, encoding="utf-8")
    frame = pd.DataFrame({
        "ts": [1778972400.0],
        "src": ["192.0.2.10"],
        "dst": ["198.51.100.20"],
        "port": [443],
        "proto": ["tcp"],
        "bytes": [1],
    })
    first = LoadResult(
        logs={"conn*.log*": pd.DataFrame()}, record_counts={"conn*.log*": 0},
    )
    retry = LoadResult(
        logs={"conn*.log*": frame},
        record_counts={"conn*.log*": 1},
        permission_skips={
            "conn*.log*": PermissionSkipInfo(
                discovered=2, denied=1, paths=(denied,),
            )
        },
    )
    from sigwood.common import loader

    results = iter((first, retry))
    monkeypatch.setattr(loader, "resolve_load_windows", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        loader, "load_required_logs", lambda *args, **kwargs: next(results),
    )
    stream = io.StringIO()
    config = _config()
    config["sigwood"]["default_window"] = "7d"

    with pytest.raises(GraphSourceUnreadable, match="1 of 2"):
        runner.run_graph(
            config, kind="conn", inputs=source, stream=stream,
            quiet=True, use_utc=True,
        )
    assert stream.getvalue() == ""


@pytest.mark.parametrize("inputs", [None, "", [], [""], [None]])
def test_run_graph_config_file_never_inherits_a_falsy_trusted_override(
    tmp_path: Path,
    inputs: object,
) -> None:
    """Falsy caller values retain config discovery rather than bypassing it."""
    dns = tmp_path / "dns.log"
    dns.write_text(_DNS_LINE, encoding="utf-8")

    with pytest.raises(GraphEmpty, match="no parseable records"):
        runner.run_graph(
            _config(zeek_dir=dns),
            kind="conn",
            inputs=inputs,  # type: ignore[arg-type]
            stream=io.StringIO(),
            quiet=True,
            show_progress=False,
        )


def test_graph_bare_config_keeps_source_provenance_at_runner_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bare CLI buckets do not turn a configured file into a trusted input."""
    dns = tmp_path / "dns.log"
    dns.write_text(_DNS_LINE, encoding="utf-8")
    _stub_config(monkeypatch, _config(zeek_dir=dns))
    seen: dict[str, object] = {}

    def _empty(_config: dict[str, Any], *, kind: str, inputs: object, **_kwargs: Any) -> None:
        seen[kind] = inputs
        raise GraphEmpty(kind, "dns.log", "no parseable records")

    monkeypatch.setattr(runner, "run_graph", _empty)

    assert cli._main(["graph", "-q"]) == 0
    assert seen == {"dns": None}


def test_graph_bare_config_file_requires_loader_discovery_before_clean_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """An arbitrary configured filename cannot become a falsely recognized no-op."""
    source = tmp_path / "captured"
    source.write_text(_CONN_LINE, encoding="utf-8")
    _stub_config(monkeypatch, _config(zeek_dir=source))

    assert cli._main(["graph", "-q"]) == 1
    captured = capsys.readouterr()

    assert "does not match conn*.log* discovery" in captured.err
    assert "pass it as a PATH" in captured.err
    assert "recognized captured" not in captured.err
    assert captured.err.rstrip().endswith("sigwood: nothing to graph")


def test_graph_malformed_config_path_is_an_actionable_cli_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """A non-string configured path stops at the public error boundary."""
    config = _config()
    config["sigwood"]["zeek_dir"] = 7
    _stub_config(monkeypatch, config)

    with pytest.raises(SystemExit) as stopped:
        cli.main(["graph"])

    captured = capsys.readouterr()
    assert stopped.value.code == 1
    assert "sigwood: configured path must be a string" in captured.err
    assert "traceback" not in captured.err.lower()


@pytest.mark.parametrize(
    ("toml", "message"),
    [
        ("sigwood = 7\n", "[sigwood] must be a table"),
        ("graph = 7\n", "[graph] must be a table"),
        ("[graph]\ndomain_level = []\n", "[graph].domain_level must be"),
    ],
)
def test_graph_toml_table_and_value_shapes_fail_at_the_cli_boundary(
    tmp_path: Path,
    toml: str,
    message: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """TOML structural mistakes receive one actionable CLI diagnostic."""
    config_file = tmp_path / "config.toml"
    config_file.write_text(toml, encoding="utf-8")

    with pytest.raises(SystemExit) as stopped:
        cli.main(["graph", f"--config={config_file}"])

    captured = capsys.readouterr()
    assert stopped.value.code == 1
    assert f"sigwood: {message}" in captured.err
    assert "traceback" not in captured.err.lower()


def test_run_graph_strips_surrogate_escaped_source_label_before_html_sink(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A filesystem-decoded invalid byte cannot survive into artifact script data."""
    surrogate_path = Path(os.fsdecode(b"/tmp/sigwood-graph-\x80"))
    frame = pd.DataFrame({
        "ts": [1779750000.0],
        "src": ["192.0.2.10"],
        "dst": ["198.51.100.20"],
        "port": [443],
        "proto": ["tcp"],
        "bytes": [1],
    })
    result = LoadResult(
        logs={"conn*.log*": frame}, record_counts={"conn*.log*": 1},
    )
    from sigwood.common import loader

    real_exists = Path.exists
    real_is_file = Path.is_file
    monkeypatch.setattr(
        Path, "exists",
        lambda path: True if path == surrogate_path else real_exists(path),
    )
    monkeypatch.setattr(
        Path, "is_file",
        lambda path: True if path == surrogate_path else real_is_file(path),
    )
    monkeypatch.setattr(
        runner, "resolve_graph_source",
        lambda *_args, **_kwargs: (graph_kind_spec("conn"), [surrogate_path]),
    )
    monkeypatch.setattr(loader, "resolve_load_windows", lambda *args, **kwargs: [])
    monkeypatch.setattr(loader, "load_required_logs", lambda *args, **kwargs: result)

    stream = io.StringIO()
    runner.run_graph(_config(), kind="conn", stream=stream, quiet=True)

    assert "\udc80" not in stream.getvalue()


def test_run_graph_sets_default_window_metadata_only_from_resolver_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A resolver-returned graph window survives into the saved player payload."""
    source = tmp_path / "trusted"
    source.write_text("placeholder\n", encoding="utf-8")
    frame = pd.DataFrame({
        "ts": [1779750000.0],
        "src": ["192.0.2.10"],
        "dst": ["198.51.100.20"],
        "port": [443],
        "proto": ["tcp"],
        "bytes": [1],
    })
    result = LoadResult(logs={"conn*.log*": frame}, record_counts={"conn*.log*": 1})
    from sigwood.common import loader

    window = LoadWindow("zeek_dir", None, timedelta(days=7), False)
    applied: list[tuple[object, ...]] = []
    monkeypatch.setattr(loader, "resolve_load_windows", lambda *args, **kwargs: [window])
    monkeypatch.setattr(loader, "load_required_logs", lambda *args, **kwargs: result)
    monkeypatch.setattr(
        loader, "apply_default_window",
        lambda *args, **kwargs: (applied.append(args), result)[1],
    )
    config = _config()
    config["sigwood"]["default_window"] = "7d"
    stream = io.StringIO()

    runner.run_graph(config, kind="conn", inputs=source, stream=stream, quiet=True)

    blob = stream.getvalue().split("const DATA = ", 1)[1].split(";</script>", 1)[0]
    assert json.loads(blob)["meta"]["default_window_note"] == default_window_advisory("7d")
    assert applied


def test_graph_date_dir_window_uses_exact_name_and_display_timezone(
    tmp_path: Path, pin_tz,
) -> None:
    source = tmp_path / "2026-05-25"
    source.mkdir()

    assert runner._graph_date_dir_window([source], use_utc=True) == (
        datetime(2026, 5, 25, 0, 0, 0, tzinfo=timezone.utc),
        datetime(2026, 5, 25, 23, 59, 59, tzinfo=timezone.utc),
    )

    pin_tz("Etc/GMT+6")
    assert runner._graph_date_dir_window([source], use_utc=False) == (
        datetime(2026, 5, 25, 6, 0, 0, tzinfo=timezone.utc),
        datetime(2026, 5, 26, 5, 59, 59, tzinfo=timezone.utc),
    )


def test_graph_date_dir_window_rejects_lookalikes_parent_layouts_and_probe_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    suffixed = tmp_path / "2026-05-25-TSVPRE"
    suffixed.mkdir()
    exact_parent = tmp_path / "2026-05-26"
    exact_parent.mkdir()
    (exact_parent / "2026-05-25").mkdir()
    exact_file = tmp_path / "2026-05-27"
    exact_file.write_text("placeholder\n", encoding="utf-8")

    assert runner._graph_date_dir_window([suffixed], use_utc=True) is None
    assert runner._graph_date_dir_window([exact_parent], use_utc=True) is None
    assert runner._graph_date_dir_window([exact_file], use_utc=True) is None
    assert runner._graph_date_dir_window([suffixed, exact_parent], use_utc=True) is None

    probe = tmp_path / "2026-05-28"
    probe.mkdir()
    monkeypatch.setattr(
        loader, "_zeek_date_subdirs",
        lambda _path: (_ for _ in ()).throw(OSError("probe denied")),
    )
    assert runner._graph_date_dir_window([probe], use_utc=True) is None


@pytest.mark.parametrize(
    ("kind", "filename", "line"),
    [
        ("conn", "conn.log", _CONN_LINE),
        ("dns", "dns.log", _DNS_LINE),
    ],
)
def test_run_graph_date_directory_filters_real_zeek_rows_for_every_graph_kind(
    tmp_path: Path,
    restore_display_utc,
    kind: str,
    filename: str,
    line: str,
) -> None:
    source = tmp_path / "2026-05-25"
    source.mkdir()
    earlier = line.replace("1779750000.0", "1779663600.0").replace(
        '"uid":"C1"', '"uid":"C0"',
    ).replace('"uid":"D1"', '"uid":"D0"')
    (source / filename).write_text(earlier + line, encoding="utf-8")
    config = _config()
    config["sigwood"]["default_window"] = "7d"
    stream = io.StringIO()

    runner.run_graph(
        config, kind=kind, inputs=source, stream=stream, quiet=True, use_utc=True,
    )

    blob = stream.getvalue().split("const DATA = ", 1)[1].split(";</script>", 1)[0]
    meta = json.loads(blob)["meta"]
    assert meta["rows"] == 1
    expected_note = (
        "windowed to 2026-05-25 (date-named directory) - "
        "pass --all or --since/--until to change"
    )
    if kind == "conn":
        expected_note += "; connections that began before that day are not shown"
    assert meta["default_window_note"] == expected_note


@pytest.mark.parametrize(
    ("default_window", "kwargs"),
    [
        ("all", {}),
        ("7d", {"load_all": True}),
        (
            "7d",
            {
                "since": datetime(2026, 5, 25, tzinfo=timezone.utc),
                "until": datetime(2026, 5, 25, 23, 59, 59, tzinfo=timezone.utc),
            },
        ),
    ],
)
def test_run_graph_date_directory_respects_window_opt_outs(
    tmp_path: Path,
    restore_display_utc,
    default_window: str,
    kwargs: dict[str, object],
) -> None:
    source = tmp_path / "2026-05-25"
    source.mkdir()
    (source / "conn.log").write_text(_CONN_LINE, encoding="utf-8")
    config = _config()
    config["sigwood"]["default_window"] = default_window
    stream = io.StringIO()

    runner.run_graph(
        config,
        kind="conn",
        inputs=source,
        stream=stream,
        quiet=True,
        use_utc=True,
        **kwargs,
    )

    blob = stream.getvalue().split("const DATA = ", 1)[1].split(";</script>", 1)[0]
    assert json.loads(blob)["meta"]["default_window_note"] is None


@pytest.mark.parametrize(
    ("kind", "filename", "line"),
    [
        ("conn", "conn.log", _CONN_LINE),
        ("dns", "dns.log", _DNS_LINE),
    ],
)
def test_run_graph_date_directory_empty_retries_the_full_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    restore_display_utc,
    kind: str,
    filename: str,
    line: str,
) -> None:
    source = tmp_path / "2026-05-25"
    source.mkdir()
    earlier = line.replace("1779750000.0", "1778972400.0")
    (source / filename).write_text(earlier, encoding="utf-8")
    config = _config()
    config["sigwood"]["default_window"] = "7d"
    stream = io.StringIO()
    module = __import__(f"sigwood.graph.{kind}", fromlist=["build"])
    actual_build = module.build
    seen_trim_flags: list[bool] = []

    def _capture(*args: object, **builder_kwargs: object) -> dict[str, Any]:
        seen_trim_flags.append(bool(builder_kwargs["trim_sparse_edges"]))
        return actual_build(*args, **builder_kwargs)

    monkeypatch.setattr(module, "build", _capture)

    runner.run_graph(
        config,
        kind=kind,
        inputs=source,
        stream=stream,
        quiet=True,
        use_utc=True,
    )

    payload = json.loads(
        stream.getvalue().split("const DATA = ", 1)[1].split(";</script>", 1)[0]
    )
    assert payload["meta"]["rows"] == 1
    assert payload["meta"]["default_window_note"] is None
    assert payload["meta"]["date_window_widened"] is True
    assert seen_trim_flags == [False]
    assert payload["meta"]["degrade_note"] == (
        f"date window held no {kind} rows that started that day; "
        "widened to the full archive"
    )


def test_run_graph_operator_empty_window_does_not_auto_widen(
    tmp_path: Path, restore_display_utc,
) -> None:
    source = tmp_path / "2026-05-25"
    source.mkdir()
    (source / "conn.log").write_text(_CONN_LINE, encoding="utf-8")

    with pytest.raises(GraphEmpty, match="no records in selected window"):
        runner.run_graph(
            _config(),
            kind="conn",
            inputs=source,
            since=datetime(2026, 6, 1, tzinfo=timezone.utc),
            until=datetime(2026, 6, 2, tzinfo=timezone.utc),
            stream=io.StringIO(),
            quiet=True,
            use_utc=True,
        )


def test_run_graph_warn_above_never_prompts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "conn.log"
    second_line = _CONN_LINE.replace('"uid":"C1"', '"uid":"C2"').replace(
        '"id.orig_h":"192.0.2.10"', '"id.orig_h":"192.0.2.11"',
    )
    source.write_text(_CONN_LINE + second_line, encoding="utf-8")
    config = _config()
    config["sigwood"]["warn_above"] = 1
    monkeypatch.setattr(
        "builtins.input",
        lambda *_args, **_kwargs: pytest.fail("graph must not prompt"),
    )

    runner.run_graph(
        config, kind="conn", inputs=source, stream=io.StringIO(), quiet=True,
    )


def test_run_graph_degrade_note_matches_quiet_gated_stderr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "conn.log"
    source.write_text(
        _CONN_LINE.replace('"orig_bytes":128', '"orig_bytes":1e308'),
        encoding="utf-8",
    )
    stream = io.StringIO()

    runner.run_graph(
        _config(), kind="conn", inputs=source, stream=stream,
        quiet=False, show_progress=False,
    )

    payload = json.loads(
        stream.getvalue().split("const DATA = ", 1)[1].split(";</script>", 1)[0]
    )
    note = payload["meta"]["degrade_note"]
    assert note == "scaled 1 metric cells to the render ceiling"
    assert capsys.readouterr().err.strip() == note


def test_run_graph_emits_stored_band_and_straddler_facts_on_separate_lines(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    restore_display_utc,
) -> None:
    source = tmp_path / "conn.log"
    source.write_text("placeholder\n", encoding="utf-8")
    dense_timestamps = [
        float(bin_index)
        for bin_index in range(6, 14)
        for _ in range(2_000)
    ]
    frame = pd.DataFrame({
        "ts": [0.0, *dense_timestamps],
        "src": ["192.0.2.250", *(["192.0.2.10"] * 16_000)],
        "dst": ["198.51.100.250", *(["198.51.100.10"] * 16_000)],
        "port": [443] * 16_001,
        "proto": ["tcp"] * 16_001,
        "bytes": [100, *([1] * 16_000)],
        "duration": [100, *([1] * 16_000)],
    })
    result = LoadResult(
        logs={"conn*.log*": frame}, record_counts={"conn*.log*": len(frame)},
    )
    monkeypatch.setattr(loader, "resolve_load_windows", lambda *args, **kwargs: [])
    monkeypatch.setattr(loader, "load_required_logs", lambda *args, **kwargs: result)
    config = _config()
    config["sigwood"]["default_window"] = "7d"
    stream = io.StringIO()

    runner.run_graph(
        config,
        kind="conn",
        inputs=source,
        stream=stream,
        quiet=False,
        show_progress=False,
        use_utc=True,
    )

    payload = json.loads(
        stream.getvalue().split("const DATA = ", 1)[1].split(";</script>", 1)[0]
    )
    lines = capsys.readouterr().err.strip().splitlines()
    assert payload["meta"]["degrade_note"] is None
    assert lines == [
        payload["meta"]["band_loss_note"],
        payload["meta"]["straddler_note"],
    ]


def test_run_graph_bounded_files_trim_sparse_edge_and_share_one_note(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    restore_display_utc,
) -> None:
    source = tmp_path / "conn.log"
    source.write_text("placeholder\n", encoding="utf-8")
    frame = _trim_candidate_conn_frame()
    result = LoadResult(
        logs={"conn*.log*": frame}, record_counts={"conn*.log*": len(frame)},
    )
    monkeypatch.setattr(loader, "resolve_load_windows", lambda *args, **kwargs: [])
    monkeypatch.setattr(loader, "load_required_logs", lambda *args, **kwargs: result)
    config = _config()
    config["sigwood"]["default_window"] = "7d"
    stream = io.StringIO()

    runner.run_graph(
        config,
        kind="conn",
        inputs=source,
        stream=stream,
        quiet=False,
        show_progress=False,
        use_utc=True,
    )

    payload = json.loads(
        stream.getvalue().split("const DATA = ", 1)[1].split(";</script>", 1)[0]
    )
    note = payload["meta"]["degrade_note"]
    assert payload["meta"]["rows"] == 16_000
    assert payload["meta"]["t0"] == 6.0
    assert payload["meta"]["trimmed_leading"] == 1
    assert note == (
        "trimmed 1 connection before the retained window to focus the timeline "
        "(window begins 1970-01-01 00:00 UTC)"
    )
    assert capsys.readouterr().err.strip() == note

    runner.run_graph(
        config,
        kind="conn",
        inputs=source,
        stream=io.StringIO(),
        quiet=True,
        show_progress=False,
        use_utc=True,
    )
    assert capsys.readouterr().err == ""


def test_run_graph_real_bounded_file_route_enables_density_trim(
    tmp_path: Path, restore_display_utc,
) -> None:
    base = 1_779_750_000.0
    tail = tmp_path / "conn.log.1"
    dense = tmp_path / "conn.log.2"

    def _record(ts: float, uid: str) -> str:
        return json.dumps({
            "_path": "conn",
            "ts": ts,
            "uid": uid,
            "id.orig_h": "192.0.2.10",
            "id.resp_h": "198.51.100.20",
            "id.resp_p": 443,
            "proto": "tcp",
            "duration": 1.0,
            "orig_bytes": 1,
        }) + "\n"

    tail.write_text(_record(base, "TAIL"), encoding="utf-8")
    dense.write_text(
        "".join(
            _record(base + bin_index, f"D{bin_index}-{row}")
            for bin_index in range(6, 14)
            for row in range(125)
        ),
        encoding="utf-8",
    )
    config = _config()
    config["sigwood"]["default_window"] = "7d"
    stream = io.StringIO()

    runner.run_graph(
        config,
        kind="conn",
        inputs=[tail, dense],
        stream=stream,
        quiet=True,
        show_progress=False,
        use_utc=True,
    )

    payload = json.loads(
        stream.getvalue().split("const DATA = ", 1)[1].split(";</script>", 1)[0]
    )
    assert payload["meta"]["rows"] == 1_000
    assert payload["meta"]["trimmed_leading"] == 1
    assert payload["meta"]["t0"] == base + 6
    assert payload["meta"]["default_window_note"] is None
    assert payload["meta"]["degrade_note"].startswith(
        "trimmed 1 connection before the retained window"
    )


def test_run_graph_resolver_window_prevents_a_second_density_trim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, restore_display_utc,
) -> None:
    source = tmp_path / "zeek"
    source.mkdir()
    (source / "conn.log").write_text("placeholder\n", encoding="utf-8")
    frame = _trim_candidate_conn_frame()
    result = LoadResult(
        logs={"conn*.log*": frame}, record_counts={"conn*.log*": len(frame)},
    )
    window = LoadWindow("zeek_dir", None, timedelta(days=7), False)
    monkeypatch.setattr(
        loader, "resolve_load_windows", lambda *args, **kwargs: [window],
    )
    monkeypatch.setattr(loader, "load_required_logs", lambda *args, **kwargs: result)
    monkeypatch.setattr(loader, "apply_default_window", lambda *args, **kwargs: result)
    config = _config()
    config["sigwood"]["default_window"] = "7d"
    stream = io.StringIO()

    runner.run_graph(
        config, kind="conn", inputs=source, stream=stream, quiet=True,
    )

    payload = json.loads(
        stream.getvalue().split("const DATA = ", 1)[1].split(";</script>", 1)[0]
    )
    assert payload["meta"]["rows"] == 16_001
    assert payload["meta"]["trimmed_leading"] == 0
    assert payload["meta"]["degrade_note"] is None
    assert payload["meta"]["default_window_note"] == default_window_advisory("7d")


@pytest.mark.parametrize(
    ("default_window", "kwargs", "expected"),
    [
        ("7d", {}, True),
        ("all", {}, False),
        ("7d", {"load_all": True}, False),
        (
            "7d",
            {"since": datetime(2026, 1, 1, tzinfo=timezone.utc)},
            False,
        ),
        (
            "7d",
            {"until": datetime(2026, 1, 2, tzinfo=timezone.utc)},
            False,
        ),
    ],
)
def test_run_graph_threads_tail_trim_from_original_operator_intent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    default_window: str,
    kwargs: dict[str, object],
    expected: bool,
) -> None:
    source = tmp_path / "conn.log"
    source.write_text("placeholder\n", encoding="utf-8")
    frame = pd.DataFrame({
        "ts": [1.0],
        "src": ["192.0.2.10"],
        "dst": ["198.51.100.10"],
        "port": [443],
        "proto": ["tcp"],
        "bytes": [1],
    })
    result = LoadResult(logs={"conn*.log*": frame}, record_counts={"conn*.log*": 1})
    monkeypatch.setattr(loader, "resolve_load_windows", lambda *args, **kwargs: [])
    monkeypatch.setattr(loader, "load_required_logs", lambda *args, **kwargs: result)

    from sigwood.graph import conn as conn_graph

    actual_build = conn_graph.build
    seen: list[bool] = []

    def _capture(*args: object, **builder_kwargs: object) -> dict[str, Any]:
        seen.append(bool(builder_kwargs["trim_sparse_edges"]))
        return actual_build(*args, **builder_kwargs)

    monkeypatch.setattr(conn_graph, "build", _capture)
    config = _config()
    config["sigwood"]["default_window"] = default_window

    runner.run_graph(
        config, kind="conn", inputs=source, stream=io.StringIO(), quiet=True,
        **kwargs,
    )

    assert seen == [expected]


def test_run_graph_dns_smooth_breach_sets_radius_only_degrade_note(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "dns.log"
    source.write_text("placeholder\n", encoding="utf-8")
    flow_count = 636
    frame = pd.DataFrame({
        "ts": [0.0 if index % 2 == 0 else 86_340.0 for index in range(flow_count)],
        "src": [f"192.0.2.{index % 30 + 1}" for index in range(flow_count)],
        "query": [f"d{index // 30}.test" for index in range(flow_count)],
        "qtype": [1] * flow_count,
    })
    result = LoadResult(
        logs={"dns*.log*": frame}, record_counts={"dns*.log*": flow_count},
    )
    from sigwood.common import loader

    monkeypatch.setattr(loader, "load_required_logs", lambda *args, **kwargs: result)
    stream = io.StringIO()

    runner.run_graph(
        _config(), kind="dns", inputs=source, stream=stream,
        quiet=False, show_progress=False,
    )

    payload = json.loads(
        stream.getvalue().split("const DATA = ", 1)[1].split(";</script>", 1)[0]
    )
    assert len(payload["flows"]) == flow_count
    assert payload["meta"]["bins"] == 1_440
    assert payload["meta"]["bin_seconds"] == 60
    assert payload["meta"]["max_radius"] == 108
    assert payload["meta"]["degrade_note"] == (
        "capped max smoothing to +/-108 bins to stay interactive"
    )
    assert capsys.readouterr().err.strip() == payload["meta"]["degrade_note"]


def test_run_graph_pihole_resolves_bounded_file_and_keeps_explicit_timeframe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pi-hole enters the universal resolver; bounded/explicit gates remain owned."""
    source = tmp_path / "pihole.log"
    source.write_text("placeholder\n", encoding="utf-8")
    frame = pd.DataFrame({
        "ts": [1779750000.0],
        "src": ["192.0.2.10"],
        "query": ["portal.example.com"],
        "event_type": ["query"],
    })
    result = LoadResult(
        logs={"pihole*.log*": frame}, record_counts={"pihole*.log*": 1},
    )
    real_resolve = loader.resolve_load_windows
    resolved: list[list[LoadWindow]] = []
    calls: list[tuple[object, ...]] = []

    def _resolve(*args: object, **kwargs: object) -> list[LoadWindow]:
        windows = real_resolve(*args, **kwargs)
        resolved.append(windows)
        return windows

    def _load(*args: object, **_kwargs: object) -> LoadResult:
        calls.append(args)
        return result

    monkeypatch.setattr(loader, "resolve_load_windows", _resolve)
    monkeypatch.setattr(loader, "load_required_logs", _load)
    config = _config()
    config["sigwood"]["default_window"] = "7d"

    stream = io.StringIO()
    runner.run_graph(config, kind="pihole", inputs=source, stream=stream, quiet=True)
    first = json.loads(stream.getvalue().split("const DATA = ", 1)[1].split(
        ";</script>", 1,
    )[0])
    assert first["meta"]["default_window_note"] is None
    assert resolved == [[]]
    assert calls[0][2:4] == (None, None)

    since = datetime(2026, 1, 1, tzinfo=timezone.utc)
    until = datetime(2026, 1, 2, tzinfo=timezone.utc)
    runner.run_graph(
        config,
        kind="pihole",
        inputs=source,
        since=since,
        until=until,
        stream=io.StringIO(),
        quiet=True,
    )
    assert resolved == [[], []]
    assert calls[1][2:4] == (since, until)


def test_run_graph_pihole_directory_uses_default_window_with_real_loader(
    tmp_path: Path, pin_tz, restore_display_utc,
) -> None:
    """A bare Pi-hole archive is disclosed and precisely trimmed by its own data."""
    pin_tz("UTC")
    source = _pihole_rotation_directory(tmp_path)
    config = _config()
    config["sigwood"]["default_window"] = "1d"
    stream = io.StringIO()

    runner.run_graph(
        config,
        kind="pihole",
        inputs=source,
        stream=stream,
        quiet=True,
        use_utc=True,
    )

    payload = json.loads(
        stream.getvalue().split("const DATA = ", 1)[1].split(";</script>", 1)[0]
    )
    assert payload["meta"]["default_window_note"] == default_window_advisory("1d")
    assert payload["meta"]["rows"] == 1
    assert [node["id"] for node in payload["dstNodes"]] == ["recent.example.test"]


def test_run_graph_pihole_floor_routes_to_file_selection_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A conservative flat floor prunes files but never row-filters."""
    source = tmp_path / "pihole"
    source.mkdir()
    (source / "pihole.log").write_text("placeholder\n", encoding="utf-8")
    floor = datetime(2026, 7, 19, tzinfo=timezone.utc)
    span = timedelta(days=1)
    window = LoadWindow("pihole_dir", (floor, None), span, True)
    frame = pd.DataFrame({
        "ts": [floor.timestamp() + 1],
        "src": ["192.0.2.20"],
        "query": ["recent.example.test"],
        "event_type": ["query"],
    })
    result = LoadResult(
        logs={"pihole*.log*": frame},
        record_counts={"pihole*.log*": 1},
    )
    observed: dict[str, object] = {"resolved": False}

    def _resolve(*_args: object, **_kwargs: object) -> list[LoadWindow]:
        observed["resolved"] = True
        return [window]

    def _load(*_args: object, **kwargs: object) -> LoadResult:
        observed["source_windows"] = kwargs.get("source_windows")
        observed["file_select_windows"] = kwargs.get("file_select_windows")
        return result

    def _apply(
        actual: LoadResult,
        patterns: list[str],
        actual_span: timedelta,
        *,
        keep_null: bool,
    ) -> LoadResult:
        observed["apply"] = (actual, patterns, actual_span, keep_null)
        return result

    monkeypatch.setattr(loader, "resolve_load_windows", _resolve)
    monkeypatch.setattr(loader, "load_required_logs", _load)
    monkeypatch.setattr(loader, "apply_default_window", _apply)
    config = _config()
    config["sigwood"]["default_window"] = "1d"

    runner.run_graph(
        config, kind="pihole", inputs=source, stream=io.StringIO(), quiet=True,
    )

    assert observed["resolved"] is True
    assert observed["source_windows"] is None
    assert observed["file_select_windows"] == {
        "pihole_dir": (floor, None),
    }
    assert observed["apply"] == (
        result, ["pihole*.log*"], span, True,
    )


def test_run_graph_pihole_unpeekable_default_loads_full_then_trims(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unpeekable flat default carries no selection map but still trims."""
    source = tmp_path / "pihole"
    source.mkdir()
    (source / "pihole.log").write_text("placeholder\n", encoding="utf-8")
    span = timedelta(days=1)
    window = LoadWindow("pihole_dir", None, span, True)
    frame = pd.DataFrame({
        "ts": [1779750000.0],
        "src": ["192.0.2.20"],
        "query": ["recent.example.test"],
        "event_type": ["query"],
    })
    result = LoadResult(
        logs={"pihole*.log*": frame},
        record_counts={"pihole*.log*": 1},
    )
    observed: dict[str, object] = {}

    monkeypatch.setattr(
        loader, "resolve_load_windows", lambda *_a, **_kw: [window],
    )

    def _load(*_args: object, **kwargs: object) -> LoadResult:
        observed["source_windows"] = kwargs.get("source_windows")
        observed["file_select_windows"] = kwargs.get("file_select_windows")
        return result

    def _apply(
        actual: LoadResult,
        patterns: list[str],
        actual_span: timedelta,
        *,
        keep_null: bool,
    ) -> LoadResult:
        observed["apply"] = (actual, patterns, actual_span, keep_null)
        return result

    monkeypatch.setattr(loader, "load_required_logs", _load)
    monkeypatch.setattr(loader, "apply_default_window", _apply)
    config = _config()
    config["sigwood"]["default_window"] = "1d"

    runner.run_graph(
        config, kind="pihole", inputs=source, stream=io.StringIO(), quiet=True,
    )

    assert observed["source_windows"] is None
    assert observed["file_select_windows"] is None
    assert observed["apply"] == (
        result, ["pihole*.log*"], span, True,
    )


@pytest.mark.parametrize(
    ("default_window", "mode", "expected_rows"),
    [
        ("all", "default", 3),
        ("1d", "all", 3),
        ("1d", "explicit", 2),
    ],
)
def test_run_graph_pihole_directory_respects_window_opt_outs(
    tmp_path: Path,
    pin_tz,
    restore_display_utc,
    default_window: str,
    mode: str,
    expected_rows: int,
) -> None:
    """Disabled, --all, and explicit windows retain their existing semantics."""
    pin_tz("UTC")
    source = _pihole_rotation_directory(tmp_path)
    config = _config()
    config["sigwood"]["default_window"] = default_window
    stream = io.StringIO()
    kwargs: dict[str, object] = {}
    if mode == "all":
        kwargs["load_all"] = True
    elif mode == "explicit":
        recent = loader._peek_first_ts(source / "pihole.log")
        straddler = loader._peek_first_ts(source / "pihole.log.1")
        assert recent is not None and straddler is not None
        kwargs.update({
            "since": straddler - timedelta(hours=1),
            "until": recent + timedelta(hours=1),
        })

    runner.run_graph(
        config,
        kind="pihole",
        inputs=source,
        stream=stream,
        quiet=True,
        use_utc=True,
        **kwargs,
    )

    payload = json.loads(
        stream.getvalue().split("const DATA = ", 1)[1].split(";</script>", 1)[0]
    )
    assert payload["meta"]["default_window_note"] is None
    assert payload["meta"]["rows"] == expected_rows


def test_run_graph_windowed_pihole_directory_disables_density_trim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A resolver window remains the only automatic trim act for Pi-hole dirs."""
    source = tmp_path / "pihole"
    source.mkdir()
    (source / "pihole.log").write_text("placeholder\n", encoding="utf-8")
    frame = pd.DataFrame({
        "ts": [1779750000.0],
        "src": ["192.0.2.20"],
        "query": ["recent.example.test"],
        "event_type": ["query"],
    })
    result = LoadResult(
        logs={"pihole*.log*": frame},
        record_counts={"pihole*.log*": 1},
    )
    window = LoadWindow(
        "pihole_dir",
        (datetime(2026, 5, 20, tzinfo=timezone.utc), None),
        timedelta(days=1),
        True,
    )
    monkeypatch.setattr(
        loader, "resolve_load_windows", lambda *_a, **_kw: [window],
    )
    monkeypatch.setattr(loader, "load_required_logs", lambda *_a, **_kw: result)
    monkeypatch.setattr(loader, "apply_default_window", lambda *_a, **_kw: result)
    module = __import__("sigwood.graph.pihole", fromlist=["build"])
    actual_build = module.build
    trim_flags: list[bool] = []

    def _capture(*args: object, **kwargs: object) -> dict[str, Any]:
        trim_flags.append(bool(kwargs["trim_sparse_edges"]))
        return actual_build(*args, **kwargs)

    monkeypatch.setattr(module, "build", _capture)
    config = _config()
    config["sigwood"]["default_window"] = "1d"

    runner.run_graph(
        config, kind="pihole", inputs=source, stream=io.StringIO(), quiet=True,
    )

    assert trim_flags == [False]


def test_run_graph_pihole_file_stays_bounded_and_unwindowed(
    tmp_path: Path, pin_tz, restore_display_utc,
) -> None:
    """An explicitly named Pi-hole file keeps every row and gets no default note."""
    pin_tz("UTC")
    source = tmp_path / "pihole.log"
    source.write_text(
        "Jul 20 12:00:00 dnsmasq[1]: query[A] "
        "recent.example.test from 192.0.2.20\n"
        "Jul 15 12:00:00 dnsmasq[1]: query[A] "
        "old.example.test from 192.0.2.15\n",
        encoding="utf-8",
    )
    config = _config()
    config["sigwood"]["default_window"] = "1d"
    stream = io.StringIO()

    runner.run_graph(
        config,
        kind="pihole",
        inputs=source,
        stream=stream,
        quiet=True,
        use_utc=True,
    )

    payload = json.loads(
        stream.getvalue().split("const DATA = ", 1)[1].split(";</script>", 1)[0]
    )
    assert payload["meta"]["default_window_note"] is None
    assert payload["meta"]["rows"] == 2


def test_run_graph_pihole_rotation_fallback_is_exact_and_quiet_gated(
    tmp_path: Path,
    pin_tz,
    restore_display_utc,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Fallback reasons reuse the shared safe stderr line and honor quiet."""
    pin_tz("UTC")
    source = tmp_path / "pihole"
    source.mkdir()
    line = (
        "Jul 20 12:00:00 dnsmasq[1]: query[A] "
        "recent.example.test from 192.0.2.20\n"
    )
    (source / "pihole.log").write_text(line, encoding="utf-8")
    with gzip.open(source / "pihole.log.gz", "wt", encoding="utf-8") as handle:
        handle.write(line)
    config = _config()
    config["sigwood"]["default_window"] = "1d"
    expected = (
        "Pi-hole: duplicate rotation files - read the full archive "
        "(windowing skipped; duplicate rows may be counted twice)"
    )

    runner.run_graph(
        config,
        kind="pihole",
        inputs=source,
        stream=io.StringIO(),
        quiet=False,
        show_progress=False,
        use_utc=True,
    )
    assert capsys.readouterr().err.strip() == expected

    runner.run_graph(
        config,
        kind="pihole",
        inputs=source,
        stream=io.StringIO(),
        quiet=True,
        show_progress=False,
        use_utc=True,
    )
    assert capsys.readouterr().err == ""


def test_run_graph_pihole_normal_rotation_prune_has_no_stderr_disclosure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pin_tz,
    restore_display_utc,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Ordinary pruning remains represented by the window, not live narration."""
    pin_tz("UTC")
    source = _pihole_rotation_directory(tmp_path)
    config = _config()
    config["sigwood"]["default_window"] = "1d"
    real_load = loader.load_required_logs
    observed_skips = []

    def _load(*args: object, **kwargs: object) -> LoadResult:
        result = real_load(*args, **kwargs)
        observed_skips.append(result.rotation_skips["pihole*.log*"])
        return result

    monkeypatch.setattr(loader, "load_required_logs", _load)

    runner.run_graph(
        config,
        kind="pihole",
        inputs=source,
        stream=io.StringIO(),
        quiet=False,
        show_progress=False,
        use_utc=True,
    )

    assert len(observed_skips) == 1
    assert observed_skips[0].skipped > 0
    assert observed_skips[0].fallback is False
    assert capsys.readouterr().err == ""


def test_run_graph_windowed_pihole_empty_names_selected_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A resolver-selected Pi-hole window keeps the generalized empty wording."""
    source = tmp_path / "pihole"
    source.mkdir()
    (source / "pihole.log").write_text("placeholder\n", encoding="utf-8")
    frame = pd.DataFrame({
        "ts": [1779750000.0],
        "src": ["192.0.2.20"],
        "query": ["recent.example.test"],
        "event_type": ["query"],
    })
    loaded = LoadResult(
        logs={"pihole*.log*": frame},
        record_counts={"pihole*.log*": 1},
    )
    empty = LoadResult(
        logs={"pihole*.log*": frame.iloc[0:0]},
        record_counts={},
    )
    monkeypatch.setattr(
        loader,
        "resolve_load_windows",
        lambda *_a, **_kw: [
            LoadWindow("pihole_dir", None, timedelta(days=1), True),
        ],
    )
    monkeypatch.setattr(loader, "load_required_logs", lambda *_a, **_kw: loaded)
    monkeypatch.setattr(loader, "apply_default_window", lambda *_a, **_kw: empty)
    config = _config()
    config["sigwood"]["default_window"] = "1d"

    with pytest.raises(GraphEmpty, match="no records in selected window"):
        runner.run_graph(
            config, kind="pihole", inputs=source, stream=io.StringIO(), quiet=True,
        )
