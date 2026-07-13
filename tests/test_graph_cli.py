"""CLI and runner integration coverage for self-contained graph artifacts."""

from __future__ import annotations

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
from sigwood.common.display import default_window_advisory
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
    assert "__SIGWOOD_GRAPH_DATA__" not in html


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
        (('"orig_bytes":128', '"orig_bytes":1e308'), 1, "metric values are too large", False),
    ],
)
def test_graph_real_loader_contains_hostile_finite_numbers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    replacement: tuple[str, str],
    expected_rc: int,
    expected_message: str,
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
    assert expected_message in captured.err
    assert "traceback" not in captured.err.lower()
    assert target.exists() is expected_artifact


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


def test_run_graph_pihole_skips_implicit_window_but_keeps_explicit_timeframe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pihole follows the full-load default with explicit windows still passed on."""
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
    from sigwood.common import loader

    def _no_default(*_args: object, **_kwargs: object) -> None:
        pytest.fail("pihole must not resolve an implicit graph window")

    calls: list[tuple[object, ...]] = []

    def _load(*args: object, **_kwargs: object) -> LoadResult:
        calls.append(args)
        return result

    monkeypatch.setattr(loader, "resolve_load_windows", _no_default)
    monkeypatch.setattr(loader, "load_required_logs", _load)
    config = _config()
    config["sigwood"]["default_window"] = "7d"

    stream = io.StringIO()
    runner.run_graph(config, kind="pihole", inputs=source, stream=stream, quiet=True)
    first = json.loads(stream.getvalue().split("const DATA = ", 1)[1].split(
        ";</script>", 1,
    )[0])
    assert first["meta"]["default_window_note"] is None
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
    assert calls[1][2:4] == (since, until)
