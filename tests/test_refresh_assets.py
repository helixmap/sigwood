from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import struct
import sys
from typing import Mapping, Sequence
import zlib

import pytest


_TOOL = Path(__file__).resolve().parents[1] / "tools" / "refresh_assets.py"
_SPEC = importlib.util.spec_from_file_location("sigwood_refresh_assets", _TOOL)
assert _SPEC is not None and _SPEC.loader is not None
refresh_assets = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = refresh_assets
_SPEC.loader.exec_module(refresh_assets)


def _chunk(kind: bytes, payload: bytes) -> bytes:
    crc = zlib.crc32(kind + payload) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", crc)


def _png(width: int = 2220, height: int = 1800) -> bytes:
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr) + _chunk(b"IEND", b"")


def _gif(width: int = 760, height: int = 788) -> bytes:
    header = b"GIF89a" + struct.pack("<HHBBB", width, height, 0x80, 0, 0)
    palette = b"\x00\x00\x00\xff\xff\xff"
    loop = b"!\xff\x0bNETSCAPE2.0\x03\x01\x00\x00\x00"
    control = b"!\xf9\x04\x00\x08\x00\x00\x00"
    descriptor = b",\x00\x00\x00\x00\x01\x00\x01\x00\x00"
    first = descriptor + b"\x02\x02\x44\x01\x00"
    second = descriptor + b"\x02\x02\x4c\x01\x00"
    return header + palette + loop + control + first + control + second + b";"


def _report_html(
    label: str = "alpha",
    command: str = (
        "sigwood hunt -q --config=demo/sigwood.toml "
        "--format=html --out=report.html"
    ),
) -> str:
    return (
        "<html><head><title>sigwood</title>"
        "<style>@media (prefers-color-scheme: dark) {}</style></head><body>"
        '<span class="meta-label">as</span><span class="meta-value">'
        f"{command}</span>"
        '<table class="summary findings-table dense">'
        f"<tr><th> method </th><th>finding</th></tr>"
        f"<tr><td> dns </td><td>{label}   host</td></tr>"
        "</table></body></html>"
    )


class FakeRunner:
    def __init__(self, *, label: str = "alpha") -> None:
        self.label = label
        self.calls: list[tuple[list[str], Path, dict[str, str], float]] = []

    def __call__(
        self,
        argv: Sequence[str],
        cwd: Path,
        env: Mapping[str, str],
        timeout: float,
    ) -> object:
        args = list(argv)
        self.calls.append((args, cwd, dict(env), timeout))
        if str(refresh_assets.CORPUS_GENERATOR) in args:
            target = Path(args[2])
            for name in ("zeek", "syslog", "pihole"):
                (target / name).mkdir(parents=True, exist_ok=True)
            return refresh_assets.RunResult(0)
        out = next((item.split("=", 1)[1] for item in args if item.startswith("--out=")), None)
        if out is not None:
            output = Path(out)
            if not output.is_absolute():
                output = cwd / output
            command = " ".join([Path(args[0]).name, *args[1:]])
            output.write_text(_report_html(self.label, command), encoding="utf-8")
            return refresh_assets.RunResult(0)
        command = next((item for item in args if item in ("digest", "hunt")), "")
        if command == "digest":
            return refresh_assets.RunResult(
                0,
                "generated: 2026-08-29\n  wrapped stamp\nDIGEST stable\n",
            )
        if command == "hunt":
            return refresh_assets.RunResult(0, "as: local time\nHUNT stable\n")
        return refresh_assets.RunResult(0)


def test_report_oracle_uses_all_findings_rows_in_document_order() -> None:
    html = (
        '<table class="findings-table"><tr><td> one\n two </td><td>A</td></tr></table>'
        '<table class="x findings-table y"><tr><th>B</th><th> three   four </th></tr></table>'
    )
    canonical = "one two\x1fA\nB\x1fthree four"
    import hashlib
    assert refresh_assets.report_oracle(html) == hashlib.sha256(canonical.encode()).hexdigest()


def test_demo_oracle_drops_banner_rows_and_wrapped_continuations() -> None:
    first = "generated: today\n  at some path\nkept one\n"
    second = "\x1b[32mas: local\x1b[0m\n    wrapped\nkept two\n"
    import hashlib
    expected = hashlib.sha256("kept one\nkept two".encode()).hexdigest()
    assert refresh_assets.demo_oracle((first, second)) == expected


def test_build_sandbox_is_single_config_owner_without_pihole(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(refresh_assets, "find_sigwood", lambda: Path("/opt/sigwood/bin/sigwood"))
    runner = FakeRunner()
    home = refresh_assets.build_sandbox(tmp_path, runner)
    config = (home / ".sigwood" / "config.toml").read_text()
    assert 'zeek_dir = "~/zeek"' in config
    assert 'syslog_dir = "~/syslog"' in config
    assert "pihole" not in config
    assert (home / "zeek").is_dir()
    assert (home / "syslog").is_dir()
    assert (home / ".castrc").is_file()
    assert all(call[2]["TZ"] == "UTC" for call in runner.calls)


def test_report_copies_tracked_config_and_runs_relative_from_isolated_workdir(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(refresh_assets, "find_sigwood", lambda: Path("/opt/sigwood/bin/sigwood"))
    runner = FakeRunner()
    html, digest = refresh_assets.generate_report_html(tmp_path, runner)
    hunt = next(call for call in runner.calls if "--format=html" in call[0])
    assert hunt[1] == tmp_path / "report"
    assert "--config=demo/sigwood.toml" in hunt[0]
    assert "--out=report.html" in hunt[0]
    assert not any(str(tmp_path) in item for item in hunt[0])
    assert (
        tmp_path / "report" / "demo" / "sigwood.toml"
    ).read_bytes() == refresh_assets.DEMO_CONFIG.read_bytes()
    assert (tmp_path / "report" / "demo" / "corpus" / "syslog").is_dir()
    printable = refresh_assets._prepare_print_html(html)
    assert (
        "sigwood hunt -q --config=demo/sigwood.toml "
        "--format=html --out=report.html"
    ) in printable
    assert str(tmp_path) not in printable
    assert digest == refresh_assets.report_oracle(html)


def test_report_root_is_private_even_when_created_with_permissive_mode(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(refresh_assets, "find_sigwood", lambda: Path("/opt/sigwood/bin/sigwood"))
    report_root = tmp_path / "report"
    report_root.mkdir()
    report_root.chmod(0o755)

    refresh_assets.generate_report_html(tmp_path, FakeRunner())

    assert report_root.stat().st_mode & 0o777 == 0o700


def test_report_config_cannot_escape_to_checkout_corpus(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(refresh_assets, "find_sigwood", lambda: Path("/opt/sigwood/bin/sigwood"))

    def no_corpus_runner(
        argv: Sequence[str], cwd: Path, env: Mapping[str, str], timeout: float
    ) -> object:
        args = list(argv)
        if str(refresh_assets.CORPUS_GENERATOR) in args:
            return refresh_assets.RunResult(0)
        if "--config=demo/sigwood.toml" not in args or "--out=report.html" not in args:
            return refresh_assets.RunResult(0)
        assert not (cwd / "demo" / "corpus" / "zeek").exists()
        return refresh_assets.RunResult(
            1,
            stderr="zeek_dir demo/corpus/zeek not found - skipping detectors: beacon, exfil",
        )

    with pytest.raises(refresh_assets.AssetError, match="zeek_dir demo/corpus/zeek not found"):
        refresh_assets.generate_report_html(tmp_path, no_corpus_runner)


def test_hostile_inherited_timezone_is_replaced_for_both_oracles(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("TZ", "Pacific/Honolulu")
    monkeypatch.setenv("SIGWOOD_ROOT", "/hostile/root")
    monkeypatch.setattr(refresh_assets, "find_sigwood", lambda: Path("/opt/sigwood/bin/sigwood"))
    runner = FakeRunner()
    refresh_assets.generate_report_html(tmp_path, runner)
    home = refresh_assets.build_sandbox(tmp_path, runner)
    refresh_assets.generate_demo_oracle(home, runner)
    assert all(call[2]["TZ"] == "UTC" for call in runner.calls)
    assert all("SIGWOOD_ROOT" not in call[2] for call in runner.calls)


def test_recording_env_overrides_hostile_terminal_color_controls(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("TERM", "dumb")
    monkeypatch.setenv("COLORTERM", "")
    monkeypatch.setattr(refresh_assets, "find_sigwood", lambda: Path("/opt/sigwood/bin/sigwood"))
    env = refresh_assets.recording_env(tmp_path)
    assert "NO_COLOR" not in env
    assert env["TERM"] == "xterm-256color"
    assert env["COLORTERM"] == "truecolor"


def test_pihole_only_perturbation_does_not_change_demo_hash(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(refresh_assets, "find_sigwood", lambda: Path("/opt/sigwood/bin/sigwood"))
    runner = FakeRunner()
    home = refresh_assets.build_sandbox(tmp_path, runner)
    before = refresh_assets.generate_demo_oracle(home, runner)
    (home / "pihole" / "pihole.log").write_text("changed only here", encoding="utf-8")
    after = refresh_assets.generate_demo_oracle(home, runner)
    assert after == before


def test_pty_rows_are_derived_to_hold_command_whole_hunt_and_prompt() -> None:
    hunt = "\n".join(["x" * 121, *(["y"] * 44)]) + "\n"
    # The long row wraps twice, plus 44 ordinary rows, command echo, and prompt.
    assert refresh_assets.derive_pty_rows(hunt, cols=120) == 48


def test_explicit_invalid_browser_is_authoritative_and_never_falls_back(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(refresh_assets.shutil, "which", lambda name: "/fallback/chrome")
    assert refresh_assets.find_browser(str(tmp_path / "missing")) is None


def test_print_report_preserves_the_true_relative_command_row() -> None:
    html = (
        "<html><style>@media (prefers-color-scheme: dark) {}</style><body>"
        '<span class="meta-label">as</span><span class="meta-value">'
        "sigwood hunt -q --config=demo/sigwood.toml "
        "--format=html --out=report.html"
        "</span></body></html>"
    )
    printable = refresh_assets._prepare_print_html(html)
    command = (
        "sigwood hunt -q --config=demo/sigwood.toml "
        "--format=html --out=report.html"
    )
    assert printable.count(command) == 1


def test_hidden_path_reports_each_optional_demo_tool_missing(monkeypatch) -> None:
    monkeypatch.setattr(refresh_assets.shutil, "which", lambda name: None)
    assert refresh_assets.find_optional_tool("asciinema") is None
    assert refresh_assets.find_optional_tool("termsvg") is None


@pytest.mark.parametrize(
    "mutator, message",
    [
        (lambda data: data[:-1], "truncated"),
        (lambda data: data + b"junk", "trailing bytes"),
        (lambda data: data[:29] + bytes([data[29] ^ 1]) + data[30:], "CRC"),
    ],
)
def test_png_structure_rejects_corruption(mutator, message: str) -> None:
    with pytest.raises(refresh_assets.AssetError, match=message):
        refresh_assets.validate_png(
            mutator(_png()), expected_width=2220, expected_height=1800
        )


def test_png_structure_rejects_wrong_dimensions() -> None:
    with pytest.raises(refresh_assets.AssetError, match="dimensions"):
        refresh_assets.validate_png(_png(1110, 900), expected_width=2220, expected_height=1800)


def test_png_structure_accepts_exact_dimensions_and_terminal_iend() -> None:
    refresh_assets.validate_png(_png(), expected_width=2220, expected_height=1800)


def test_svg_theme_maps_color_values_and_plays_once() -> None:
    source = (
        '<svg fill="#282D35"><style>'
        ".a{fill:#C0C0C0}.b{fill:#FF00FF}.c{fill:#008080}.d{fill:#00FFFF}"
        "text{font-family:Monaco,Consolas,'Courier New',monospace}"
        ".k{animation:k 12.5s infinite steps(1,end)}"
        "</style></svg>"
    )
    themed = refresh_assets.theme_demo_svg(source)
    assert "fill:#00FFFF" in themed
    assert "fill:#ff9800" in themed
    assert "animation:k 12.5s steps(1,end);animation-fill-mode:forwards" in themed
    assert "infinite" not in themed


def test_selected_assets_are_not_promoted_if_a_later_renderer_fails(
    tmp_path: Path, monkeypatch
) -> None:
    writes: list[tuple[Path, bytes]] = []
    monkeypatch.setattr(
        refresh_assets,
        "load_stamps",
        lambda: {"schema_version": 1, "tz": "UTC"},
    )
    monkeypatch.setattr(refresh_assets, "build_sandbox", lambda work, runner: tmp_path)
    monkeypatch.setattr(
        refresh_assets,
        "generate_report_html",
        lambda work, runner: (_report_html(), "a" * 64),
    )
    monkeypatch.setattr(refresh_assets, "find_browser", lambda explicit: Path("/browser"))
    monkeypatch.setattr(
        refresh_assets,
        "render_report_png",
        lambda html, work, browser, runner: b"report candidate",
    )
    monkeypatch.setattr(
        refresh_assets, "generate_demo_state", lambda home, runner: ("b" * 64, 57)
    )
    monkeypatch.setattr(refresh_assets, "find_optional_tool", lambda name: Path("/" + name))
    monkeypatch.setattr(
        refresh_assets,
        "render_demo_svg",
        lambda *args: (_ for _ in ()).throw(refresh_assets.AssetError("bad demo")),
    )
    monkeypatch.setattr(
        refresh_assets, "atomic_write", lambda path, data: writes.append((path, data))
    )
    with pytest.raises(refresh_assets.AssetError, match="bad demo"):
        refresh_assets.refresh_assets(("report", "demo"), browser_arg=None)
    assert writes == []


def test_unknown_stamp_schema_is_a_hard_failure(tmp_path: Path) -> None:
    stamp = tmp_path / "stamp.json"
    stamp.write_text('{"schema_version": 2, "tz": "UTC"}', encoding="utf-8")
    with pytest.raises(refresh_assets.AssetError, match="unknown"):
        refresh_assets.load_stamps(stamp)


def test_check_mode_is_fast_renderer_free_and_detects_stale_input(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(refresh_assets, "find_sigwood", lambda: Path("/opt/sigwood/bin/sigwood"))
    monkeypatch.setattr(refresh_assets, "REPORT_ASSET", tmp_path / "report.png")
    monkeypatch.setattr(refresh_assets, "DEMO_ASSET", tmp_path / "demo.svg")
    monkeypatch.setattr(refresh_assets, "STAMP_PATH", tmp_path / "assets.stamp.json")
    refresh_assets.REPORT_ASSET.write_bytes(b"asset")
    refresh_assets.DEMO_ASSET.write_text("asset", encoding="utf-8")
    runner = FakeRunner()
    report_hash = refresh_assets.report_oracle(_report_html())
    demo_hash = refresh_assets.demo_oracle(
        (
            "generated: 2026-08-29\n  wrapped stamp\nDIGEST stable\n",
            "as: local time\nHUNT stable\n",
        )
    )
    refresh_assets.write_stamps(
        {
            "schema_version": 1,
            "tz": "UTC",
            "report_png": {"oracle": "finding-rows/sha256", "hash": report_hash},
            "demo_svg": {"oracle": "text-output/sha256", "hash": demo_hash},
        }
    )
    assert refresh_assets.check_assets(("report", "demo"), runner) == []
    assert not any("chrome" in " ".join(call[0]).lower() for call in runner.calls)
    runner.label = "changed"
    assert refresh_assets.check_assets(("report",), runner) == ["report"]


def test_main_returns_three_and_names_every_skip(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        refresh_assets,
        "refresh_assets",
        lambda selected, **kwargs: (
            [],
            [
                refresh_assets.AssetSkip("browser", "report.png"),
                refresh_assets.AssetSkip("termsvg", "demo.svg"),
            ],
        ),
    )
    assert refresh_assets.main([]) == 3
    err = capsys.readouterr().err
    assert "missing browser" in err and "report.png" in err
    assert "missing termsvg" in err and "demo.svg" in err


def test_graph_is_excluded_from_defaults_stamps_and_checks() -> None:
    assert refresh_assets._selection(None) == ("report", "demo")
    assert "graph" not in refresh_assets._selection(None)
    with pytest.raises(refresh_assets.AssetError, match="outside --check"):
        refresh_assets.check_assets(("graph",))


@pytest.mark.parametrize(
    "args",
    [
        ["--only=graph"],
        ["--only=graph", "--from=x.gz", "--check"],
        ["--only=report", "--from=x.gz"],
        ["--only=demo", "--top-hosts=1"],
        ["--only=graph", "--from=x.gz", "--top-hosts=0"],
    ],
)
def test_graph_cli_rejects_implicit_or_incoherent_sources(args: list[str]) -> None:
    with pytest.raises(SystemExit):
        refresh_assets.parse_args(args)


def test_graph_cli_defaults_to_the_frozen_top_host_ceiling() -> None:
    args = refresh_assets.parse_args(["--only=graph", "--from=private.gz"])
    assert args.top_hosts == 30
    assert args.graph_source == Path("private.gz")


def test_generate_graph_html_uses_only_neutral_source_and_home(
    tmp_path: Path, monkeypatch
) -> None:
    private = tmp_path / "private-name-with-date.log.gz"
    private.write_bytes(b"private source")
    calls: list[tuple[list[str], Path, dict[str, str]]] = []

    def runner(argv, cwd, env, timeout):
        calls.append((list(argv), cwd, dict(env)))
        (cwd / "graph.html").write_text(
            '<html><canvas id="sankey"></canvas></html>', encoding="utf-8"
        )
        return refresh_assets.RunResult(0)

    monkeypatch.setattr(
        refresh_assets, "find_sigwood", lambda: Path("/opt/sigwood/bin/sigwood")
    )
    html = refresh_assets.generate_graph_html(
        private, tmp_path / "render", top_hosts=30, runner=runner
    )
    argv, cwd, env = calls[0]
    command = " ".join(argv)
    assert str(private) not in command
    assert private.name not in command
    assert "source/conn.log.gz" in command
    assert env["HOME"].startswith(str(cwd))
    config_arg = next(item for item in argv if item.startswith("--config="))
    config = Path(config_arg.split("=", 1)[1]).read_text(encoding="utf-8")
    assert "top_hosts = 30" in config
    assert str(private) not in html


def test_graph_only_refresh_never_reads_or_writes_asset_stamps(
    tmp_path: Path, monkeypatch
) -> None:
    source = tmp_path / "private.gz"
    source.write_bytes(b"source")
    writes: list[tuple[Path, bytes]] = []
    monkeypatch.setattr(
        refresh_assets,
        "load_stamps",
        lambda: (_ for _ in ()).throw(AssertionError("stamps read")),
    )
    monkeypatch.setattr(
        refresh_assets,
        "write_stamps",
        lambda data: (_ for _ in ()).throw(AssertionError("stamps written")),
    )
    monkeypatch.setattr(refresh_assets, "find_browser", lambda explicit: Path("/browser"))
    monkeypatch.setattr(refresh_assets, "find_optional_tool", lambda name: Path("/" + name))
    monkeypatch.setattr(
        refresh_assets,
        "generate_graph_html",
        lambda *args, **kwargs: '<canvas id="sankey"></canvas>',
    )
    monkeypatch.setattr(
        refresh_assets, "render_graph_gif", lambda *args, **kwargs: _gif()
    )
    monkeypatch.setattr(
        refresh_assets, "atomic_write", lambda path, data: writes.append((path, data))
    )
    refreshed, skipped = refresh_assets.refresh_assets(
        ("graph",), browser_arg=None, graph_source=source
    )
    assert refreshed == ["graph.gif"]
    assert skipped == []
    assert writes == [(refresh_assets.GRAPH_ASSET, _gif())]


def test_gif_validator_requires_dimensions_frames_and_real_change() -> None:
    assert refresh_assets.validate_gif(_gif()) == 2
    with pytest.raises(refresh_assets.AssetError, match="dimensions"):
        refresh_assets.validate_gif(_gif(width=1, height=1))
    duplicate = _gif().replace(b"\x4c\x01", b"\x44\x01")
    with pytest.raises(refresh_assets.AssetError, match="nontrivial"):
        refresh_assets.validate_gif(duplicate)


def test_graph_encoder_prefers_gifski_and_accepts_timed_out_valid_artifact(
    tmp_path: Path, monkeypatch
) -> None:
    calls: list[str] = []

    def find(name: str):
        return Path("/" + name)

    def runner(argv, cwd, env, timeout):
        calls.append(Path(argv[0]).name)
        (cwd / "graph.gif").write_bytes(_gif())
        return refresh_assets.RunResult(124, timed_out=True)

    monkeypatch.setattr(refresh_assets, "find_optional_tool", find)
    result = refresh_assets._encoded_graph_gif(
        (tmp_path / "frame-0000.png", tmp_path / "frame-0001.png"),
        tmp_path,
        runner,
    )
    assert result == _gif()
    assert calls == ["gifski"]


def test_graph_encoder_falls_back_to_ffmpeg_after_gifski_failure(
    tmp_path: Path, monkeypatch
) -> None:
    calls: list[str] = []

    def runner(argv, cwd, env, timeout):
        name = Path(argv[0]).name
        calls.append(name)
        if name == "ffmpeg":
            (cwd / "graph.gif").write_bytes(_gif())
            return refresh_assets.RunResult(0)
        return refresh_assets.RunResult(1, stderr="gifski failed")

    monkeypatch.setattr(
        refresh_assets, "find_optional_tool", lambda name: Path("/" + name)
    )
    result = refresh_assets._encoded_graph_gif(
        (tmp_path / "frame-0000.png", tmp_path / "frame-0001.png"),
        tmp_path,
        runner,
    )
    assert result == _gif()
    assert calls == ["gifski", "ffmpeg"]
