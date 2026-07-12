"""Unit tests for sigwood.common.sources.

Covers three independent concerns:

* ``route_positional_source`` - the ONE detect-path positional → source-dir
  router. Pure-function: takes a Path and a pre-imported detector
  module; uses ``REQUIRED_LOGS`` when present, else content-sniff against
  ``OPTIONAL_LOGS``; degrades gracefully on directory positional or sniff
  ``OSError`` to ``OPTIONAL_LOGS[0]["source"]``.

* ``resolve_sources`` - analyze-path resolver. Owns the four-key truth
  table (override / scope / config fallback). The ``None``-contract is
  binding: ``overrides.get(key)`` of ``None`` is "no override," identical
  to an absent key. Explicit-override shell semantics - ``~`` expansion,
  CWD-relative ignoring SIGWOOD_ROOT, absolute round-trip, ``Path`` round-trip -
  are all asserted directly here because ``_resolve_one`` is the SOLE
  string→Path site (CLI hands raw strings through).

* ``resolve_digest_source`` - digest resolver. Owns the per-schema
  candidate ladder, wrong-key + XOR + not-configured errors. Error strings
  are byte-preserved from the previous run_digest ladders; this file
  pins each string literal.
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from sigwood.common import sources
from sigwood.common import loader
from sigwood.common.sources import (
    DigestSource,
    GRAPH_KINDS,
    GraphKindSpec,
    ResolvedSources,
    discover_for_source_key,
    discover_graph_kinds,
    graph_buckets_for_inputs,
    graph_kind_for_sniff,
    graph_kind_spec,
    probe_graph_inputs,
    resolve_digest_source,
    resolve_graph_source,
    resolve_sources,
    route_positional_source,
)


# ── route_positional_source ───────────────────────────────────────────────────


class _ReqModule:
    """Detector stand-in carrying REQUIRED_LOGS only."""

    REQUIRED_LOGS = [{"source": "cloudtrail_dir", "pattern": "*.json*"}]
    OPTIONAL_LOGS: list[dict[str, str]] = []


class _OptModule:
    """Detector stand-in mirroring the dns shape: zeek_dir first, pihole_dir second."""

    REQUIRED_LOGS: list[dict[str, str]] = []
    OPTIONAL_LOGS = [
        {"source": "zeek_dir", "pattern": "dns*.log*"},
        {"source": "pihole_dir", "pattern": "pihole*.log*"},
    ]


class _SyslogShape:
    """Detector stand-in mirroring the syslog shape: syslog_dir first, zeek_dir second."""

    REQUIRED_LOGS: list[dict[str, str]] = []
    OPTIONAL_LOGS = [
        {"source": "syslog_dir", "pattern": "*.log*"},
        {"source": "zeek_dir", "pattern": "syslog*.log*"},
    ]


def test_router_required_logs_wins(tmp_path: Path) -> None:
    """REQUIRED_LOGS[0]["source"] short-circuits - no sniff needed."""
    nothing = tmp_path / "anything.log"
    nothing.write_text("not even json\n", encoding="utf-8")
    assert route_positional_source(nothing, detector_module=_ReqModule) == "cloudtrail_dir"


def test_router_dns_pihole_content_under_neutral_name(tmp_path: Path) -> None:
    """A Pi-hole-CONTENT file whose name does NOT match pihole*.log* routes via
    content-sniff to pihole_dir. Locks the fnmatch→content-sniff migration."""
    # Name is deliberately bland - "mystery" cannot satisfy pihole*.log*.
    pihole = tmp_path / "mystery.log"
    pihole.write_text(
        "Jun 11 12:00:00 host1 dnsmasq[1234]: query[A] example.com from 192.0.2.10\n",
        encoding="utf-8",
    )
    assert route_positional_source(pihole, detector_module=_OptModule) == "pihole_dir"


def test_router_dns_zeek_content_routes_to_zeek_dir(tmp_path: Path) -> None:
    """A Zeek-dns content file routes to zeek_dir even under a neutral name."""
    zeek_dns = tmp_path / "mystery.log"
    zeek_dns.write_text(
        '{"_path":"dns","ts":1779750000.0,"uid":"CDS01",'
        '"id.orig_h":"192.0.2.10","id.resp_h":"198.51.100.20",'
        '"id.resp_p":53,"proto":"udp","query":"example.com","qtype":1}\n',
        encoding="utf-8",
    )
    assert route_positional_source(zeek_dns, detector_module=_OptModule) == "zeek_dir"


def test_router_syslog_zeek_content_routes_to_zeek_dir(tmp_path: Path) -> None:
    """Zeek syslog.log (TSV with #path syslog) routes to zeek_dir."""
    zeek_syslog = tmp_path / "syslog.log"
    zeek_syslog.write_text(
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
    assert route_positional_source(zeek_syslog, detector_module=_SyslogShape) == "zeek_dir"


def test_router_syslog_flat_content_routes_to_syslog_dir(tmp_path: Path) -> None:
    flat = tmp_path / "auth.log"
    flat.write_text(
        "<134>Jun 11 12:00:00 host1 sshd[1234]: Accepted publickey for user\n",
        encoding="utf-8",
    )
    assert route_positional_source(flat, detector_module=_SyslogShape) == "syslog_dir"


def test_router_directory_falls_back_to_first_optional(tmp_path: Path) -> None:
    """A directory with no recognized votes defaults to OPTIONAL_LOGS[0]."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    assert route_positional_source(log_dir, detector_module=_OptModule) == "zeek_dir"
    assert route_positional_source(log_dir, detector_module=_SyslogShape) == "syslog_dir"


def test_router_directory_votes_pihole_over_sorted_decoys(tmp_path: Path) -> None:
    """Directory routing samples beyond sorted decoys and lets Pi-hole win ties."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "FTL.log").write_text(
        "<134>Jun 11 12:00:00 host1 pihole-FTL[123]: daemon ready\n",
        encoding="utf-8",
    )
    (log_dir / "pihole.log").write_text("", encoding="utf-8")
    (log_dir / "pihole.log.1").write_text(
        "Jun 11 12:00:00 host1 dnsmasq[1234]: "
        "query[A] example.test from 192.0.2.10\n",
        encoding="utf-8",
    )

    assert route_positional_source(log_dir, detector_module=None) == "pihole_dir"
    assert route_positional_source(log_dir, detector_module=_OptModule) == "pihole_dir"


def test_router_directory_votes_zeek_content(tmp_path: Path) -> None:
    """A directory with recognized Zeek content routes to zeek_dir."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "conn.log").write_text(
        '{"_path":"conn","ts":1779750000.0,"uid":"C1",'
        '"id.orig_h":"192.0.2.10","id.resp_h":"198.51.100.20",'
        '"id.resp_p":443,"proto":"tcp"}\n',
        encoding="utf-8",
    )

    assert route_positional_source(log_dir, detector_module=None) == "zeek_dir"
    assert route_positional_source(log_dir, detector_module=_OptModule) == "zeek_dir"


def test_router_directory_permission_hint_votes_pihole(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unreadable pihole*.log* samples cast a narrow Pi-hole filename vote."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "FTL.log").write_text("daemon log\n", encoding="utf-8")
    (log_dir / "pihole.log").write_text("unreadable placeholder\n", encoding="utf-8")
    (log_dir / "pihole.log.1").write_text("unreadable placeholder\n", encoding="utf-8")

    def _fake_sniff(path: Path):
        if path.name.startswith("pihole.log"):
            raise PermissionError("synthetic denied")
        return SimpleNamespace(origin=None)

    monkeypatch.setattr(sources, "sniff_format_detailed", _fake_sniff)

    assert route_positional_source(log_dir, detector_module=None) == "pihole_dir"
    assert route_positional_source(log_dir, detector_module=_OptModule) == "pihole_dir"


def test_router_directory_permission_hint_stays_narrow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A broad *.log filename does not become a syslog vote when unreadable."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "messages.log").write_text("unreadable placeholder\n", encoding="utf-8")

    def _fake_sniff(_path: Path):
        raise PermissionError("synthetic denied")

    monkeypatch.setattr(sources, "sniff_format_detailed", _fake_sniff)

    assert route_positional_source(log_dir, detector_module=None) == "zeek_dir"
    assert route_positional_source(log_dir, detector_module=_SyslogShape) == "syslog_dir"


def test_router_missing_file_degrades_silently(tmp_path: Path) -> None:
    """A missing/unreadable positional must not raise; falls back to OPTIONAL_LOGS[0]."""
    ghost = tmp_path / "does-not-exist.log"
    assert route_positional_source(ghost, detector_module=_SyslogShape) == "syslog_dir"


def test_router_unrecognized_content_falls_back_to_first_optional(tmp_path: Path) -> None:
    """A file the sniffer can't claim falls through to OPTIONAL_LOGS[0]."""
    mystery = tmp_path / "mystery.log"
    mystery.write_text("lorem ipsum dolor\nsit amet\n", encoding="utf-8")
    assert route_positional_source(mystery, detector_module=_SyslogShape) == "syslog_dir"


# ── graph kind/source foundation ────────────────────────────────────────────


def test_graph_kinds_are_ordered_declarations() -> None:
    """Graph advertises conn and Zeek dns in deterministic order."""
    assert GRAPH_KINDS == (
        GraphKindSpec("conn", "zeek_dir", "conn*.log*", "conn", "zeek"),
        GraphKindSpec("dns", "zeek_dir", "dns*.log*", "dns", "zeek"),
    )


@pytest.mark.parametrize(
    ("schema", "origin", "expected"),
    [
        ("conn", "zeek", "conn"),
        ("dns", "zeek", "dns"),
        ("dns", "pihole", None),
        ("syslog", "zeek", None),
        (None, None, None),
    ],
)
def test_graph_kind_for_sniff_uses_schema_and_origin(
    schema: str | None,
    origin: str | None,
    expected: str | None,
) -> None:
    spec = graph_kind_for_sniff(schema, origin)
    assert (spec.kind if spec is not None else None) == expected


def test_discover_for_source_key_delegates_to_registered_loader(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The graph seam delegates discovery to the registered source strategy."""
    calls: list[tuple[Path, str, object, object]] = []

    class _Strategy:
        def discover(self, directory, pattern, since, until):
            calls.append((directory, pattern, since, until))
            return [directory / "conn.log"]

    monkeypatch.setitem(loader._SOURCE_LOADERS, "graph_test_dir", _Strategy())

    assert discover_for_source_key("graph_test_dir", tmp_path, "conn*.log*") == [
        tmp_path / "conn.log"
    ]
    assert calls == [(tmp_path, "conn*.log*", None, None)]


def test_discover_for_source_key_rejects_unknown_loader(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unknown source key 'missing_dir'"):
        discover_for_source_key("missing_dir", tmp_path, "*.log*")


def test_discover_graph_kinds_keeps_only_nonempty_buckets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A graphable directory may fan out to multiple ordered kind buckets."""
    calls: list[tuple[str, Path, str]] = []

    def _discover(source_key: str, directory: str | Path, pattern: str) -> list[Path]:
        root = Path(directory)
        calls.append((source_key, root, pattern))
        if pattern == "dns*.log*":
            return [root / "dns.log"]
        return []

    monkeypatch.setattr(sources, "discover_for_source_key", _discover)

    assert discover_graph_kinds(tmp_path) == {"dns": [tmp_path / "dns.log"]}
    assert calls == [
        ("zeek_dir", tmp_path, "conn*.log*"),
        ("zeek_dir", tmp_path, "dns*.log*"),
    ]


def test_graph_buckets_file_sniffs_and_keeps_trusted_explicit_path(
    tmp_path: Path,
) -> None:
    """A neutral explicit filename becomes a conn bucket after detailed sniff."""
    source = tmp_path / "captured"
    source.write_text(
        '{"_path":"conn","ts":1779750000.0,"uid":"C1",'
        '"id.orig_h":"192.0.2.10","id.resp_h":"198.51.100.20",'
        '"id.resp_p":443,"proto":"tcp","duration":1.0}\n',
        encoding="utf-8",
    )

    assert graph_buckets_for_inputs({"sigwood": {}}, [source]) == {
        "conn": [source],
    }


def test_graph_buckets_directory_fans_out_and_keeps_directory_input(
    tmp_path: Path,
) -> None:
    """Directory probing selects kinds but leaves discovery ownership to loader."""
    source = tmp_path / "zeek"
    source.mkdir()
    (source / "conn.log").write_text(
        '{"_path":"conn","ts":1779750000.0,"uid":"C1",'
        '"id.orig_h":"192.0.2.10","id.resp_h":"198.51.100.20",'
        '"id.resp_p":443,"proto":"tcp","duration":1.0}\n',
        encoding="utf-8",
    )
    (source / "dns.log").write_text(
        '{"_path":"dns","ts":1779750000.0,"uid":"D1",'
        '"id.orig_h":"192.0.2.10","query":"example.test"}\n',
        encoding="utf-8",
    )
    mixed: dict[str, tuple[str, ...]] = {}

    buckets = graph_buckets_for_inputs(
        {"sigwood": {}}, [source], _mixed_sink=mixed,
    )

    assert buckets == {"conn": [source], "dns": [source]}
    assert mixed == {str(source): ("conn", "dns")}


def test_graph_probe_keeps_a_valid_file_when_a_sibling_cannot_be_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Input probing returns a typed denial beside the surviving graph bucket."""
    conn = tmp_path / "conn.log"
    conn.write_text(
        '{"_path":"conn","ts":1779750000.0,"uid":"C1",'
        '"id.orig_h":"192.0.2.10","id.resp_h":"198.51.100.20",'
        '"id.resp_p":443,"proto":"tcp","duration":1.0}\n',
        encoding="utf-8",
    )
    denied = tmp_path / "denied.log"
    denied.write_text("placeholder\n", encoding="utf-8")
    real_sniff = sources.sniff_format_detailed

    def _sniff(path: Path):
        if path == denied:
            raise PermissionError("synthetic denied")
        return real_sniff(path)

    monkeypatch.setattr(sources, "sniff_format_detailed", _sniff)

    probe = probe_graph_inputs({"sigwood": {}}, [conn, denied])

    assert probe.buckets == {"conn": [conn]}
    assert len(probe.issues) == 1
    assert probe.issues[0].path == denied
    assert probe.issues[0].permission is True


def test_graph_bare_config_resolution_honors_root_and_declared_source(
    tmp_path: Path,
) -> None:
    """Bare graph resolves config input through the shared source resolver."""
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "conn.log").write_text(
        '{"_path":"conn","ts":1779750000.0,"uid":"C1",'
        '"id.orig_h":"192.0.2.10","id.resp_h":"198.51.100.20",'
        '"id.resp_p":443,"proto":"tcp","duration":1.0}\n',
        encoding="utf-8",
    )
    config = {"sigwood": {"root": str(tmp_path), "zeek_dir": "logs"}}

    spec, resolved = resolve_graph_source(config, "conn")

    assert spec == graph_kind_spec("conn")
    assert resolved == [logs]
    assert graph_buckets_for_inputs(config) == {"conn": [logs]}


# ── resolve_sources - overrides None-contract + scope truth table ─────────────


def _cfg_all_four() -> dict[str, Any]:
    return {"sigwood": {
        "root": "/tmp/sigwood-root",
        "zeek_dir": "zeek",
        "syslog_dir": "syslog",
        "pihole_dir": "pihole",
        "cloudtrail_dir": "cloudtrail",
    }}


def test_resolve_sources_none_overrides_treated_as_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A None override is identical to an absent key.

    ``runner.run(config=..., dry_run=True)`` passes all four kwargs with their
    None defaults intact; the programmatic-fallback rail
    (tests/test_root_provenance.py) depends on the resolver treating None as
    'no override' and config-filling.
    """
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    resolved = resolve_sources(
        _cfg_all_four(),
        overrides={k: None for k in
                   ("zeek_dir", "syslog_dir", "pihole_dir", "cloudtrail_dir")},
        scope=None,
    )
    assert resolved == ResolvedSources(
        zeek_dir=[Path("/tmp/sigwood-root/zeek")],
        syslog_dir=[Path("/tmp/sigwood-root/syslog")],
        pihole_dir=[Path("/tmp/sigwood-root/pihole")],
        cloudtrail_dir=[Path("/tmp/sigwood-root/cloudtrail")],
    )


def test_resolve_sources_empty_overrides_dict_matches_none_overrides(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``{}`` and ``{k: None, ...}`` produce identical results - same contract."""
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    cfg = _cfg_all_four()
    via_empty = resolve_sources(cfg, overrides={}, scope=None)
    via_nones = resolve_sources(
        cfg,
        overrides={"zeek_dir": None, "syslog_dir": None,
                   "pihole_dir": None, "cloudtrail_dir": None},
        scope=None,
    )
    assert via_empty == via_nones


def test_resolve_sources_empty_string_override_treated_as_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An empty-string override falls through to config fallback.

    The CLI parser stores a bare ``--zeek-dir=`` as ``""`` (not None, not
    rejected). Truthiness (``if cli_val:``) treats ``""`` as "no value, use
    config." A naive ``is not None`` check at
    the resolver boundary would treat ``""`` as present, send it through
    ``resolve_path("", "")`` → None, and silently suppress the config
    fallback. The ``_present`` helper keeps this truthiness-based semantics."""
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    resolved = resolve_sources(
        {"sigwood": {"root": "/sigwood-root", "zeek_dir": "zeek"}},
        overrides={"zeek_dir": ""},
        scope=None,
    )
    assert resolved.zeek_dir == [Path("/sigwood-root/zeek")]


def test_resolve_sources_scope_suppresses_unscoped_config_fill(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A scoped run does not config-fill sibling source-dirs."""
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    resolved = resolve_sources(
        _cfg_all_four(),
        overrides={},
        scope=frozenset({"syslog_dir"}),
    )
    assert resolved.syslog_dir == [Path("/tmp/sigwood-root/syslog")]
    assert resolved.zeek_dir == []
    assert resolved.pihole_dir == []
    assert resolved.cloudtrail_dir == []


def test_resolve_sources_override_outside_scope_still_wins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An explicit override outside ``scope`` still applies - operator widening.

    This is the property that lets ``sigwood syslog PATH --zeek-dir=/x``
    widen the run while the positional still scopes to syslog_dir.
    """
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    resolved = resolve_sources(
        _cfg_all_four(),
        overrides={"zeek_dir": "/explicit/zk"},
        scope=frozenset({"syslog_dir"}),
    )
    assert resolved.zeek_dir == [Path("/explicit/zk")]
    assert resolved.syslog_dir == [Path("/tmp/sigwood-root/syslog")]
    assert resolved.pihole_dir == []
    assert resolved.cloudtrail_dir == []


def test_resolve_sources_override_wins_over_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    resolved = resolve_sources(
        _cfg_all_four(),
        overrides={"zeek_dir": "/explicit/zk"},
        scope=None,
    )
    assert resolved.zeek_dir == [Path("/explicit/zk")]
    # Config still fills siblings because scope is None.
    assert resolved.syslog_dir == [Path("/tmp/sigwood-root/syslog")]


# ── resolve_sources - explicit override shell semantics ──────────────────────


def test_resolve_sources_tilde_override_expands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A ``~``-anchored override expands via expanduser - proves _resolve_one
    sends overrides through resolve_path(value, ""), NOT resolve_path(value, root)."""
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    home = str(Path("~").expanduser())
    resolved = resolve_sources(
        {"sigwood": {"root": "/sigwood-root"}},
        overrides={"zeek_dir": "~/zk"},
        scope=None,
    )
    assert resolved.zeek_dir == [Path(home) / "zk"]


def test_resolve_sources_relative_override_ignores_sigwood_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A relative override resolves CWD-relative and ignores SIGWOOD_ROOT - the
    CLI-vs-config provenance split that ``_resolve_one`` enforces by
    passing ``root=""`` on the override branch."""
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    resolved = resolve_sources(
        {"sigwood": {"root": "/sigwood-root"}},
        overrides={"zeek_dir": "rel/zk"},
        scope=None,
    )
    assert resolved.zeek_dir == [Path("rel/zk")]
    # Negative: must NOT be /sigwood-root/rel/zk.
    assert resolved.zeek_dir != [Path("/sigwood-root/rel/zk")]


def test_resolve_sources_absolute_override_round_trips() -> None:
    resolved = resolve_sources(
        {"sigwood": {"root": "/sigwood-root"}},
        overrides={"zeek_dir": "/abs/zk"},
        scope=None,
    )
    assert resolved.zeek_dir == [Path("/abs/zk")]


def test_resolve_sources_path_override_round_trips() -> None:
    """A ``Path`` override goes through ``str(override)`` and is treated the
    same as the equivalent string."""
    resolved = resolve_sources(
        {"sigwood": {"root": "/sigwood-root"}},
        overrides={"zeek_dir": Path("/abs/zk")},
        scope=None,
    )
    assert resolved.zeek_dir == [Path("/abs/zk")]


def test_resolve_sources_config_relative_uses_sigwood_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Config-side values still get SIGWOOD_ROOT - the rail
    ``tests/test_root_provenance.py:160`` guards directly. Mirrored here so a
    drift only requires reading this file."""
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    resolved = resolve_sources(
        {"sigwood": {"root": "/sigwood-root", "zeek_dir": "zeek"}},
        overrides={},
        scope=None,
    )
    assert resolved.zeek_dir == [Path("/sigwood-root/zeek")]


def test_resolve_sources_env_sigwood_root_wins_over_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SIGWOOD_ROOT env var beats the config ``root`` key - the
    ``effective_root`` rail. Tested here too because ``_resolve_one`` reads
    it via the helper."""
    monkeypatch.setenv("SIGWOOD_ROOT", "/env-root")
    resolved = resolve_sources(
        {"sigwood": {"root": "/cfg-root", "zeek_dir": "zeek"}},
        overrides={},
        scope=None,
    )
    assert resolved.zeek_dir == [Path("/env-root/zeek")]


# ── resolve_digest_source ─────────────────────────────────────────────────────


def test_digest_conn_wrong_key_byte_preserved() -> None:
    """digest conn rejects every non-zeek_dir override with the exact text."""
    for bad in ("pihole_dir", "syslog_dir", "cloudtrail_dir"):
        with pytest.raises(ValueError) as exc:
            resolve_digest_source(
                {"sigwood": {}}, "conn",
                overrides={bad: "/x"},
            )
        assert str(exc.value) == (
            f"digest conn: {bad} is not valid for the conn schema"
        )


def test_digest_dns_wrong_key_byte_preserved() -> None:
    for bad in ("syslog_dir", "cloudtrail_dir"):
        with pytest.raises(ValueError) as exc:
            resolve_digest_source(
                {"sigwood": {}}, "dns",
                overrides={bad: "/x"},
            )
        assert str(exc.value) == (
            f"digest dns: {bad} is not valid for the dns schema"
        )


def test_digest_syslog_wrong_key_byte_preserved() -> None:
    for bad in ("pihole_dir", "cloudtrail_dir"):
        with pytest.raises(ValueError) as exc:
            resolve_digest_source(
                {"sigwood": {}}, "syslog",
                overrides={bad: "/x"},
            )
        assert str(exc.value) == (
            f"digest syslog: {bad} is not valid for the syslog schema"
        )


def test_digest_cloudtrail_wrong_key_byte_preserved() -> None:
    for bad in ("zeek_dir", "pihole_dir", "syslog_dir"):
        with pytest.raises(ValueError) as exc:
            resolve_digest_source(
                {"sigwood": {}}, "cloudtrail",
                overrides={bad: "/x"},
            )
        assert str(exc.value) == (
            f"digest cloudtrail: {bad} is not valid for the cloudtrail schema"
        )


def test_digest_dns_xor_byte_preserved() -> None:
    with pytest.raises(ValueError) as exc:
        resolve_digest_source(
            {"sigwood": {}}, "dns",
            overrides={"zeek_dir": "/z", "pihole_dir": "/p"},
        )
    assert str(exc.value) == (
        "digest dns: cannot use both --zeek-dir and --pihole-dir"
    )


def test_digest_syslog_xor_byte_preserved() -> None:
    with pytest.raises(ValueError) as exc:
        resolve_digest_source(
            {"sigwood": {}}, "syslog",
            overrides={"zeek_dir": "/z", "syslog_dir": "/s"},
        )
    assert str(exc.value) == (
        "digest syslog: cannot use both zeek_dir and syslog_dir"
    )


def test_digest_conn_not_configured_byte_preserved() -> None:
    with pytest.raises(ValueError) as exc:
        resolve_digest_source({"sigwood": {}}, "conn", overrides={})
    assert str(exc.value) == (
        "digest: zeek_dir not configured - pass a PATH or set "
        "[sigwood].zeek_dir in your config"
    )


def test_digest_dns_not_configured_byte_preserved() -> None:
    with pytest.raises(ValueError) as exc:
        resolve_digest_source({"sigwood": {}}, "dns", overrides={})
    assert str(exc.value) == (
        "digest dns: zeek_dir or pihole_dir not configured - "
        "pass a PATH, --zeek-dir/--pihole-dir, or set one in config"
    )


def test_digest_syslog_not_configured_byte_preserved() -> None:
    with pytest.raises(ValueError) as exc:
        resolve_digest_source({"sigwood": {}}, "syslog", overrides={})
    assert str(exc.value) == (
        "digest syslog: no syslog source configured - pass a PATH, "
        "--zeek-dir, or set [sigwood].syslog_dir / "
        "[sigwood].zeek_dir in your config"
    )


def test_digest_cloudtrail_not_configured_byte_preserved() -> None:
    with pytest.raises(ValueError) as exc:
        resolve_digest_source({"sigwood": {}}, "cloudtrail", overrides={})
    assert str(exc.value) == (
        "digest cloudtrail: cloudtrail_dir not configured - pass a PATH, "
        "--cloudtrail-dir, or set [sigwood].cloudtrail_dir in your config"
    )


def test_digest_conn_override_wins() -> None:
    ds = resolve_digest_source(
        {"sigwood": {}}, "conn",
        overrides={"zeek_dir": "/explicit/zk"},
    )
    assert ds == DigestSource(
        source_key="zeek_dir",
        directory=Path("/explicit/zk"),
        feed=None,
    )


def test_digest_dns_zeek_preference_on_config_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With both zeek_dir and pihole_dir configured, the dns digest prefers
    zeek_dir - the first entry in the candidate ladder."""
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    ds = resolve_digest_source(
        {"sigwood": {"zeek_dir": "/cfg/zk", "pihole_dir": "/cfg/ph"}},
        "dns",
        overrides={},
    )
    assert ds == DigestSource(
        source_key="zeek_dir", directory=Path("/cfg/zk"), feed="zeek",
    )


def test_digest_dns_pihole_when_only_pihole_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    ds = resolve_digest_source(
        {"sigwood": {"pihole_dir": "/cfg/ph"}},
        "dns",
        overrides={},
    )
    assert ds == DigestSource(
        source_key="pihole_dir", directory=Path("/cfg/ph"), feed="pihole",
    )


def test_digest_syslog_syslog_preference_on_config_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With both syslog_dir and zeek_dir configured, syslog digest prefers
    syslog_dir."""
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    ds = resolve_digest_source(
        {"sigwood": {"zeek_dir": "/cfg/zk", "syslog_dir": "/cfg/sl"}},
        "syslog",
        overrides={},
    )
    assert ds == DigestSource(
        source_key="syslog_dir", directory=Path("/cfg/sl"), feed="syslog",
    )


def test_digest_syslog_zeek_when_only_zeek_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    ds = resolve_digest_source(
        {"sigwood": {"zeek_dir": "/cfg/zk"}},
        "syslog",
        overrides={},
    )
    assert ds == DigestSource(
        source_key="zeek_dir", directory=Path("/cfg/zk"), feed="zeek",
    )


def test_digest_cloudtrail_config_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    ds = resolve_digest_source(
        {"sigwood": {"cloudtrail_dir": "/cfg/ct"}},
        "cloudtrail",
        overrides={},
    )
    assert ds == DigestSource(
        source_key="cloudtrail_dir", directory=Path("/cfg/ct"), feed=None,
    )


def test_digest_none_overrides_treated_as_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The None-contract applies to the digest resolver too - runner.run_digest
    passes all four dir kwargs with None defaults."""
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    ds = resolve_digest_source(
        {"sigwood": {"syslog_dir": "/cfg/sl"}},
        "syslog",
        overrides={"zeek_dir": None, "syslog_dir": None,
                   "pihole_dir": None, "cloudtrail_dir": None},
    )
    assert ds.source_key == "syslog_dir"


def test_digest_empty_string_override_falls_through_to_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bare ``--zeek-dir=`` in a digest invocation must NOT suppress config
    fallback. Mirror of the analyze resolver's empty-string test - same
    falsy-vs-None class, locked at both resolvers."""
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    ds = resolve_digest_source(
        {"sigwood": {"zeek_dir": "/cfg/zk"}},
        "conn",
        overrides={"zeek_dir": ""},
    )
    assert ds.source_key == "zeek_dir"
    assert ds.directory == Path("/cfg/zk")


def test_digest_empty_string_override_does_not_trigger_wrong_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bare ``--syslog-dir=`` for a conn-schema digest must NOT raise the
    wrong-key error - empty-string is "no override," not "present with the
    wrong key." Defends the wrong-key guard against the same falsy class."""
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    ds = resolve_digest_source(
        {"sigwood": {"zeek_dir": "/cfg/zk"}},
        "conn",
        overrides={"zeek_dir": "", "syslog_dir": ""},
    )
    assert ds.source_key == "zeek_dir"
    assert ds.directory == Path("/cfg/zk")


def test_digest_override_root_provenance_uses_shell_semantics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An override into resolve_digest_source resolves through shell semantics
    (no SIGWOOD_ROOT prefix). Mirror of test_resolve_sources_relative_override_ignores_sigwood_root."""
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    ds = resolve_digest_source(
        {"sigwood": {"root": "/sigwood-root", "zeek_dir": "should-not-be-used"}},
        "conn",
        overrides={"zeek_dir": "/abs/zk"},
    )
    assert ds.directory == Path("/abs/zk")


def test_digest_config_relative_uses_sigwood_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mirror of the analyze resolver: config-side relative values get SIGWOOD_ROOT."""
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    ds = resolve_digest_source(
        {"sigwood": {"root": "/sigwood-root", "zeek_dir": "zeek"}},
        "conn",
        overrides={},
    )
    assert ds.directory == Path("/sigwood-root/zeek")


# ── three-way drift tripwire for the digest (schema, source_key) keyspace ────


def test_digest_schema_source_keyspaces_agree() -> None:
    """Three structures encode the legal (schema, source_key) space and must
    agree. Without this tripwire, adding a new combo to two of the three
    surfaces yields a production KeyError at the
    ``_DIGEST_PATTERN_AND_EMPTY[(schema, source_key)]`` lookup in
    ``run_digest`` for that schema only. Same drift shape we already guard
    for the config example.
    """
    from sigwood.common.sources import _DIGEST_CANDIDATES, _DIGEST_FEED
    from sigwood.runner import _DIGEST_PATTERN_AND_EMPTY

    legal = {(s, k) for s, ks in _DIGEST_CANDIDATES.items() for k in ks}
    assert set(_DIGEST_FEED) == legal
    assert set(_DIGEST_PATTERN_AND_EMPTY) == legal


def test_router_mixed_directory_records_vote_tally(tmp_path: Path) -> None:
    """A directory sample holding more than one recognizable family records
    the full tally in the caller-owned sink - the caller discloses that the
    losing family's files are not hunted as their own kind."""
    log_dir = tmp_path / "mixed"
    log_dir.mkdir()
    for i in (1, 2):
        (log_dir / f"conn.{i}.log").write_text(
            '{"_path":"conn","ts":1779750000.0,"uid":"C1",'
            '"id.orig_h":"192.0.2.10","id.resp_h":"198.51.100.20",'
            '"id.resp_p":443,"proto":"tcp"}\n',
            encoding="utf-8",
        )
    (log_dir / "messages").write_text(
        "<134>Jun 11 12:00:00 host1 sshd[1234]: Accepted publickey for user\n",
        encoding="utf-8",
    )

    sink: dict[str, dict[str, int]] = {}
    routed = route_positional_source(
        log_dir, detector_module=None, _vote_sink=sink,
    )

    assert routed == "zeek_dir"
    assert sink == {str(log_dir): {"zeek": 2, "syslog": 1}}


def test_router_single_family_directory_records_no_tally(tmp_path: Path) -> None:
    """A single-family sample is not "mixed" - the sink stays empty."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "conn.log").write_text(
        '{"_path":"conn","ts":1779750000.0,"uid":"C1",'
        '"id.orig_h":"192.0.2.10","id.resp_h":"198.51.100.20",'
        '"id.resp_p":443,"proto":"tcp"}\n',
        encoding="utf-8",
    )

    sink: dict[str, dict[str, int]] = {}
    assert route_positional_source(
        log_dir, detector_module=None, _vote_sink=sink,
    ) == "zeek_dir"
    assert sink == {}
