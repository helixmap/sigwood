"""A-phase guard: the loader/ package presents the same import surface as the
former single common/loader.py module, and the test-patchable I/O seams
(``progress`` / ``_open_log``) remain SETTABLE at the package boundary AND
patch-through to the load pipeline.

This is the extraction's safety net: a dropped
re-export or a facade that snapshots a pre-patch object fails here loudly.
"""

from __future__ import annotations

from pathlib import Path

import sigwood.common.loader as loader


# The full re-export inventory. Every name that resolved at
# sigwood.common.loader.<name> before the package split MUST still resolve.
# Pinned literally so a dropped re-export is a hard failure, not silent drift.
_SURFACE = [
    # display re-export (imported module-global, monkeypatched in 12 tests)
    "progress",
    # io
    "_open_log", "_safe_resolve", "_union_dedupe",
    # types
    "LoadResult", "CoverageTracker", "SourceCoverage", "RotationSkipInfo",
    "_data_window", "_PIHOLE_COLUMNS", "_CLOUDTRAIL_COLUMNS", "_SYSLOG_COLUMNS",
    "_LOG_SUFFIXES",
    # diagnostics
    "_log_type", "_schema_warning", "_zeek_file_read_warning",
    "_cloudtrail_parse_warning", "_zeek_file_parse_warning",
    "_zeek_bad_lines_warning", "_zeek_no_records_warning",
    # sniff
    "sniff_format", "sniff_format_detailed", "SniffResult", "_is_ndjson",
    "_looks_binary", "_looks_like_syslog", "_SNIFF_MAX_PEEK", "_SNIFF_ORIGIN",
    "_SNIFF_RECOGNIZERS",
    "_SYSLOG_SNIFF_BYTES",
    # windowing
    "_apply_ts_filter", "_missing_ts", "is_bounded", "is_zeek_bounded",
    "_classify_rotation_name", "_rotation_base_and_index", "_peek_first_ts",
    "_select_group", "_group_order_conflict", "_rotation_windowed_files",
    "_COMPRESSION_EXTS", "_ROTATION_NUM_RE", "_DATE_RANK_BASE", "_EXPORT_WINDOW_RE",
    # windowing - B+D named window model
    "LoadWindow", "apply_default_window",
    # discovery
    "discover_files", "_DATE_DIR_RE", "_zeek_date_subdirs", "_file_matches_pattern",
    "discover_zeek_files", "_syslog_files", "_discover_syslog_files",
    "_dir_has_regular_files", "discover_cloudtrail_files", "_stem_hostname",
    # discovery - B+D strategy resolvers (folded accessors)
    "_zeek_dated_window", "_flat_default_floor", "_default_resolve_window",
    "_zeek_resolve_window", "_flat_resolve_window",
    # pipeline
    "SourceLoader", "_SOURCE_LOADERS", "discover_for_source_key", "run_load", "load_required_logs",
    "load_logs", "load_zeek_log", "load_syslog", "load_pihole", "load_cloudtrail",
    "_zeek_records_from_lines", "_zeek_parse_from_lines", "_parse_ndjson_file",
    "_parse_lines", "_zeek_strategy_parse", "_zeek_normalize",
    "_syslog_strategy_parse", "_pihole_strategy_parse", "_cloudtrail_strategy_parse",
    "_events_from_whole_document", "_syslog_should_skip", "_pihole_should_skip",
    "_syslog_warn_undecodable", "_pihole_warn_undecodable",
    "_NORMALIZER_MAP", "resolve_load_windows",
]


def test_full_surface_resolves():
    missing = [name for name in _SURFACE if not hasattr(loader, name)]
    assert not missing, f"loader package dropped re-exports: {missing}"


def test_source_loaders_registry_identity():
    # The name imported by string-path must BE the registry the pipeline reads.
    from sigwood.common.loader import _SOURCE_LOADERS as imported
    assert imported is loader._SOURCE_LOADERS
    # Every detector source key has a registered strategy (the completeness rail
    # this extraction must not break).
    for key in ("zeek_dir", "syslog_dir", "pihole_dir", "cloudtrail_dir"):
        assert key in loader._SOURCE_LOADERS


def _write_conn(tmp_path: Path) -> Path:
    d = tmp_path / "zeek"
    d.mkdir()
    (d / "conn.log").write_text(
        '{"ts": 1.0, "id.orig_h": "192.0.2.1", "id.resp_h": "192.0.2.2", '
        '"id.resp_p": 53, "proto": "udp"}\n'
    )
    return d


def test_progress_patch_through(tmp_path, monkeypatch):
    """Patching loader.progress (the package attr) must reach pipeline.run_load -
    proves the facade reads progress at call time, not via an import-time snapshot.
    """
    hits = {"n": 0}
    real = loader.progress

    def spy(it, **kwargs):
        hits["n"] += 1
        return real(it, **kwargs)

    monkeypatch.setattr(loader, "progress", spy)
    df = loader.load_logs(_write_conn(tmp_path), "conn*.log*")
    assert len(df) == 1
    assert hits["n"] >= 1, "progress patch did not reach the load pipeline"


def test_open_log_patch_through(tmp_path, monkeypatch):
    """Patching loader._open_log (the package attr) must reach pipeline.run_load."""
    hits = {"n": 0}
    real = loader._open_log

    def spy(path):
        hits["n"] += 1
        return real(path)

    monkeypatch.setattr(loader, "_open_log", spy)
    df = loader.load_logs(_write_conn(tmp_path), "conn*.log*")
    assert len(df) == 1
    assert hits["n"] >= 1, "_open_log patch did not reach the load pipeline"
