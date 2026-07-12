"""Log discovery, decompression, parsing, and timeframe filtering.

All file I/O for log data flows through this package. Detectors never open files
directly. This ``__init__`` re-exports the FULL public + private symbol surface
of the package, so every name is importable or monkeypatchable at
``sigwood.common.loader.<name>`` regardless of which submodule owns it.

Submodule layout (acyclic; ``io``/``types``/``diagnostics`` are leaves):
- ``io``          - ``_open_log`` + path-normalization primitives.
- ``types``       - ``LoadResult`` / coverage / rotation-skip dataclasses, the
                    cross-frame window helper, column constants.
- ``diagnostics`` - log-type + warning/wording helpers.
- ``sniff``       - the digest recognizer cascade + the syslog content gate.
- ``windowing``   - ts filter, boundedness, the rotation-peek subsystem.
- ``discovery``   - per-family file discovery + dated-Zeek default window.
- ``pipeline``    - ``run_load`` + the ``_SOURCE_LOADERS`` registry + the
                    public ``load_*`` shims + registry-policy accessors.

Canonical connection record schema
───────────────────────────────────
All conn log DataFrames returned by this package use these column names.
Detectors, runner, and matcher never reference Zeek-specific column names.

  src        - source IP (str)
  dst        - destination IP (str)
  port       - destination port (int)
  proto      - protocol: tcp / udp / icmp (str)
  ts         - unix epoch timestamp (float)
  duration   - connection duration in seconds (float, nullable)
  bytes      - originator bytes (int, nullable)
  conn_state - connection state (str, nullable)
  local_orig - bool (nullable)
"""

from __future__ import annotations

# progress is re-exported so sigwood.common.loader.progress both RESOLVES and
# is SETTABLE - the load pipeline reads it through this package attribute (the
# call-time facade), so monkeypatching it here takes effect.
from sigwood.common.display import progress

from sigwood.common.loader.io import (
    _open_log,
    _safe_resolve,
    _union_dedupe,
)
from sigwood.common.loader.types import (
    _CLOUDTRAIL_COLUMNS,
    _LOG_SUFFIXES,
    _PIHOLE_COLUMNS,
    _SYSLOG_COLUMNS,
    CoverageTracker,
    LoadResult,
    PermissionSkipInfo,
    RotationSkipInfo,
    SourceCoverage,
    _data_window,
    _is_out_of_range_ts,
)
from sigwood.common.loader.diagnostics import (
    _cloudtrail_parse_warning,
    _log_type,
    _schema_warning,
    _permission_denied_message,
    _zeek_bad_lines_warning,
    _zeek_file_parse_warning,
    _zeek_file_read_warning,
    _zeek_no_records_warning,
)
from sigwood.common.loader.sniff import (
    _SNIFF_MAX_PEEK,
    _SNIFF_ORIGIN,
    _SNIFF_RECOGNIZERS,
    _SYSLOG_SNIFF_BYTES,
    SniffResult,
    _is_ndjson,
    _looks_binary,
    _looks_like_syslog,
    sniff_format,
    sniff_format_detailed,
)
from sigwood.common.loader.windowing import (
    _COMPRESSION_EXTS,
    _DATE_RANK_BASE,
    _EXPORT_WINDOW_RE,
    _ROTATION_NUM_RE,
    LoadWindow,
    _apply_ts_filter,
    _classify_rotation_name,
    _group_order_conflict,
    _missing_ts,
    _peek_first_ts,
    _rotation_base_and_index,
    _rotation_windowed_files,
    _select_group,
    _strip_compression_ext,
    apply_default_window,
    is_bounded,
    is_zeek_bounded,
)
from sigwood.common.loader.discovery import (
    _DATE_DIR_RE,
    _default_resolve_window,
    _dir_has_regular_files,
    _discover_syslog_files,
    _file_matches_pattern,
    _flat_default_floor,
    _flat_resolve_window,
    _stem_hostname,
    _syslog_files,
    _zeek_date_subdirs,
    _zeek_dated_window,
    _zeek_resolve_window,
    discover_cloudtrail_files,
    discover_files,
    discover_zeek_files,
)
from sigwood.common.loader.pipeline import (
    _NORMALIZER_MAP,
    _SOURCE_LOADERS,
    _cloudtrail_strategy_parse,
    _events_from_whole_document,
    _parse_lines,
    _parse_ndjson_file,
    _pihole_should_skip,
    _pihole_strategy_parse,
    _pihole_warn_undecodable,
    _syslog_should_skip,
    _syslog_strategy_parse,
    _syslog_warn_undecodable,
    _zeek_normalize,
    _zeek_parse_from_lines,
    _zeek_records_from_lines,
    _zeek_strategy_parse,
    SourceLoader,
    discover_for_source_key,
    load_cloudtrail,
    load_logs,
    load_pihole,
    load_required_logs,
    load_syslog,
    load_zeek_log,
    resolve_load_windows,
    run_load,
)
