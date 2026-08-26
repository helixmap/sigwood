"""Config loading with precedence chain: CLI arg > user > system.

Precedence (highest to lowest):
  1. Explicit --config=FILE argument
  2. ~/.sigwood/config.toml  (user default)
  3. /etc/sigwood/config.toml  (system-wide)

When no config file is found, returns a deep copy of built-in defaults - no exception raised.
"""

from __future__ import annotations

import copy
import difflib
import ipaddress
import tomllib
from collections.abc import Mapping
from datetime import timedelta
from pathlib import Path
from typing import Any

from sigwood.common.sanitize import strip_control
from sigwood.common.syslog_mode import SyslogModeError, parse_syslog_mode


class ConfigError(Exception):
    """Raised for config problems that the user needs to act on."""


def parse_window_span(spec: str | None) -> timedelta | None:
    """Parse a default_window config value into a timedelta.

    Returns None for: None, "", "all" (case-insensitive) - meaning "no default".
    Accepts: "Nd" (days), "Nh" (hours) where N is a positive integer.
    Raises ConfigError for any other value - silent fallback hides real config bugs.
    """
    if spec is None:
        return None
    s = str(spec).strip()
    if s == "" or s.lower() == "all":
        return None
    try:
        if s.endswith("d"):
            n = int(s[:-1])
            if n > 0:
                return timedelta(days=n)
        elif s.endswith("h"):
            n = int(s[:-1])
            if n > 0:
                return timedelta(hours=n)
    except ValueError:
        pass
    raise ConfigError(
        f"default_window={spec!r} is not a valid duration - "
        f"use 'Nd' (days), 'Nh' (hours), '' or 'all' to disable"
    )


def _validate_warn_above(config: dict[str, Any]) -> None:
    value = config.get("sigwood", {}).get("warn_above")
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ConfigError(
            f"[sigwood].warn_above={value!r} must be a non-negative integer "
            "(0 disables the prompt)"
        )


def _validate_syslog_source(config: dict[str, Any]) -> None:
    """Validate the system-log mode eagerly at the config boundary."""
    value = config.get("sigwood", {}).get("syslog_source")
    try:
        parse_syslog_mode(value)
    except SyslogModeError as exc:
        raise ConfigError(
            f"[sigwood].syslog_source={value!r} must be one of "
            "auto, journal, files, or off"
        ) from exc


def _validate_home_net(config: Mapping[str, Any]) -> None:
    """Validate operator topology at the config boundary."""
    sigwood = config.get("sigwood", {})
    if not isinstance(sigwood, Mapping):
        raise ConfigError("[sigwood] must be a table")

    value = sigwood.get("home_net", [])
    if isinstance(value, (str, bytes)) or not isinstance(value, list):
        raise ConfigError(
            f"[sigwood].home_net={value!r} must be a TOML array of IP networks; "
            'for example: home_net = ["10.0.0.0/8"]'
        )

    for position, network in enumerate(value, start=1):
        if not isinstance(network, str):
            raise ConfigError(
                f"[sigwood].home_net entry {position}={network!r} "
                "must be a string containing an IP network"
            )
        try:
            ipaddress.ip_network(network, strict=False)
        except ValueError as exc:
            raise ConfigError(
                f"[sigwood].home_net entry {position}={network!r} "
                "is not a valid IP network"
            ) from exc


def resolve_home_net(config: Mapping[str, Any]) -> list[str]:
    """Return one validated, caller-owned copy of ``[sigwood].home_net``."""
    _validate_home_net(config)
    sigwood = config.get("sigwood", {})
    assert isinstance(sigwood, Mapping)  # established by _validate_home_net
    value = sigwood.get("home_net", [])
    assert isinstance(value, list)  # established by _validate_home_net
    return list(value)


def validate_table_sections(
    config: object,
    sections: tuple[str, ...] | None = None,
) -> None:
    """Require configuration sections used by a caller to be TOML tables."""
    if not isinstance(config, dict):
        raise ConfigError("config must be a table")
    for section in sections or tuple(_DEFAULTS):
        value = config.get(section, {})
        if not isinstance(value, dict):
            raise ConfigError(f"[{section}] must be a table")


DEFAULT_DETECT_SPEC = "default"


_DEFAULTS: dict[str, Any] = {
    "sigwood": {
        # The root - base for RELATIVE paths in config-file values. Empty = use
        # CWD for relative paths. Absolute and ~-anchored paths ignore it.
        # Env override: SIGWOOD_ROOT (env wins over config).
        "root": "~/.sigwood",
        "detect": DEFAULT_DETECT_SPEC,
        # Conventional source locations; tried out-of-box. pihole/cloudtrail
        # stay None (opt-in - no missing-file warning when absent).
        "zeek_dir": "/var/log/zeek",
        "syslog_dir": "/var/log",
        "syslog_source": "auto",
        "pihole_dir": None,
        "cloudtrail_dir": None,
        # Internal networks for traffic-direction classification. Topology
        # fact, not detector tuning. RFC1918 default; override only if your
        # internal address plan differs.
        "home_net": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        # Where exporters write pulled logs. Backends and per-query stanzas
        # may override per the precedence cascade.
        # Trailing slash communicates directory intent to be_like_water -
        # without it, a non-existent path would be interpreted as a FILE.
        "export_dir": "exports/",
        # report_dir intentionally OMITTED - no shipped default. Setting it is
        # an explicit opt-in to file-mode analyze output. Bare analyze prints
        # to stdout when report_dir is unset and --out is not passed.
        "output_format": "text",
        "default_window": "7d",
        "warn_above": 10_000_000,
        # Suppress runner-owned progress/status stderr (loader bars, liveness,
        # the default-window advisory). CLI -q/--quiet wins per run. Never
        # suppresses warnings, prompts, errors, or the stdout report.
        "quiet": False,
        # Render report times in UTC and read naive --since/--until dates and
        # --days boundaries as UTC. CLI --utc wins per run. json output is
        # always UTC.
        "use_utc": False,
        # Per-detector total row cap for TEXT output only (json/csv/html
        # render everything - machine formats must not lose data). The cap
        # is a running budget across the detector's subsections in declared
        # order; the disclosure line reports rendered-vs-total. 0 = unlimited.
        "max_findings_per_detector": 100,
    },
    "graph": {
        "target_bins": 2000,
        "top_hosts": 30,
        "top_services": 16,
        "domain_level": "domain",
    },
    "detectors": {},
    "allowlist": {
        # Master switch: false disables ALL suppression every run (or pass
        # --no-allowlist for a single run). Per-name shipped-list toggles live
        # under [allowlist.lists]; absence there means "use the registry default"
        # - NOT carried here as active values.
        "enabled": True,
        # allowlist.d auto-discovers dot-free domains* / connections* drop-ins by
        # the dot rule; these explicit keys are an escape hatch for files OUTSIDE
        # allowlist.d (any extension) and default to empty. allowlist_dir is root-
        # relative so it follows [sigwood].root (byte-identical at the default root).
        "domain_patterns": [],
        "connection_rules": [],
        "allowlist_dir": "allowlist.d/",
    },
    "export": {
        "splunk": {
            "host": "",
            "port": 8089,
            "verify_tls": True,
            "username": "",
            "password": "",
        },
        # cloudtrail exporter - boto3 pull from S3, writes CloudTrail JSON locally.
        # path is the s3:// URL to the CloudTrail tree; egress_warn_gb is the
        # cost guard threshold. Activation is a non-empty path.
        "cloudtrail": {
            "path": "",
            "egress_warn_gb": 5.0,
        },
    },
}

SEARCH_PATHS: list[Path] = [
    Path("~/.sigwood/config.toml").expanduser(),
    Path("/etc/sigwood/config.toml"),
]

# The top-level tables the config schema defines. Derived from _DEFAULTS so a new
# section cannot drift out of the set. `__user_set__` is a provenance sidecar
# _load_file attaches to the merged dict, not a user-facing section.
KNOWN_SECTIONS: frozenset[str] = frozenset(_DEFAULTS)
_INTERNAL_KEYS: frozenset[str] = frozenset({"__user_set__"})

# The explicit public config vocabulary.  ``_LEAF`` recognizes a name without
# descending into its value; ``_ANY_SCOPE`` recognizes an arbitrary table name
# and applies the nested declaration to that table's contents.  This cannot be
# derived from _DEFAULTS: several supported keys are deliberately unset there.
_LEAF = object()
_ANY_SCOPE = object()
_RETIRED_DETECTOR_SECTIONS: dict[str, tuple[str, tuple[str, ...]]] = {
    "duration": ("exfil", ("min_duration_seconds",)),
}

KNOWN_CONFIG_KEYS: dict[str, Any] = {
    "sigwood": {
        "root": _LEAF,
        "detect": _LEAF,
        "zeek_dir": _LEAF,
        "syslog_dir": _LEAF,
        "syslog_source": _LEAF,
        "pihole_dir": _LEAF,
        "cloudtrail_dir": _LEAF,
        "home_net": _LEAF,
        "export_dir": _LEAF,
        "report_dir": _LEAF,
        "output_format": _LEAF,
        "default_window": _LEAF,
        "warn_above": _LEAF,
        "quiet": _LEAF,
        "use_utc": _LEAF,
        "max_findings_per_detector": _LEAF,
    },
    "graph": {
        "target_bins": _LEAF,
        "top_hosts": _LEAF,
        "top_services": _LEAF,
        "domain_level": _LEAF,
    },
    # Detector names and keys are checked runner-side after discovery.  The
    # wildcard makes this subtree open to the config-level walker.
    "detectors": {_ANY_SCOPE: _LEAF},
    "allowlist": {
        "enabled": _LEAF,
        "domain_patterns": _LEAF,
        "connection_rules": _LEAF,
        "allowlist_dir": _LEAF,
        # Shipped-list names and stanza contents are deliberately open.
        "lists": _LEAF,
        "entry": _LEAF,
    },
    "export": {
        "splunk": {
            "host": _LEAF,
            "port": _LEAF,
            "verify_tls": _LEAF,
            "username": _LEAF,
            "password": _LEAF,
            "export_dir": _LEAF,
            "query": {
                _ANY_SCOPE: {
                    "spl": _LEAF,
                    "output_basename": _LEAF,
                    "export_dir": _LEAF,
                },
            },
        },
        "cloudtrail": {
            "path": _LEAF,
            "egress_warn_gb": _LEAF,
            "export_dir": _LEAF,
        },
    },
}


def unknown_sections(config: dict[str, Any]) -> list[str]:
    """Top-level config keys that no reader looks up, in first-seen order.

    A merged config always carries every known section, so a leftover key came from
    the user's file. Every reader fetches its section by name, misses, and falls
    back to a default - so a mistyped or stale section voids its settings with no
    diagnostic at all. Pure: the caller owns the disclosure and any output-surface
    neutralization.
    """
    return [
        key
        for key in config
        if key not in KNOWN_SECTIONS and key not in _INTERNAL_KEYS
    ]


def _suggestion(name: str, vocabulary: list[str]) -> str:
    """Optional close-match clause for one user-authored config name."""
    matches = difflib.get_close_matches(name, vocabulary, n=1, cutoff=0.6)
    if not matches:
        return ""
    return f" (did you mean {strip_control(matches[0])}?)"


def _setting_line(path: tuple[str, ...], key: str, vocabulary: list[str]) -> str:
    scope = strip_control(".".join(path))
    shown_key = strip_control(key)
    return (
        f"config: ignoring unknown setting [{scope}].{shown_key}"
        f"{_suggestion(key, vocabulary)}"
    )


def _section_line(
    path: tuple[str, ...],
    key: str,
    vocabulary: list[str],
    *,
    detector: bool = False,
) -> str:
    section = strip_control(".".join((*path, key)))
    kind = "detector section" if detector else "section"
    return (
        f"config: ignoring unknown {kind} [{section}]"
        f"{_suggestion(key, vocabulary)}"
    )


def _schema_keys(schema: Mapping[object, Any]) -> list[str]:
    return [key for key in schema if isinstance(key, str)]


def _walk_declared_scope(
    configured: Mapping[str, Any],
    schema: Mapping[object, Any],
    path: tuple[str, ...],
    section_lines: list[str],
    setting_lines: list[str],
    *,
    root: bool = False,
) -> None:
    """Collect unknown names from one declared scope without validating values."""
    dynamic_schema = schema.get(_ANY_SCOPE)
    if dynamic_schema is not None:
        if not isinstance(dynamic_schema, Mapping):
            return
        for name, value in configured.items():
            if isinstance(name, str) and isinstance(value, Mapping):
                _walk_declared_scope(
                    value,
                    dynamic_schema,
                    (*path, name),
                    section_lines,
                    setting_lines,
                )
        return

    vocabulary = _schema_keys(schema)
    for key, value in configured.items():
        if not isinstance(key, str) or key in schema:
            continue
        if root:
            if key not in _INTERNAL_KEYS:
                section_lines.append(_section_line((), key, vocabulary))
        elif path == ("export",) and isinstance(value, Mapping):
            section_lines.append(_section_line(path, key, vocabulary))
        else:
            setting_lines.append(_setting_line(path, key, vocabulary))

    for key, child_schema in schema.items():
        if not isinstance(key, str) or not isinstance(child_schema, Mapping):
            continue
        value = configured.get(key)
        if not isinstance(value, Mapping):
            continue
        _walk_declared_scope(
            value,
            child_schema,
            (*path, key),
            section_lines,
            setting_lines,
        )


def config_disclosure_lines(config: Mapping[str, Any]) -> list[str]:
    """Compose warnings for unknown non-detector config names.

    Sections precede settings.  Within each group, scopes follow the explicit
    declaration order and unknown keys retain their mapping order.  Pure and
    value-shape agnostic: validation and emission remain caller responsibilities.
    """
    if not isinstance(config, Mapping):
        return []
    sections: list[str] = []
    settings: list[str] = []
    _walk_declared_scope(
        config,
        KNOWN_CONFIG_KEYS,
        (),
        sections,
        settings,
        root=True,
    )
    return sections + settings


def detector_disclosure_lines(
    detectors_cfg: Mapping[str, Any],
    vocab: Mapping[str, Mapping[str, Any] | None],
) -> list[str]:
    """Compose warnings for unknown detector names and recursively unknown keys."""
    if not isinstance(detectors_cfg, Mapping) or not isinstance(vocab, Mapping):
        return []

    sections: list[str] = []
    settings: list[str] = []
    names = [name for name in vocab if isinstance(name, str)]
    for name in detectors_cfg:
        if not isinstance(name, str) or name in vocab:
            continue
        retired = _RETIRED_DETECTOR_SECTIONS.get(name)
        if retired is not None:
            successor, retired_keys = retired
            sections.append(
                f"config: [detectors.{name}] is retired; use [detectors.{successor}] "
                f"- retired keys: {', '.join(retired_keys)}"
            )
        else:
            sections.append(
                _section_line(("detectors",), name, names, detector=True)
            )

    for name, schema in vocab.items():
        configured = detectors_cfg.get(name)
        if schema is None or not isinstance(schema, Mapping):
            continue
        if not isinstance(configured, Mapping):
            continue
        _walk_declared_scope(
            configured,
            schema,
            ("detectors", name),
            sections,
            settings,
        )
    return sections + settings


def load(config_file: str | Path | None = None) -> dict[str, Any]:
    """Load config from the precedence chain and return the merged config dict.

    If config_file is given, it is used directly; raises ConfigError if missing.
    If no config file is found in the search path, returns built-in defaults cleanly.
    """
    if config_file is not None:
        path = Path(config_file)
        if not path.exists():
            raise ConfigError(
                f"config file not found: {path} - run: sigwood init"
            )
        config = _load_file(path)
    else:
        found = _find_config_file()
        if found is None:
            config = copy.deepcopy(_DEFAULTS)
        else:
            config = _load_file(found)

    validate_table_sections(config)
    # Validate default_window eagerly so typos in user config fail at load time -
    # not lazily during the run, where bounded paths would never notice.
    parse_window_span(config.get("sigwood", {}).get("default_window"))
    _validate_warn_above(config)
    _validate_syslog_source(config)
    _validate_home_net(config)
    return config


def default_allowlist_paths() -> dict[str, Any]:
    """Return a deep copy of ``_DEFAULTS["allowlist"]`` - the single source of
    truth for fallback paths when an allowlist config key is absent.

    Used by ``common/allowlist.py:build_matcher`` when a raw / notebook config
    arrives without ``domain_patterns``, ``connection_rules``, or
    ``allowlist_dir`` set (the ``cfg.load`` deep-merge would otherwise have
    supplied them from ``_DEFAULTS``).
    """
    return copy.deepcopy(_DEFAULTS["allowlist"])


def get_detector_config(
    config: dict[str, Any],
    detector_name: str,
    detector_defaults: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the merged config for a specific detector.

    File config wins over detector_defaults, which win over nothing.
    """
    base = copy.deepcopy(detector_defaults or {})
    file_section = config.get("detectors", {}).get(detector_name, {})
    return _deep_merge(base, file_section)


def _find_config_file() -> Path | None:
    """Walk SEARCH_PATHS and return the first existing file."""
    for path in SEARCH_PATHS:
        if path.exists():
            return path
    return None


def _load_file(path: Path) -> dict[str, Any]:
    """Parse a TOML config file and deep-merge it over built-in defaults.

    Attaches a ``__user_set__`` sidecar to the returned merged dict: a mapping
    from top-level section name to the set of key names the operator declared
    in that section. This is provenance metadata for runner-level disclosures
    (e.g. "default RFC1918 vs. operator-declared home_net") - a value-only
    check cannot distinguish a defaulted value from a user-declared value that
    happens to equal the default. The "no config file found" path in load()
    skips _load_file entirely; absence of the sidecar is correctly read as
    "no user declarations".
    """
    try:
        with path.open("rb") as fh:
            user_config = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(
            f"config parse error in {path} - {exc}"
        ) from exc

    merged = _deep_merge(copy.deepcopy(_DEFAULTS), user_config)
    merged["__user_set__"] = {
        section: set(content.keys()) if isinstance(content, dict) else set()
        for section, content in user_config.items()
    }
    return merged


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge override into base, returning a new dict.

    Scalars and lists in override replace those in base. Dicts are merged recursively.
    """
    result = dict(base)
    for key, val in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = copy.deepcopy(val)
    return result
