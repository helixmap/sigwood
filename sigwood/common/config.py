"""Config loading with precedence chain: CLI arg > user > system.

Precedence (highest to lowest):
  1. Explicit --config=FILE argument
  2. ~/.sigwood/config.toml  (user default)
  3. /etc/sigwood/config.toml  (system-wide)

When no config file is found, returns a deep copy of built-in defaults - no exception raised.
"""

from __future__ import annotations

import copy
import tomllib
from datetime import timedelta
from pathlib import Path
from typing import Any


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
            f"[sigwood].warn_above={value!r} must be a non-negative integer"
        )


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


_DEFAULTS: dict[str, Any] = {
    "sigwood": {
        # The root - base for RELATIVE paths in config-file values. Empty = use
        # CWD for relative paths. Absolute and ~-anchored paths ignore it.
        # Env override: SIGWOOD_ROOT (env wins over config).
        "root": "~/.sigwood",
        "detect": "all",
        # Conventional source locations; tried out-of-box. pihole/cloudtrail
        # stay None (opt-in - no missing-file warning when absent).
        "zeek_dir": "/var/log/zeek",
        "syslog_dir": "/var/log",
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
        "top_hosts": 24,
        "top_services": 12,
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
