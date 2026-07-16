"""Pure system-log mode validation and configured-mode classification."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class SyslogMode(str, Enum):
    """Operator-selectable local system-log input modes."""

    AUTO = "auto"
    JOURNAL = "journal"
    FILES = "files"
    OFF = "off"


class SyslogModeError(ValueError):
    """Raised when a system-log mode value is outside the public enum."""


@dataclass(frozen=True)
class ConfiguredSyslogMode:
    """Effective configured mode plus legacy disk-config provenance."""

    mode: SyslogMode
    legacy_migrated: bool


def parse_syslog_mode(value: object) -> SyslogMode:
    """Return the exact system-log mode or raise a pure validation error."""
    if isinstance(value, SyslogMode):
        return value
    if isinstance(value, str):
        try:
            return SyslogMode(value)
        except ValueError:
            pass
    raise SyslogModeError(
        f"syslog_source must be one of auto, journal, files, or off (got {value!r})"
    )


def classify_configured_syslog_mode(
    *,
    mode_present: bool,
    mode_value: object,
    dir_present: bool,
    dir_value: object,
    disk_shape: bool,
) -> ConfiguredSyslogMode:
    """Classify merged disk config or an unprovenanced programmatic mapping.

    Disk configuration uses declaration provenance because a deep-merged
    default cannot distinguish an omitted key from an explicit ``auto``.
    Raw mappings preserve the historical truthy-directory behavior when the
    new mode key is absent.
    """
    if mode_present:
        return ConfiguredSyslogMode(parse_syslog_mode(mode_value), False)

    if disk_shape:
        if dir_present and not dir_value:
            return ConfiguredSyslogMode(SyslogMode.OFF, False)
        return ConfiguredSyslogMode(SyslogMode.AUTO, True)

    return ConfiguredSyslogMode(
        SyslogMode.FILES if dir_value else SyslogMode.OFF,
        False,
    )
