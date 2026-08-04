"""Access-decision analysis over the canonical system-log lane. (planned)"""

from __future__ import annotations

from sigwood.common.finding import DetectorContext, Finding

DETECTOR_NAME = "auth"
STATUS = "planned"

REQUIRED_LOGS: list[dict] = []

OPTIONAL_LOGS = [
    {"source": "syslog_dir", "pattern": "*.log*"},
    {"source": "journal", "pattern": "*.log*"},
    {"source": "zeek_dir", "pattern": "syslog*.log*"},
]

REQUIRES_ONE_OF_OPTIONAL = True
REQUIRES_ONE_OF_OPTIONAL_REASON = (
    "no syslog source found (need a readable system journal, syslog files, "
    "or Zeek syslog.log)"
)

DEFAULT_CONFIG: dict = {}


def run(context: DetectorContext) -> list[Finding]:
    """Analyze normalized access decisions from the system-log lane."""
    raise NotImplementedError("auth detector is planned - not yet implemented")
