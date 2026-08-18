"""Generated, RFC-3164-safe input for the DNSBlock repeat reproduction."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path


ADDRESS = "192.0.2.10"
FAMILY_KEY = "example.com"
BACKGROUND_NAME = "bg01.tracker.example.com"
Q_A_NAMES = tuple(
    f"a{number:02d}.tracker.example.com" for number in range(1, 6)
)
Q_B_NAMES = tuple(
    f"b{number:02d}.tracker.example.com" for number in range(1, 6)
)
QUALIFIED_NAMES = Q_A_NAMES + Q_B_NAMES


@dataclass(frozen=True)
class RepeatFixture:
    log: Path
    requests: dict[str, Path]
    windows: dict[str, tuple[dict[str, str], ...]]
    first_stamp: str
    last_stamp: str


def anchor_for(now: datetime) -> datetime:
    """Return the one local-midnight anchor mandated for this experiment."""
    return now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(
        days=183
    )


def _instant(value: datetime) -> str:
    """Render a UTC request instant without making the fixture clock-aware."""
    return value.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


def _window(
    start: datetime, end: datetime, context_start: datetime, context_end: datetime
) -> dict[str, str]:
    return {
        "start": _instant(start),
        "end": _instant(end),
        "context_start": _instant(context_start),
        "context_end": _instant(context_end),
    }


def _requests(anchor: datetime) -> dict[str, tuple[dict[str, str], ...]]:
    stepped = tuple(
        _window(
            anchor + timedelta(days=start_day),
            anchor + timedelta(days=start_day + 7),
            anchor + timedelta(days=start_day - 28),
            anchor + timedelta(days=start_day) - timedelta(seconds=1),
        )
        for start_day in range(28, 32)
    )
    disjoint = (
        _window(
            anchor + timedelta(days=28),
            anchor + timedelta(days=35),
            anchor,
            anchor + timedelta(days=28) - timedelta(seconds=1),
        ),
        _window(
            anchor + timedelta(days=35),
            anchor + timedelta(days=42),
            anchor + timedelta(days=7),
            anchor + timedelta(days=35) - timedelta(seconds=1),
        ),
    )
    return {"stepped": stepped, "single": (stepped[0],), "disjoint": disjoint}


def _line(stamp: datetime, message: str) -> str:
    return f"{stamp.strftime('%b %e %H:%M:%S')} pihole dnsmasq[1]: {message}\n"


def write_repeat_fixture(tmp_path: Path, anchor: datetime) -> RepeatFixture:
    """Write the approved synthetic log and the three one-key series requests."""
    log = tmp_path / "pihole.log"
    events: list[tuple[datetime, str]] = []

    def add_pair(stamp: datetime, name: str) -> None:
        events.extend(
            (
                (stamp, f"query[A] {name} from {ADDRESS}"),
                (stamp, f"gravity blocked {name} is 0.0.0.0"),
            )
        )

    for offset in range(46):
        add_pair((anchor + timedelta(days=offset)).replace(hour=6), BACKGROUND_NAME)
    for offset in range(31, 35):
        stamp = (anchor + timedelta(days=offset)).replace(hour=12)
        for name in Q_A_NAMES:
            add_pair(stamp, name)
    for offset in range(38, 42):
        stamp = (anchor + timedelta(days=offset)).replace(hour=12)
        for name in Q_B_NAMES:
            add_pair(stamp, name)

    lines = [_line(stamp, message) for stamp, message in sorted(events)]
    log.write_text("".join(lines), encoding="utf-8")

    windows = _requests(anchor)
    requests = {}
    for shape, rows in windows.items():
        path = tmp_path / f"{shape}.json"
        path.write_text(json.dumps({"windows": rows}), encoding="utf-8")
        requests[shape] = path
    return RepeatFixture(
        log=log,
        requests=requests,
        windows=windows,
        first_stamp=lines[0],
        last_stamp=lines[-1],
    )
