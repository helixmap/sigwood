"""Activation and Finding-contract regressions for the auth detector.

All addresses are RFC 5737 documentation space and every hostname is synthetic.
"""

from __future__ import annotations

import io
import json
from datetime import datetime, timezone

import pandas as pd

from sigwood import cli
from sigwood.common.finding import DetectorContext, MethodTag, RunSummary, Severity
from sigwood.detectors import auth
from sigwood.outputs.html import render_report_html
from sigwood.outputs.json import JsonHandler
from sigwood.outputs.text import TextHandler
from sigwood.parsers.syslog import parse_line
from tests.test_voice_consistency import assert_report_voice


_COMMON_EVIDENCE = {
    "signal",
    "attempt_count",
    "denial_count",
    "host_count",
    "real_account_count",
    "nonexistent_account_count",
    "unknown_account_count",
    "live_account_count",
    "first_seen",
    "last_seen",
    "span_seconds",
    "window_coverage_pct",
    "window_spanning",
    "severity_basis",
}


def _stamp(second: int) -> str:
    minute, second = divmod(second, 60)
    return f"2026-08-05T00:{minute:02d}:{second:02d}+00:00"


def _failure(
    second: int,
    *,
    host: str = "host-a.example.test",
    account: str = "alice",
    source: str = "192.0.2.10",
) -> str:
    return (
        f"{_stamp(second)} {host} sshd[{1000 + second}]: "
        f"Failed password for {account} from {source} port {40000 + second} ssh2"
    )


def _success(
    second: int,
    *,
    host: str = "host-a.example.test",
    account: str = "alice",
    source: str = "192.0.2.10",
) -> str:
    return (
        f"{_stamp(second)} {host} sshd[{2000 + second}]: "
        f"Accepted publickey for {account} from {source} port {50000 + second} ssh2"
    )


def _local_failure(
    second: int,
    *,
    host: str = "console.example.test",
    account: str = "alice",
) -> str:
    return (
        f"{_stamp(second)} {host} sudo[{3000 + second}]: "
        f"pam_unix(sudo:auth): authentication failure; user={account}"
    )


def _frame(lines: list[str]) -> pd.DataFrame:
    records: list[dict[str, object]] = []
    for line in lines:
        parsed = parse_line(line)
        assert parsed is not None and parsed["ts"] is not None
        records.append(
            {
                "ts": parsed["ts"].timestamp(),
                "host": parsed["host"],
                "program": parsed["program"],
                "raw": parsed["raw"],
                "message": parsed["message"],
            }
        )
    return pd.DataFrame.from_records(
        records,
        columns=["ts", "host", "program", "raw", "message"],
    )


def _context(
    lines: list[str],
    *,
    zeek_lines: list[str] | None = None,
) -> DetectorContext:
    flat = _frame(lines)
    logs = {"*.log*": flat}
    frames = [flat]
    if zeek_lines is not None:
        zeek = _frame(zeek_lines)
        logs["syslog*.log*"] = zeek
        frames.append(zeek)
    start = min(float(frame["ts"].min()) for frame in frames if not frame.empty)
    end = max(float(frame["ts"].max()) for frame in frames if not frame.empty)
    return DetectorContext.unsuppressed(
        logs,
        data_window=(
            datetime.fromtimestamp(start, timezone.utc),
            datetime.fromtimestamp(end, timezone.utc),
        ),
    )


def _summary(window: tuple[datetime, datetime]) -> RunSummary:
    return RunSummary(
        data_window=window,
        record_counts={"*.log*": 18},
        data_size_bytes=0,
        detectors_run=["auth"],
        detectors_skipped={},
        detector_methods={"auth": MethodTag("heuristics", named=False)},
    )


def _assert_reader_vocabulary(findings) -> None:
    forbidden = ("access decision", "actor", "gate", "granted", "denied")
    for finding in findings:
        prose = " ".join(
            [finding.description, *finding.next_steps]
        ).casefold()
        assert all(word not in prose for word in forbidden)


def test_auth_exports_activate_as_opt_in_heuristics() -> None:
    assert auth.DETECTOR_NAME == "auth"
    assert auth.STATUS == "available"
    assert auth.IN_DEFAULT_HUNT is False
    assert auth.DETECTOR_METHOD == MethodTag("heuristics", named=False)


def test_empty_or_nonfinite_frames_return_no_findings() -> None:
    window = (
        datetime(2026, 8, 5, tzinfo=timezone.utc),
        datetime(2026, 8, 5, 1, tzinfo=timezone.utc),
    )
    empty = pd.DataFrame(columns=["ts", "host", "program", "raw", "message"])
    nonfinite = pd.DataFrame(
        [{"ts": float("nan"), "host": "host.example.test", "program": "sshd",
          "raw": "synthetic", "message": "sshd[*]: synthetic"}]
    )
    assert auth.run(DetectorContext.unsuppressed({}, data_window=window)) == []
    assert auth.run(
        DetectorContext.unsuppressed({"*.log*": empty}, data_window=window)
    ) == []
    assert auth.run(
        DetectorContext.unsuppressed({"*.log*": nonfinite}, data_window=window)
    ) == []


def test_concentration_projects_one_medium_finding_with_frozen_evidence() -> None:
    ctx = _context([_failure(index) for index in range(1, 101)])

    findings = auth.run(ctx)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.MEDIUM
    assert finding.title == "192.0.2.10"
    assert finding.evidence["signal"] == "concentration"
    assert finding.evidence["severity_basis"] == ["concentration"]
    assert finding.evidence["attempt_count"] == 100
    assert finding.evidence["denial_count"] == 100
    assert finding.evidence["host_count"] == 1
    assert finding.evidence["live_account_count"] == 0
    assert set(finding.evidence) == _COMMON_EVIDENCE | {
        "host", "service", "identity_axes", "source",
        "account_namespace", "account",
    }
    assert "severity_cap" not in finding.evidence
    assert_report_voice(findings)
    _assert_reader_vocabulary(findings)


def test_host_spread_absorbs_every_exact_landing_into_one_high_owner() -> None:
    lines = [
        *[_failure(index, host="host-a.example.test") for index in range(1, 7)],
        _success(7, host="host-a.example.test"),
        *[_failure(20 + index, host="host-b.example.test") for index in range(1, 7)],
        _success(27, host="host-b.example.test"),
        _failure(40, host="host-c.example.test"),
    ]

    findings = auth.run(_context(lines))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.HIGH
    assert finding.title == "alice"
    assert finding.evidence["signal"] == "host_spread"
    assert finding.evidence["severity_basis"] == ["host_spread", "landing"]
    assert finding.evidence["host_count"] == 3
    assert finding.evidence["denial_count"] == 13
    assert finding.evidence["live_account_count"] == 1
    episodes = finding.evidence["landing_episodes"]
    assert [(item["host"], item["failure_count"]) for item in episodes] == [
        ("host-a.example.test", 6),
        ("host-b.example.test", 6),
    ]
    assert set(finding.evidence) == _COMMON_EVIDENCE | {
        "source", "account_namespace", "account", "landing_episodes",
    }
    assert_report_voice(findings)
    _assert_reader_vocabulary(findings)


def test_unmatched_and_degraded_landing_stays_medium() -> None:
    lines = [*[_failure(index) for index in range(1, 7)], _success(7)]

    findings = auth.run(_context(lines))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.MEDIUM
    assert finding.evidence["signal"] == "landing"
    assert finding.evidence["severity_basis"] == ["landing"]
    assert len(finding.evidence["landing_episodes"]) == 1


def test_source_absent_denied_only_episode_titles_observed_host_and_service() -> None:
    findings = auth.run(
        _context([_local_failure(index) for index in range(1, 101)])
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.evidence["signal"] == "concentration"
    assert finding.title == "console.example.test · sudo"
    assert finding.evidence["account"] == "alice"
    assert "alice" not in finding.description
    assert all("alice" not in step for step in finding.next_steps)


def test_live_account_count_changes_title_context_never_severity() -> None:
    denials = [
        _failure(1, host="host-a.example.test"),
        _failure(2, host="host-b.example.test"),
        _failure(3, host="host-c.example.test"),
    ]
    without_live = auth.run(_context(denials))
    with_live = auth.run(_context([*denials, _success(4)]))

    assert len(without_live) == len(with_live) == 1
    assert without_live[0].severity is Severity.MEDIUM
    assert with_live[0].severity is Severity.MEDIUM
    assert without_live[0].evidence["severity_basis"] == ["host_spread"]
    assert with_live[0].evidence["severity_basis"] == ["host_spread"]
    assert without_live[0].evidence["live_account_count"] == 0
    assert with_live[0].evidence["live_account_count"] == 1
    assert without_live[0].title == "192.0.2.10"
    assert with_live[0].title == "alice"


def test_landing_suppresses_concentration_at_the_same_episode_grain() -> None:
    lines = [*[_failure(index) for index in range(1, 101)], _success(101)]

    findings = auth.run(_context(lines))

    assert [finding.evidence["signal"] for finding in findings] == ["landing"]
    assert findings[0].evidence["denial_count"] == 100


def test_fixed_lane_order_combines_local_and_zeek_rows_without_record_collisions() -> None:
    local = [*[_failure(index) for index in range(1, 7)], _success(7)]
    zeek = [
        _failure(20, host="host-b.example.test"),
        _failure(21, host="host-c.example.test"),
    ]

    findings = auth.run(_context(local, zeek_lines=zeek))

    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert findings[0].evidence["host_count"] == 3
    assert len(findings[0].evidence["landing_episodes"]) == 1


def test_auth_direct_verb_runs_the_real_loader_and_detector_alone(
    tmp_path,
    capsys,
) -> None:
    source = tmp_path / "auth.log"
    source.write_text(
        "\n".join([*[_failure(index) for index in range(1, 7)], _success(7)])
        + "\n",
        encoding="utf-8",
    )
    config = tmp_path / "config.toml"
    config.write_text(
        "[sigwood]\n"
        f'root = "{tmp_path / "root"}"\n'
        'output_format = "text"\n',
        encoding="utf-8",
    )

    cli.main([
        "auth",
        str(source),
        "--all",
        "--no-allowlist",
        "--syslog-source=files",
        f"--config={config}",
    ])

    captured = capsys.readouterr()
    assert "auth - 1 finding" in captured.out
    assert "[M]" in captured.out
    assert "alice" in captured.out


def test_denied_only_hostile_account_is_machine_data_never_title_or_prose() -> None:
    hostile = "<svg/onload=alert(1)>\x1b[31m"
    findings = auth.run(
        _context([_failure(index, account=hostile) for index in range(1, 19)])
    )
    account_finding = next(
        finding
        for finding in findings
        if finding.evidence["signal"] == "account_volume"
    )

    assert hostile not in account_finding.title
    assert hostile not in account_finding.description
    assert all(hostile not in step for step in account_finding.next_steps)
    assert account_finding.evidence["account"] == hostile

    text0 = io.StringIO()
    TextHandler(stream=text0, verbose_level=0).write([account_finding])
    text1 = io.StringIO()
    TextHandler(stream=text1, verbose_level=1).write([account_finding])
    text2 = io.StringIO()
    TextHandler(stream=text2, verbose_level=2).write([account_finding])
    assert "<svg/onload=alert(1)>" not in text0.getvalue()
    assert "<svg/onload=alert(1)>" not in text1.getvalue()
    assert "\x1b" not in text2.getvalue()
    assert "<svg/onload=alert(1)>[31m" in text2.getvalue()

    html = render_report_html(
        [account_finding],
        _summary(account_finding.data_window),
        verbose_level=2,
        max_findings_per_detector=100,
    )
    assert "<svg/onload=alert(1)>" not in html
    assert "&lt;svg/onload=alert(1)&gt;" in html
    assert "\x1b" not in html

    stream = io.StringIO()
    handler = JsonHandler(stream=stream)
    handler.begin(_summary(account_finding.data_window))
    handler.write([account_finding])
    handler.end()
    payload = json.loads(stream.getvalue())
    account = payload["findings"][0]["evidence"]["account"]
    assert type(account) is str
    assert account == hostile
