"""Runner-owned auth summary-note regressions."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import pytest

import sigwood.runner as runner
from sigwood.common.finding import DetectorContext
from sigwood.detectors import auth
from sigwood.parsers.syslog import parse_line


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


def _success(second: int) -> str:
    return (
        f"{_stamp(second)} host-a.example.test sshd[{2000 + second}]: "
        f"Accepted publickey for alice from 192.0.2.10 port {50000 + second} ssh2"
    )


def _frame(lines: list[str]) -> pd.DataFrame:
    records = []
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
        records, columns=["ts", "host", "program", "raw", "message"],
    )


def _context(lines: list[str]) -> DetectorContext:
    frame = _frame(lines)
    start = datetime.fromtimestamp(float(frame["ts"].min()), timezone.utc)
    end = datetime.fromtimestamp(float(frame["ts"].max()), timezone.utc)
    return DetectorContext.unsuppressed({"*.log*": frame}, data_window=(start, end))


def _run_config(root: Path, *, allowlist: bool = False) -> dict:
    config = {
        "sigwood": {"root": str(root), "default_window": ""},
        "allowlist": {
            "enabled": allowlist,
            "allowlist_dir": str(root / "allowlist.d"),
            "domain_patterns": [],
            "connection_rules": [],
        },
    }
    return config


def _write_log(root: Path, lines: list[str]) -> Path:
    source = root / "logs"
    source.mkdir()
    (source / "system.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return source


def _run_text(config: dict, source: Path) -> int:
    return runner.run(
        config,
        detect="auth",
        syslog_dir=source,
        syslog_source="files",
        load_all=True,
        no_allowlist=not config["allowlist"]["enabled"],
        quiet=True,
    )


def test_summary_facts_use_counted_decisions_and_never_run_lenses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context([
        _failure(1),
        _success(2),
        f"{_stamp(3)} host-b.example.test kernel: link ready",
    ])

    def _forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("summary facts must not run auth lenses")

    monkeypatch.setattr(auth.core, "run_lenses", _forbidden)
    facts = auth.summary_facts(context)

    assert facts.observation_count == 3
    assert facts.eligible_count == 2
    assert facts.identity_group_count == 1
    assert facts.service_count == 1
    assert facts.remote_source_count == 1
    assert facts.positive_window is True


def test_real_runner_distinguishes_detector_abstention_from_evaluated_zero(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    quiet_root = tmp_path / "quiet"
    quiet_root.mkdir()
    quiet_source = _write_log(
        quiet_root,
        [f"{_stamp(1)} host-a.example.test kernel: link ready"],
    )
    assert _run_text(_run_config(quiet_root), quiet_source) == 0
    quiet = " ".join(capsys.readouterr().out.split())
    assert (
        "auth: 1 log observation; no eligible authentication records in the "
        "loaded window - detector abstained; requires at least one supported "
        "authentication success or failure"
    ) in quiet
    disclosure = (
        "counts are decision records as each source logged them; a host reporting "
        "through more than one source can record one event in each"
    )
    assert disclosure in quiet

    evaluated_root = tmp_path / "evaluated"
    evaluated_root.mkdir()
    evaluated_source = _write_log(
        evaluated_root,
        [_failure(1), _failure(2)],
    )
    assert _run_text(_run_config(evaluated_root), evaluated_source) == 0
    evaluated = " ".join(capsys.readouterr().out.split())
    assert (
        "auth: 2 log observations; 2 eligible authentication records across "
        "1 identity group and 1 service - five lenses evaluated"
    ) in evaluated
    assert disclosure in evaluated
    assert "detector abstained" not in evaluated
    assert "auth - " not in evaluated


def test_real_runner_names_only_the_two_zero_duration_abstentions(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = _write_log(tmp_path, [_failure(1)])
    assert _run_text(_run_config(tmp_path), source) == 0
    rendered = " ".join(capsys.readouterr().out.split())
    assert (
        "concentration, landing, and host-spread evaluated; source-volume and "
        "account-volume abstained because the loaded window has no positive duration"
    ) in rendered
    assert (
        "auth allowlist: 1 remote source address extracted; system-log suppression "
        "covers whole hosts, not individual source addresses"
    ) in rendered


def test_auth_summary_uses_the_exact_post_allowlist_population(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = _write_log(
        tmp_path,
        [
            _failure(1, host="chatty.example.test", source="192.0.2.20"),
            _failure(2, host="keep.example.test", source="192.0.2.30"),
        ],
    )
    allowlist = tmp_path / "allowlist.d"
    allowlist.mkdir()
    (allowlist / "hosts").write_text("chatty.example.test\n", encoding="utf-8")
    config = _run_config(tmp_path, allowlist=True)

    assert _run_text(config, source) == 0
    rendered = " ".join(capsys.readouterr().out.split())
    assert "auth: 1 log observation; 1 eligible authentication record" in rendered
    assert "auth allowlist: 1 remote source address extracted" in rendered
    assert "chatty.example.test" not in rendered
    assert "keep.example.test" not in rendered


def test_preloop_prep_failure_retries_in_the_contained_detector_loop(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _write_log(tmp_path, [_failure(1), _failure(2)])
    config = _run_config(tmp_path)
    original = runner._prepare_detector_context
    calls = 0

    def _flaky(*args: object, **kwargs: object):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ValueError("synthetic pre-loop prep failure")
        return original(*args, **kwargs)

    monkeypatch.setattr(runner, "_prepare_detector_context", _flaky)
    assert _run_text(config, source) == 0
    rendered = " ".join(capsys.readouterr().out.split())
    assert calls == 2
    assert "synthetic pre-loop prep failure" not in rendered
    assert "five lenses evaluated" not in rendered


def test_successful_preloop_prep_is_cached_for_the_detector_loop(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _write_log(tmp_path, [_failure(1), _failure(2)])
    config = _run_config(tmp_path)
    original = runner._prepare_detector_context
    original_rows = auth._canonical_rows
    calls = 0
    row_calls = 0

    def _counted(*args: object, **kwargs: object):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    def _counted_rows(context: DetectorContext):
        nonlocal row_calls
        row_calls += 1
        return original_rows(context)

    monkeypatch.setattr(runner, "_prepare_detector_context", _counted)
    monkeypatch.setattr(auth, "_canonical_rows", _counted_rows)
    assert _run_text(config, source) == 0
    capsys.readouterr()
    assert calls == 1
    assert row_calls == 1


def test_summary_helper_failure_suppresses_only_the_optional_note(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _write_log(tmp_path, [_failure(1), _failure(2)])
    config = _run_config(tmp_path)
    original_run = auth.run
    run_calls = 0

    def _broken_summary(_context: DetectorContext) -> object:
        raise ValueError("hostile<script>\x1b[31m")

    def _counted_run(context: DetectorContext, **kwargs: object):
        nonlocal run_calls
        run_calls += 1
        return original_run(context, **kwargs)

    monkeypatch.setattr(auth, "summary_facts", _broken_summary)
    monkeypatch.setattr(auth, "run", _counted_run)
    assert _run_text(config, source) == 0
    rendered = " ".join(capsys.readouterr().out.split())
    assert run_calls == 1
    assert "auth:" not in rendered
    assert "hostile" not in rendered


def test_hostile_values_cannot_enter_summary_note_payload() -> None:
    hostile_host = "host<script>.example.test\x1b[31m"
    hostile_account = "acct<script>\x9b31m"
    facts = auth.summary_facts(
        _context([
            _failure(
                1,
                host=hostile_host,
                account=hostile_account,
                source="192.0.2.80",
            )
        ])
    )
    notes = runner._format_auth_summary_notes(facts)
    rendered = " ".join(notes)
    assert hostile_host not in rendered
    assert hostile_account not in rendered
    assert "192.0.2.80" not in rendered
    assert "\x1b" not in rendered
    assert "\x9b" not in rendered


def test_real_runner_uses_the_irregular_remote_address_plural(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = _write_log(
        tmp_path,
        [
            _failure(1, source="192.0.2.80"),
            _failure(2, source="192.0.2.81"),
        ],
    )

    assert _run_text(_run_config(tmp_path), source) == 0
    rendered = " ".join(capsys.readouterr().out.split())
    assert (
        "auth allowlist: 2 remote source addresses extracted; system-log suppression "
        "covers whole hosts, not individual source addresses"
    ) in rendered
    assert "addresss" not in rendered
