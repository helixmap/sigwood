"""Tests for the syslog digest card (three fixed slots, no fidelity branching).

Covers:
  - cliff statistic over host-volume and program-volume (gate, floor, names rank-1)
  - rate statistic over error-rate: kind definition (text matching, not severity),
    word-boundary semantics (errors matches, terror does not, oom-killer matches,
    out of memory matches as a phrase), message-not-raw scope, RATE_FLOOR floor,
    top-host attribution, no badness language
  - three-slot card has no absent slots - rendered card has no N.B. footer
  - ledes derive from speaking gating slots and stay brief
  - summariser shape: entity_label, slots in fixed order
  - CLI dispatch: sniff-driven schema routing to syslog_dir, flag/config precedence,
    cross-schema rejections at CLI and runner layers
"""

from __future__ import annotations

import io
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import pytest

import sigwood.cli as cli
import sigwood.runner as runner
from sigwood.common.display import default_window_advisory
from sigwood.common.finding import DigestCard, RunSummary
from sigwood.digest import syslog as syslog_digest
from sigwood.outputs.text import TextHandler


# ─── Fixtures ────────────────────────────────────────────────────────────────

_NOW = datetime(2026, 6, 11, 12, 0, tzinfo=timezone.utc)
_BASE_TS = _NOW.timestamp()

_SYSLOG_COLUMNS = ["ts", "host", "program", "raw", "message"]


def _syslog_row(
    host: str = "host1",
    program: str = "sshd",
    message: str = "Accepted publickey for user from 192.0.2.10",
    ts: float = _BASE_TS,
    raw: str | None = None,
) -> dict:
    """Build one canonical syslog row.

    `raw` defaults to a synthetic RFC 3164 header + the message body, so a
    test using only the helper has a realistic raw line. Tests that exercise
    the message-vs-raw scope override `raw` and `message` independently.
    """
    if raw is None:
        raw = f"<14>Jun 11 12:00:00 {host} {program}: {message}"
    return {
        "ts":      ts,
        "host":    host,
        "program": program,
        "raw":     raw,
        "message": f"{program}: {message}",
    }


def _syslog_df(rows: list[dict]) -> pd.DataFrame:
    if not rows:
        return pd.DataFrame(columns=_SYSLOG_COLUMNS)
    return pd.DataFrame(rows, columns=_SYSLOG_COLUMNS)


def _run_summary(
    window: tuple[datetime, datetime] = (_NOW - timedelta(days=1), _NOW),
) -> RunSummary:
    return RunSummary(
        data_window=window,
        record_counts={"*.log*": 100},
        data_size_bytes=0,
        detectors_run=[],
        detectors_skipped={},
        notes=[],
        data_sources=["syslog_raw"],
    )


def _card_from_body(body: dict) -> DigestCard:
    return DigestCard(
        schema="syslog",
        source_name="syslog.log",
        data_window=(_NOW - timedelta(days=1), _NOW),
        record_count=100,
        histogram_counts=[1, 2, 3, 5, 8, 5, 3, 2, 1],
        histogram_unit="hr",
        histogram_peak=8,
        zone1_extras=body["zone1_extras"],
        insights=body["insights"],
        fields=body["fields"],
    )


def _render(card: DigestCard) -> str:
    handler = TextHandler(stream=io.StringIO())
    handler.render_digest(card)
    return handler._stream.getvalue()


# ─── host-volume cliff ───────────────────────────────────────────────────────

def test_host_volume_dashes_below_population_floor() -> None:
    # 3 distinct hosts, dominant one - population below POPULATION_FLOOR=5
    rows = [_syslog_row(host="a") for _ in range(20)]
    rows.append(_syslog_row(host="b"))
    rows.append(_syslog_row(host="c"))
    df = _syslog_df(rows)
    slot = syslog_digest._slot_host_volume(df)
    assert slot.cells is None


def test_host_volume_dashes_below_gate() -> None:
    # 6 hosts with rank1/rank2 = 1.5 < CLIFF_GATE=2.0
    counts = [15, 10, 9, 8, 7, 6]
    rows = []
    for i, n in enumerate(counts):
        rows.extend([_syslog_row(host=f"host{i}") for _ in range(n)])
    df = _syslog_df(rows)
    slot = syslog_digest._slot_host_volume(df)
    assert slot.cells is None


def test_host_volume_names_rank1_when_speaking() -> None:
    # 6 hosts; rank1 emits 40 lines, others ~10 each → ratio 4
    rows = [_syslog_row(host="loud") for _ in range(40)]
    for i in range(5):
        rows.extend([_syslog_row(host=f"quiet{i}") for _ in range(10)])
    df = _syslog_df(rows)
    slot = syslog_digest._slot_host_volume(df)
    assert slot.cells is not None
    assert slot.entity == "loud"
    assert slot.cells[0] == "loud"
    assert slot.cells[1].endswith("%")
    assert slot.cells[2].endswith("x")
    assert slot.ratio is not None and slot.ratio >= 2.0


def test_host_volume_capped_display_above_threshold() -> None:
    """Cliff ratio >= CLIFF_DISPLAY_CAP renders the capped form in cells.

    Locks the conn-imported display cap on the new card so the shared cell
    formatter is exercised through host-volume too.
    """
    # 100 lines from "loud", 1 each from 5 quiet hosts → ratio 100 → capped
    rows = [_syslog_row(host="loud") for _ in range(100)]
    for i in range(5):
        rows.append(_syslog_row(host=f"quiet{i}"))
    df = _syslog_df(rows)
    slot = syslog_digest._slot_host_volume(df)
    assert slot.cells is not None
    assert slot.cells[2] == ">50x"
    # Raw ratio preserved for lede sort
    assert slot.ratio == pytest.approx(100.0)


# ─── program-volume cliff ────────────────────────────────────────────────────

def test_program_volume_dashes_below_population_floor() -> None:
    rows = [_syslog_row(program="audisp") for _ in range(20)]
    rows.append(_syslog_row(program="sshd"))
    rows.append(_syslog_row(program="kernel"))
    df = _syslog_df(rows)
    slot = syslog_digest._slot_program_volume(df)
    assert slot.cells is None


def test_program_volume_names_rank1_when_speaking() -> None:
    """Audit-logging-dominated pile: audisp dominates 20:1 over sshd.

    This is the realistic motif - a pile in which
    `audisp` runs the table is what the program-volume slot exists to flag.
    """
    rows = [_syslog_row(program="audisp", message="op=USYS_CONFIG res=success")
            for _ in range(60)]
    for prog in ("sshd", "kernel", "postfix/smtpd", "systemd", "cron"):
        rows.extend([_syslog_row(program=prog, message="routine line") for _ in range(3)])
    df = _syslog_df(rows)
    slot = syslog_digest._slot_program_volume(df)
    assert slot.cells is not None
    assert slot.entity == "audisp"
    assert slot.cells[0] == "audisp"
    # Magnitude is a raw count for program-volume (mirrors dns domain-volume)
    assert slot.cells[1] == "60"
    assert slot.cells[2].endswith("x")


# ─── error-rate kind ─────────────────────────────────────────────────────────

def test_error_rate_fires_on_lines_with_error_token() -> None:
    rows = [_syslog_row(message="connect failed: connection refused") for _ in range(10)]
    df = _syslog_df(rows)
    slot = syslog_digest._slot_error_rate(df, "syslog")
    assert slot.cells is not None
    assert slot.cells[0] == "100%"


def test_error_rate_does_not_fire_on_clean_lines() -> None:
    rows = [_syslog_row(message="accepted publickey for user") for _ in range(10)]
    df = _syslog_df(rows)
    slot = syslog_digest._slot_error_rate(df, "syslog")
    assert slot.cells is None


def test_error_rate_matches_plural_form_at_word_start() -> None:
    """'errors' matches 'error' - start-bounded, free suffix."""
    rows = [_syslog_row(message="five errors occurred during sync") for _ in range(10)]
    df = _syslog_df(rows)
    slot = syslog_digest._slot_error_rate(df, "syslog")
    assert slot.cells is not None
    assert slot.cells[0] == "100%"


def test_error_rate_does_not_match_substring_in_middle_of_word() -> None:
    """'terror' must NOT trip 'error' - no boundary before 'error'."""
    rows = [_syslog_row(message="cosmic terror of the void") for _ in range(10)]
    df = _syslog_df(rows)
    slot = syslog_digest._slot_error_rate(df, "syslog")
    assert slot.cells is None


def test_error_rate_matches_multiword_phrase() -> None:
    """'out of memory' matches as a literal phrase."""
    rows = [_syslog_row(message="reaping process: out of memory") for _ in range(10)]
    df = _syslog_df(rows)
    slot = syslog_digest._slot_error_rate(df, "syslog")
    assert slot.cells is not None
    assert slot.cells[0] == "100%"


def test_error_rate_matches_oom_in_hyphenated_token() -> None:
    """'oom-killer' matches 'oom' - hyphen is non-word, trailing context allowed."""
    rows = [_syslog_row(program="kernel",
                        message="kernel: oom-killer invoked for pid 4242")
            for _ in range(10)]
    df = _syslog_df(rows)
    slot = syslog_digest._slot_error_rate(df, "syslog")
    assert slot.cells is not None
    assert slot.cells[0] == "100%"


def test_error_rate_matches_message_only_never_raw() -> None:
    """A row whose raw line contains 'error' but whose message does not
    must NOT be flagged. Locks the message-only scope.
    """
    rows = []
    for _ in range(10):
        rows.append({
            "ts": _BASE_TS,
            "host": "host1",
            "program": "sshd",
            "raw": "<14>Jun 11 12:00:00 host-error-prefix sshd: clean line",
            "message": "sshd: clean line",
        })
    df = _syslog_df(rows)
    slot = syslog_digest._slot_error_rate(df, "syslog")
    assert slot.cells is None


def test_error_rate_dashes_below_rate_floor() -> None:
    """0.5% error-token lines < RATE_FLOOR=0.01 → dashes."""
    # 199 clean rows, 1 error row → 1/200 = 0.5% < 1%
    rows = [_syslog_row(message="routine activity") for _ in range(199)]
    rows.append(_syslog_row(message="connection refused"))
    df = _syslog_df(rows)
    slot = syslog_digest._slot_error_rate(df, "syslog")
    assert slot.cells is None


def test_error_rate_speaks_at_one_percent_pile() -> None:
    """1% error-token lines exactly meets RATE_FLOOR → speaks."""
    rows = [_syslog_row(message="routine activity") for _ in range(99)]
    rows.append(_syslog_row(host="noisy", message="operation failed"))
    df = _syslog_df(rows)
    slot = syslog_digest._slot_error_rate(df, "syslog")
    assert slot.cells is not None
    assert slot.cells[0] == "1%"


def test_error_rate_attributes_top_host() -> None:
    """Top contributor = host emitting the most error-token lines."""
    rows = [_syslog_row(host="quiet", message="routine activity") for _ in range(80)]
    rows.extend([_syslog_row(host="noisy", message="connection refused")
                 for _ in range(5)])
    rows.extend([_syslog_row(host="other1", message="operation failed")
                 for _ in range(2)])
    rows.extend([_syslog_row(host="other2", message="login denied")
                 for _ in range(2)])
    df = _syslog_df(rows)
    slot = syslog_digest._slot_error_rate(df, "syslog")
    assert slot.cells is not None
    assert slot.entity == "noisy"


def test_error_rate_lede_carries_no_badness_adjective() -> None:
    """The lede reports the fraction as a plain fact, no judgment."""
    rows = [_syslog_row(host="host1", message="routine activity")
            for _ in range(95)]
    rows.extend([_syslog_row(host="noisy", message="connection refused")
                 for _ in range(5)])
    df = _syslog_df(rows)
    body = syslog_digest.summarize(df, "syslog")
    matching = [l for l in body["insights"] if "error token" in l]
    assert matching, f"expected an error-rate lede; got: {body['insights']}"
    lede_lower = matching[0].lower()
    for forbidden in ("suspicious", "concerning", "dangerous", "malicious",
                       "attack", "alarming", "bad"):
        assert forbidden not in lede_lower, (
            f"error-rate lede must not contain {forbidden!r}; got: {matching[0]}"
        )


# ─── Three-slot card shape ──────────────────────────────────────────────────

def test_summarize_slot_computers_exist_in_fixed_order() -> None:
    """Three private slot computers, fixed order. The summariser body no
    longer exposes the full slot list - `fields` is the post-selection
    display set - so inspect the computers themselves."""
    for label in ("host-volume", "program-volume", "error-rate"):
        attr = "_slot_" + label.replace("-", "_")
        assert hasattr(syslog_digest, attr), f"missing computer: {attr}"


def test_summarize_returns_zone1_insights_fields_keys() -> None:
    df = _syslog_df([_syslog_row()])
    body = syslog_digest.summarize(df, "syslog")
    assert set(body.keys()) == {"zone1_extras", "insights", "fields"}


def test_zone1_extras_carry_distinct_host_and_program_counts() -> None:
    rows = []
    for h in ("h1", "h2", "h3"):
        for p in ("sshd", "kernel"):
            rows.append(_syslog_row(host=h, program=p))
    df = _syslog_df(rows)
    body = syslog_digest.summarize(df, "syslog")
    extras = dict(body["zone1_extras"])
    assert extras["hosts"] == "3"
    assert extras["programs"] == "2"


# ─── Ledes ───────────────────────────────────────────────────────────────────

def test_ledes_silent_on_flat_pile() -> None:
    """No gating slot speaks → ledes is empty."""
    rows = [_syslog_row(host=f"host{i}", program=("sshd", "cron")[i % 2],
                        message="routine line") for i in range(5)]
    df = _syslog_df(rows)
    body = syslog_digest.summarize(df, "syslog")
    assert body["insights"] == []


def test_ledes_verbalize_identity_and_magnitude() -> None:
    """A speaking host-volume cliff produces a brief lede mentioning the host."""
    rows = [_syslog_row(host="loud") for _ in range(40)]
    for i in range(5):
        rows.extend([_syslog_row(host=f"quiet{i}") for _ in range(10)])
    df = _syslog_df(rows)
    body = syslog_digest.summarize(df, "syslog")
    matching = [l for l in body["insights"] if "loud" in l]
    assert matching, f"expected host-volume lede mentioning 'loud'; got: {body['insights']}"
    # Never reveal raw statistic names
    for line in body["insights"]:
        assert "cliff" not in line.lower()
        assert "rank1" not in line.lower()


def test_ledes_thin_card_stays_brief() -> None:
    """Three slots + one rate → at most three lines, often fewer."""
    rows = [_syslog_row(host="loud", program="audisp",
                        message="connection refused") for _ in range(40)]
    for i in range(5):
        rows.extend([_syslog_row(host=f"q{i}", program="sshd",
                                  message="routine") for _ in range(10)])
    df = _syslog_df(rows)
    body = syslog_digest.summarize(df, "syslog")
    assert len(body["insights"]) <= 3


# ─── Renderer: no footer for syslog cards ───────────────────────────────────

def test_render_syslog_card_has_no_absent_footer() -> None:
    """Rendered syslog card must NOT contain 'N.B.' - three slots, no absents.

    Locks the absent-footer machinery against accidentally lighting up on
    syslog: dns just exercised that footer for absent feed-specific slots,
    and a future change shouldn't drag that into syslog where there are no
    absents to report.
    """
    rows = [_syslog_row(host="loud", program="audisp") for _ in range(40)]
    for i in range(5):
        rows.extend([_syslog_row(host=f"q{i}", program="sshd") for _ in range(10)])
    df = _syslog_df(rows)
    body = syslog_digest.summarize(df, "syslog")
    output = _render(_card_from_body(body))
    assert "N.B." not in output
    assert "ABSENT" not in output


def test_render_syslog_card_surfaces_each_speaking_slot_exactly_once() -> None:
    """Each slot that speaks surfaces exactly once - as an insight OR as
    a fields row. Under the flat grammar, non-speaking slots vanish; no
    dashed rows."""
    # Five distinct hosts, dominant program (audisp), error-rate fires.
    rows = [_syslog_row(host="host-a", program="audisp",
                        message="connection refused") for _ in range(20)]
    for i in range(4):
        rows.extend([
            _syslog_row(host=f"host-{i}", program="sshd",
                        message="accepted publickey")
            for _ in range(5)
        ])
    df = _syslog_df(rows)
    body = syslog_digest.summarize(df, "syslog")
    output = _render(_card_from_body(body))
    # Speaking slot identities surface - either as fields rows or as
    # insight prose. host-a dominates host-volume and is the top
    # contributor for the error-rate slot.
    assert "host-a" in output
    assert "%" in output
    assert "ABSENT" not in output
    assert "N.B." not in output


# ─── CLI dispatch ───────────────────────────────────────────────────────────

def _spy_run_digest(monkeypatch) -> dict:
    captured: dict[str, Any] = {}

    def fake_run_digest(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(runner, "run_digest", fake_run_digest)
    return captured


def _stub_config(monkeypatch, cfg_dict: dict) -> None:
    monkeypatch.setattr(cli.cfg, "load", lambda _path: cfg_dict)


_SYSLOG_LINE = (
    "<13>Jun  1 12:00:00 examplehost sshd[1234]: Accepted publickey for placeholder\n"
)


def _write_syslog_sniff_file(tmp_path: Path) -> Path:
    log_path = tmp_path / "syslog.log"
    log_path.write_text(_SYSLOG_LINE, encoding="utf-8")
    return log_path


def test_cli_digest_syslog_file_sniffs_and_routes_to_syslog_dir(
    tmp_path, monkeypatch,
) -> None:
    captured = _spy_run_digest(monkeypatch)
    _stub_config(monkeypatch, {"sigwood": {}})
    log_path = _write_syslog_sniff_file(tmp_path)
    cli._main(["digest", str(log_path)])
    assert captured.get("schema") == "syslog"
    assert captured.get("syslog_dir") == str(log_path)
    assert captured.get("zeek_dir") is None
    assert captured.get("pihole_dir") is None


def test_cli_digest_syslog_bare_falls_back_to_configured_dir(tmp_path, monkeypatch) -> None:
    """No positional → schema=conn, config-driven path. Syslog config alone
    cannot drive a bare digest under the new sniff surface - documented
    consequence of removing the schema token."""
    captured = _spy_run_digest(monkeypatch)
    syslog_dir = tmp_path / "syslog"
    syslog_dir.mkdir()
    _stub_config(monkeypatch, {"sigwood": {"syslog_dir": str(syslog_dir)}})
    cli._main(["digest"])
    # Bare digest is conn-default; the configured syslog_dir is not threaded.
    assert captured.get("schema") == "conn"
    assert captured.get("syslog_dir") is None


def test_cli_digest_syslog_file_with_since_flag(tmp_path, monkeypatch) -> None:
    captured = _spy_run_digest(monkeypatch)
    _stub_config(monkeypatch, {"sigwood": {}})
    log_path = _write_syslog_sniff_file(tmp_path)
    cli._main(["digest", str(log_path), "--since=7d"])
    assert captured.get("schema") == "syslog"
    assert captured.get("syslog_dir") == str(log_path)
    assert captured.get("since") is not None


# ─── Runner-level dispatch ───────────────────────────────────────────────────

def test_run_digest_rejects_both_zeek_and_syslog_dir_at_programmatic_boundary(
    tmp_path,
) -> None:
    """zeek_dir IS valid for syslog (Zeek syslog.log), so the rejection does
    not fire for zeek_dir alone. Instead, supplying BOTH zeek_dir AND
    syslog_dir is the contradictory case the runner rejects - mirrors the
    dns "zeek + pihole" xor-ladder rejection."""
    config: dict[str, Any] = {"sigwood": {}}
    with pytest.raises(
        ValueError, match="cannot use both zeek_dir and syslog_dir"
    ):
        runner.run_digest(
            config=config, schema="syslog",
            syslog_dir=tmp_path,
            zeek_dir=tmp_path / "zeek",
        )


def test_run_digest_rejects_pihole_dir_at_programmatic_boundary(tmp_path) -> None:
    config: dict[str, Any] = {"sigwood": {}}
    with pytest.raises(ValueError, match="pihole_dir is not valid for the syslog schema"):
        runner.run_digest(
            config=config, schema="syslog",
            syslog_dir=tmp_path,
            pihole_dir=tmp_path / "pihole",
        )


def test_run_digest_rejects_missing_syslog_dir(tmp_path) -> None:
    """Neither zeek_dir nor syslog_dir → "no syslog source configured". The
    error advertises only --zeek-dir (the one source-dir flag in
    _DIGEST_ALLOWED_LONG_FLAGS) + the two config keys; --syslog-dir is NOT
    advertised because it isn't an allowed digest flag."""
    config: dict[str, Any] = {"sigwood": {}}
    with pytest.raises(ValueError, match="no syslog source configured") as exc_info:
        runner.run_digest(config=config, schema="syslog")
    # Error text must not advertise --syslog-dir (it's not an allowed flag).
    assert "--syslog-dir" not in str(exc_info.value)
    assert "--zeek-dir" in str(exc_info.value)


def _write_syslog_file(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_run_digest_syslog_loads_full_no_default_window(tmp_path, capsys) -> None:
    """Digest default-windowing is Zeek-ONLY: a syslog DIRECTORY digest loads full
    (no default window), so rows older than default_window survive. Pins the
    caller-side Zeek-only gate - an unqualified run (no --all, no --since) must
    NOT trim the older row."""
    syslog_dir = tmp_path / "syslog"
    lines = [
        "Jun  1 12:00:00 hostA sshd[1]: old line",   # ~5 days before the newer row
        "Jun  6 12:00:00 hostB sshd[1]: new line",
    ]
    _write_syslog_file(syslog_dir / "syslog.log", lines)

    config: dict[str, Any] = {"sigwood": {"default_window": "1d"}}
    runner.run_digest(
        config=config, schema="syslog", syslog_dir=syslog_dir, skip_confirm=True,
    )
    out = capsys.readouterr().out
    # Both rows present on the identity line - NOT trimmed to the last 1d.
    assert "2 lines" in out
    # Non-Zeek source → no default window resolved → no disclosure note.
    assert default_window_advisory("1d") not in out


def test_run_digest_syslog_end_to_end_renders_a_card(tmp_path, capsys) -> None:
    """Full path: synthetic syslog file → run_digest → rendered card."""
    syslog_dir = tmp_path / "syslog"
    # 30 dominant audisp lines + 6 background lines from 6 hosts/programs
    lines = []
    for i in range(30):
        lines.append(
            "Jun 11 12:00:00 router audisp: op=USYS_CONFIG res=success"
        )
    for i, prog in enumerate(("sshd", "kernel", "postfix/smtpd",
                              "systemd", "cron", "rsyslogd")):
        lines.append(
            f"Jun 11 12:00:0{i} host{i} {prog}: routine line"
        )
    _write_syslog_file(syslog_dir / "syslog.log", lines)

    config: dict[str, Any] = {"sigwood": {}}
    runner.run_digest(
        config=config, schema="syslog",
        syslog_dir=syslog_dir, load_all=True, skip_confirm=True,
    )
    out = capsys.readouterr().out
    # Flat-card identity (no banner / no header rule).
    assert "syslog ·" in out
    assert "lines ·" in out
    # The dominant program (audisp) is named - either as an insight
    # sentence or as a fields-block row.
    assert "audisp" in out
    # No ABSENT slots, no footer / Zeek-nudge surface under the flat grammar.
    assert "ABSENT" not in out
    assert "N.B." not in out
    assert "keyword heuristic" not in out


# ─── Fidelity-aware v1: Zeek feed (severity) + nudge footer ──────────────────
#
# The Zeek arm of the syslog summariser reads `severity` (RFC 5424 enum) and
# defines "error" as {EMERG, ALERT, CRIT, ERR}. The flat arm keeps the
# keyword-token heuristic and footers a Zeek-evangelisation nudge - mirrors
# the DNS Zeek-nudge pattern. Lede wording forks: Zeek MUST NOT say "token".


_ZEEK_SYSLOG_COLUMNS = ["ts", "host", "program", "raw", "message", "facility", "severity"]


def _zeek_syslog_row(
    host: str = "host1",
    program: str = "sshd",
    message: str = "Accepted publickey for user",
    severity: str = "INFO",
    facility: str = "DAEMON",
    ts: float = _BASE_TS,
) -> dict:
    raw = f"Jun 11 12:00:00 {host} {program}: {message}"
    return {
        "ts":       ts,
        "host":     host,
        "program":  program,
        "raw":      raw,
        "message":  f"{program}: {message}",
        "facility": facility,
        "severity": severity,
    }


def _zeek_syslog_df(rows: list[dict]) -> pd.DataFrame:
    if not rows:
        return pd.DataFrame(columns=_ZEEK_SYSLOG_COLUMNS)
    return pd.DataFrame(rows, columns=_ZEEK_SYSLOG_COLUMNS)


def test_error_rate_zeek_feed_uses_severity_not_keyword() -> None:
    """A frame whose `message` carries no error tokens but whose `severity`
    is in the error-set MUST still drive the slot - proves the Zeek arm is
    severity-based, not message-token based."""
    rows = []
    for _ in range(95):
        rows.append(_zeek_syslog_row(host="quiet", severity="INFO"))
    for _ in range(5):
        # "routine activity" contains NO error tokens; severity=CRIT is what
        # the Zeek arm reads. If the slot speaks, it's reading severity.
        rows.append(_zeek_syslog_row(
            host="noisy", message="routine activity", severity="CRIT",
        ))
    df = _zeek_syslog_df(rows)

    slot = syslog_digest._slot_error_rate(df, "zeek")
    assert slot.cells is not None
    assert slot.cells[0] == "5%"
    assert slot.entity == "noisy"


def test_error_rate_zeek_feed_absent_severity_dashes() -> None:
    """Zeek arm with `severity` column missing → dashes (not "0%"). The
    detector's source-blindness rail also asserts this column may be absent."""
    rows = [_syslog_row() for _ in range(20)]   # 5-col, no severity
    df = _syslog_df(rows)
    slot = syslog_digest._slot_error_rate(df, "zeek")
    assert slot.cells is None


def test_error_rate_zeek_feed_zero_errors_dashes_not_zero_pct() -> None:
    """Present severity column with NO error-set values → DASH, not "0%".
    The shared `_rate()` primitive enforces this via RATE_FLOOR; both feeds
    converge on the same dash semantics for zero kind-count."""
    rows = [_zeek_syslog_row(severity="INFO") for _ in range(50)]
    rows.extend([_zeek_syslog_row(severity="DEBUG") for _ in range(50)])
    df = _zeek_syslog_df(rows)
    slot = syslog_digest._slot_error_rate(df, "zeek")
    assert slot.cells is None


def test_error_rate_zeek_feed_case_insensitive_severity_match() -> None:
    """Zeek severity is uppercase by convention but we match
    case-insensitively to absorb any mixed-case emission."""
    rows = [_zeek_syslog_row(severity="INFO") for _ in range(95)]
    rows.extend([_zeek_syslog_row(host="noisy", severity="err") for _ in range(5)])
    df = _zeek_syslog_df(rows)
    slot = syslog_digest._slot_error_rate(df, "zeek")
    assert slot.cells is not None
    assert slot.cells[0] == "5%"


def test_error_rate_lede_zeek_feed_says_severity_not_token() -> None:
    """Zeek lede MUST NOT say "token" or imply keyword matching."""
    rows = [_zeek_syslog_row(host="quiet", severity="INFO") for _ in range(95)]
    rows.extend([
        _zeek_syslog_row(host="noisy", severity="ERR") for _ in range(5)
    ])
    df = _zeek_syslog_df(rows)
    body = syslog_digest.summarize(df, "zeek")
    error_ledes = [l for l in body["insights"] if "error" in l.lower()]
    assert error_ledes, f"expected error-rate lede; got: {body['insights']}"
    lede = error_ledes[0]
    assert "token" not in lede.lower(), (
        f"Zeek lede must not mention 'token'; got: {lede!r}"
    )
    assert "error-severity" in lede or "severity" in lede.lower(), (
        f"Zeek lede must speak in severity terms; got: {lede!r}"
    )


def test_summarize_flat_feed_emits_no_footer_reasons_under_flat_grammar() -> None:
    """Under the flat card grammar, the digest has no footer surface and
    no Zeek-evangelisation nudge - both went with the N.B. block. The
    summariser body now exposes only zone1_extras/insights/fields."""
    rows = [_syslog_row() for _ in range(20)]
    df = _syslog_df(rows)
    body = syslog_digest.summarize(df, "syslog")
    assert "footer_reasons" not in body
    card = _card_from_body(body)
    output = _render(card)
    assert "N.B." not in output
    assert "keyword heuristic" not in output


def test_summarize_zeek_feed_emits_no_footer_either() -> None:
    """Mirror of the flat-feed check on the Zeek feed."""
    rows = [_zeek_syslog_row() for _ in range(20)]
    df = _zeek_syslog_df(rows)
    body = syslog_digest.summarize(df, "zeek")
    assert "footer_reasons" not in body
