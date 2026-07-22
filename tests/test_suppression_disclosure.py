"""Suppression disclosure line - banner three-state, machine formats, and the
runner seam (real ``runner.run``, --no-allowlist, anti-double-count).

The banner ordering failure mode (building the matcher AFTER reporter.begin) is
guarded by asserting the ``allowlist:`` line is PRESENT in REAL run output.

Fixtures use example.com / RFC 5737 only.
"""

from __future__ import annotations

import io
import json
from datetime import datetime, timezone
from pathlib import Path

from sigwood import runner
from sigwood.common import config as cfg
from sigwood.common.display import fmt_suppression
from sigwood.common.finding import RunSummary, SuppressionSummary
from sigwood.outputs.html import HtmlHandler
from sigwood.outputs.json import JsonHandler
from sigwood.outputs.text import TextHandler


_NOW = 1_779_750_000.0


def _conn_log(zeek_dir: Path) -> None:
    """Two conn rows - ports 443 and 22 - as Zeek NDJSON."""
    rows = [
        {"ts": _NOW, "id.orig_h": "192.0.2.10", "id.resp_h": "198.51.100.20",
         "id.resp_p": 443, "proto": "tcp"},
        {"ts": _NOW + 60, "id.orig_h": "192.0.2.11", "id.resp_h": "198.51.100.21",
         "id.resp_p": 22, "proto": "tcp"},
    ]
    (zeek_dir / "conn.log").write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


def _env(tmp_path: Path, *, rule: str | None) -> dict:
    zeek = tmp_path / "zeek"
    zeek.mkdir()
    _conn_log(zeek)
    ad = tmp_path / "allowlist.d"
    ad.mkdir()
    if rule is not None:
        (ad / "connections_test").write_text(rule + "\n", encoding="utf-8")
    # Load from an EXPLICIT tmp config file - never cfg.load(None), which would
    # read the developer's real ~/.sigwood/config.toml (whose ~-anchored
    # allowlist_dir bypasses root). Default allowlist_dir is relative → tmp/allowlist.d.
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(
        f'[sigwood]\nroot = "{tmp_path}"\n[allowlist]\nenabled = true\n',
        encoding="utf-8",
    )
    config = cfg.load(str(cfg_file))
    return {"config": config, "zeek_dir": str(zeek)}


# ── banner three-state (focused) ──────────────────────────────────────────────


def _banner(suppression: SuppressionSummary) -> str:
    rs = RunSummary(
        data_window=(__import__("datetime").datetime(2026, 6, 1),
                     __import__("datetime").datetime(2026, 6, 1, 6)),
        record_counts={"conn*.log*": 2},
        data_size_bytes=0,
        detectors_run=[],
        detectors_skipped={},
        suppression=suppression,
    )
    return TextHandler(stream=io.StringIO())._render_run_summary(rs)


def test_banner_off() -> None:
    assert "allowlist:     off" in _banner(SuppressionSummary(False, 0, 0))


def test_banner_no_hits() -> None:
    assert "allowlist:     no hits" in _banner(SuppressionSummary(True, 0, 0))


def test_banner_both_kinds_connections_first() -> None:
    line = _banner(SuppressionSummary(True, 1_284, 312, 2_568, 624))
    assert (
        "allowlist:     suppressed 1,284 connections (50%) and 312 domains (50%)"
        in line
    )


def test_banner_three_clauses_hosts_last_without_percent() -> None:
    summary = SuppressionSummary(
        True, 1_284, 312, 2_568, 624,
        host_rows=9_412, host_total=10_000, hosts_matched=2,
    )
    assert fmt_suppression(summary) == (
        "suppressed 1,284 connections (50%) and 312 domains (50%) and "
        "9,412 rows from 2 hosts"
    )
    assert "hosts (" not in fmt_suppression(summary)


def test_banner_hosts_only_real_plurals() -> None:
    assert "suppressed 2 rows from 1 host" in _banner(
        SuppressionSummary(True, 0, 0, host_rows=2, hosts_matched=1)
    )
    assert "suppressed 1 row from 2 hosts" in _banner(
        SuppressionSummary(True, 0, 0, host_rows=1, hosts_matched=2)
    )


def test_banner_single_kind_drops_other_clause() -> None:
    s = SuppressionSummary(True, 1, 0, 4, 0)
    assert "allowlist:     suppressed 1 connection (25%)" in _banner(s)
    assert "and" not in _banner(s).split("allowlist:")[1]


def test_banner_pct_rounds_to_nearest() -> None:
    # 433,073 / 735,766 = 58.9% → "59%" (the field sanity figure).
    line = _banner(SuppressionSummary(True, 0, 433_073, 0, 735_766))
    assert "allowlist:     suppressed 433,073 domains (59%)" in line


def test_banner_pct_floor_guard_under_one_percent() -> None:
    # count>0 but rounds to 0 → "<1%", never a misleading "(0%)".
    line = _banner(SuppressionSummary(True, 1, 0, 1_000, 0))
    assert "suppressed 1 connection (<1%)" in line


def test_banner_pct_ceil_guard_over_ninety_nine_percent() -> None:
    # count<total but rounds to 100 → ">99%", never a false "(100%)".
    line = _banner(SuppressionSummary(True, 9_999, 0, 10_000, 0))
    assert "suppressed 9,999 connections (>99%)" in line


def test_banner_pct_exact_full_is_hundred() -> None:
    # count == total is a true 100% - the ceil guard must NOT fire.
    line = _banner(SuppressionSummary(True, 5, 0, 5, 0))
    assert "suppressed 5 connections (100%)" in line


def test_banner_total_zero_omits_pct() -> None:
    # total == 0 (structurally shouldn't happen) → omit the parenthetical.
    line = _banner(SuppressionSummary(True, 3, 0, 0, 0))
    assert "allowlist:     suppressed 3 connections" in line
    assert "(" not in line.split("allowlist:")[1].split("\n")[0]


# ── machine formats ───────────────────────────────────────────────────────────


def test_json_serializes_raw_suppression() -> None:
    stream = io.StringIO()
    h = JsonHandler(stream=stream)
    h.begin(RunSummary(
        data_window=(__import__("datetime").datetime(2026, 6, 1),
                     __import__("datetime").datetime(2026, 6, 1, 6)),
        record_counts={}, data_size_bytes=0, detectors_run=[], detectors_skipped={},
        suppression=SuppressionSummary(
            True, 5, 7, 50, 70,
            host_rows=9, host_total=90, hosts_matched=2,
        ),
    ))
    h.write([])
    h.end()
    payload = json.loads(stream.getvalue())
    assert payload["run_summary"]["suppression"] == {
        "enabled": True, "connections": 5, "domains": 7,
        "connection_total": 50, "domain_total": 70,
        "host_rows": 9, "host_total": 90, "hosts_matched": 2,
    }


def test_html_renders_visible_suppression_row(tmp_path: Path) -> None:
    out = tmp_path / "report.html"
    h = HtmlHandler(output_path=out)
    h.begin(RunSummary(
        data_window=(__import__("datetime").datetime(2026, 6, 1),
                     __import__("datetime").datetime(2026, 6, 1, 6)),
        record_counts={}, data_size_bytes=0, detectors_run=[], detectors_skipped={},
        suppression=SuppressionSummary(True, 5, 7, host_rows=9, hosts_matched=2),
    ))
    h.write([])
    h.end()
    text = out.read_text(encoding="utf-8")
    # The header renders a lowercase `allowlist` meta-label + the shared
    # fmt_suppression value (escaped) in its own span.
    assert "allowlist" in text
    assert "suppressed 5 connections and 7 domains and 9 rows from 2 hosts" in text


def _host_suppression_env(tmp_path: Path) -> tuple[dict, Path, Path]:
    flat = tmp_path / "flat"
    flat.mkdir()
    (flat / "system.log").write_text(
        "Jul 21 12:00:00 Chatty-Lab sshd[10]: accepted from 192.0.2.10\n"
        "Jul 21 12:00:01 keep-lab cron[11]: job started\n",
        encoding="utf-8",
    )
    zeek = tmp_path / "zeek"
    zeek.mkdir()
    ts = datetime(2026, 7, 21, 12, tzinfo=timezone.utc).timestamp()
    records = [
        {
            "_path": "syslog", "ts": ts, "uid": "C1",
            "id.orig_h": "192.0.2.10", "id.orig_p": 40001,
            "id.resp_h": "198.51.100.20", "id.resp_p": 514,
            "proto": "udp", "facility": "DAEMON", "severity": "INFO",
            "message": "Jul 21 12:00:02 Chatty-Lab sshd[12]: session closed",
        },
        {
            "_path": "syslog", "ts": ts + 3, "uid": "C2",
            "id.orig_h": "192.0.2.11", "id.orig_p": 40002,
            "id.resp_h": "198.51.100.20", "id.resp_p": 514,
            "proto": "udp", "facility": "DAEMON", "severity": "INFO",
            "message": "Jul 21 12:00:03 other-lab kernel: link ready",
        },
    ]
    (zeek / "syslog.log").write_text(
        "".join(json.dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )
    allowlist_d = tmp_path / "allowlist.d"
    allowlist_d.mkdir()
    (allowlist_d / "hosts").write_text("chatty-*\n", encoding="utf-8")
    (allowlist_d / "hosts_bad").write_text(
        "# first\nre:(bad-open\n", encoding="utf-8",
    )
    config = {
        "sigwood": {"root": str(tmp_path), "default_window": ""},
        "allowlist": {
            "enabled": True, "allowlist_dir": "allowlist.d",
            "domain_patterns": [], "connection_rules": [],
        },
    }
    return config, flat, zeek


def test_host_suppression_real_two_feed_text_and_json_e2e(
    tmp_path: Path, capsys,
) -> None:
    config, flat, zeek = _host_suppression_env(tmp_path)
    kwargs = {
        "detect": "syslog", "syslog_dir": str(flat), "zeek_dir": str(zeek),
        "syslog_source": "files", "quiet": True,
    }

    assert runner.run(config, **kwargs) == 0
    text = capsys.readouterr().out
    assert "suppressed 2 rows from 1 host" in text
    assert "keep-lab" in text and "other-lab" in text
    assert "chatty-lab" not in text.lower()
    assert "hosts_bad:2: malformed pattern skipped (re:(bad-open)" in " ".join(
        text.split()
    )

    assert runner.run(config, output_format="json", **kwargs) == 0
    payload = json.loads(capsys.readouterr().out)
    suppression = payload["run_summary"]["suppression"]
    assert suppression["host_rows"] == 2
    assert suppression["host_total"] == 4
    assert suppression["hosts_matched"] == 1
    rendered = json.dumps(payload["findings"]).lower()
    assert "keep-lab" in rendered and "other-lab" in rendered
    assert "chatty-lab" not in rendered


def test_host_suppression_no_allowlist_is_inert(tmp_path: Path, capsys) -> None:
    config, flat, zeek = _host_suppression_env(tmp_path)
    assert runner.run(
        config, detect="syslog", syslog_dir=str(flat), zeek_dir=str(zeek),
        syslog_source="files", no_allowlist=True, quiet=True,
    ) == 0
    text = capsys.readouterr().out.lower()
    assert "allowlist:     off" in text
    assert "chatty-lab" in text


def test_runner_coverage_query_frame_never_counts_as_host(
    tmp_path: Path, capsys,
) -> None:
    config, flat, zeek = _host_suppression_env(tmp_path)
    (tmp_path / "allowlist.d" / "hosts").write_text("pihole*\n", encoding="utf-8")
    pihole = tmp_path / "pihole"
    pihole.mkdir()
    (pihole / "pihole.log").write_text(
        "Jul 21 12:00:00 dnsmasq[1]: query[A] keep.test from 192.0.2.10\n",
        encoding="utf-8",
    )

    assert runner.run(
        config, detect="syslog,dns", syslog_dir=str(flat), zeek_dir=str(zeek),
        pihole_dir=str(pihole), syslog_source="files", output_format="json",
        quiet=True,
    ) == 0
    suppression = json.loads(capsys.readouterr().out)["run_summary"]["suppression"]
    assert suppression["domain_total"] == 1
    assert suppression["host_total"] == 4
    assert suppression["host_rows"] == 0


# ── runner seam (real run) ────────────────────────────────────────────────────


def test_run_banner_shows_suppression_counted_once(tmp_path: Path, capsys) -> None:
    env = _env(tmp_path, rule=":22/tcp")          # suppresses the port-22 row
    # Three conn detectors share ONE conn frame - the count must stay 1, NOT 3
    # (anti-double-count: counted over load_result.logs, not per-detector).
    runner.run(env["config"], detect="beacon,scan,duration", zeek_dir=env["zeek_dir"])
    out = capsys.readouterr().out
    assert "allowlist:     suppressed 1 connection" in out


def test_run_banner_no_hits_when_nothing_matches(tmp_path: Path, capsys) -> None:
    env = _env(tmp_path, rule=":9999/tcp")        # matches nothing
    runner.run(env["config"], detect="duration", zeek_dir=env["zeek_dir"])
    assert "allowlist:     no hits" in capsys.readouterr().out


def test_run_no_allowlist_crosses_seam_to_off(tmp_path: Path, capsys) -> None:
    env = _env(tmp_path, rule=":22/tcp")          # would suppress, but --no-allowlist
    runner.run(env["config"], detect="duration", zeek_dir=env["zeek_dir"],
               no_allowlist=True)
    assert "allowlist:     off" in capsys.readouterr().out


def test_run_master_off_renders_off(tmp_path: Path, capsys) -> None:
    env = _env(tmp_path, rule=":22/tcp")
    env["config"]["allowlist"]["enabled"] = False
    runner.run(env["config"], detect="duration", zeek_dir=env["zeek_dir"])
    assert "allowlist:     off" in capsys.readouterr().out
